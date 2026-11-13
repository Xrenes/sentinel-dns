"""Publish the database to BIND (bind mode): zone files, the response-policy zone and the named.conf includes.

Every file is validated with named-checkzone / named-checkconf before it replaces the live one, then
applied with rndc. See docs/BIND_INTEGRATION.md.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..config import BindLayout, Config
from ..repositories import records, settings
from .ops import (
    COMMAND_TIMEOUT, Runner, candidate_path, install_file, is_current, rndc_command, run_command, run_tool, swap_in,
    write_text,
)
from .render import RpzEntries, feed_entries, render_options, render_rpz, render_zones, rpz_entries

CONFIG_SETTINGS = ("forwarders", "acl", "rrl_rps")
RPZ_SERIAL, RPZ_DIGEST = "rpz_serial", "rpz_digest"
FEEDS_SERIAL, FEEDS_DIGEST = "rpz_feeds_serial", "rpz_feeds_digest"
FEEDS_CHECK_TIMEOUT = 300.0  # the feeds zone holds a few hundred thousand names


def _temp_file(folder: Path, prefix: str, suffix: str = "") -> Path:
    handle, name = tempfile.mkstemp(prefix=prefix, suffix=suffix, dir=folder)
    os.close(handle)
    return Path(name)


@dataclass(frozen=True)
class BindSync:
    layout: BindLayout
    runner: Runner = run_command

    def _check_zone_file(self, zone: str, path: Path, timeout: float = COMMAND_TIMEOUT) -> str:
        return run_tool(self.runner, [self.layout.checkzone, zone, str(path)], stage="check",
                        failure=f"BIND rejected the {zone} zone", timeout=timeout)

    def check_zone_text(self, zone: str, text: str) -> None:
        """Validate candidate zone content (e.g. with a pending record change) without touching live files."""
        path = _temp_file(self.layout.zone_dir, f".check-{zone}-")
        try:
            write_text(path, text)
            self._check_zone_file(zone, path)
        finally:
            path.unlink(missing_ok=True)

    def _check_config(self, options: Path, zones: Path) -> str:
        """named-checkconf on a temporary top-level file that includes exactly these two files."""
        top = _temp_file(self.layout.conf_dir, ".check-", ".conf")
        try:
            write_text(top, f'include "{options.as_posix()}";\ninclude "{zones.as_posix()}";\n')
            return run_tool(self.runner, [self.layout.checkconf, str(top)], stage="check",
                            failure="BIND rejected the configuration")
        finally:
            top.unlink(missing_ok=True)

    def _rndc(self, *command: str) -> str:
        return run_tool(self.runner, rndc_command(self.layout, *command), stage="reload",
                        failure=f"The change is saved, but 'rndc {' '.join(command)}' failed")

    def sign(self, zone: str) -> None:
        self._rndc("sign", zone)

    def publish_zone(self, conn: sqlite3.Connection, cfg: Config, zone: str, *, reload: bool = True,
                     force: bool = False) -> bool:
        text = records.zone_file(conn, zone, cfg.zone)
        changed = install_file(self.layout.zone_path(zone), text, check=lambda path: self._check_zone_file(zone, path))
        if reload and (changed or force):
            self._rndc("reload", zone)
        return changed

    def _publish_policy_zone(self, conn: sqlite3.Connection, cfg: Config, zone: str, entries: RpzEntries, *,
                             keys: tuple[str, str], now: int, reload: bool, force: bool, timeout: float) -> None:
        """Rewrite one response-policy zone if its names changed (tracked by a digest in the settings)."""
        serial_key, digest_key = keys
        digest = hashlib.sha256(repr(entries).encode("utf-8")).hexdigest()
        path = self.layout.zone_path(zone)
        if not force and path.exists() and settings.get(conn, digest_key) == digest:
            return
        serial = max(int(settings.get(conn, serial_key) or 0) + 1, now)  # always grows, even if the clock goes back
        text = render_rpz(entries, serial=serial, forward_zone=cfg.zone)
        install_file(path, text, check=lambda candidate: self._check_zone_file(zone, candidate, timeout))
        settings.put_many(conn, {serial_key: serial, digest_key: digest})
        if reload:
            self._rndc("reload", zone)

    def publish_rpz(self, conn: sqlite3.Connection, cfg: Config, *, now: int, reload: bool = True,
                    force: bool = False, feeds: bool = True) -> int:
        """Rewrite the firewall zones whose names changed; returns the number of names they hold.

        feeds=False (new ML detections) leaves the large feeds zone alone.
        """
        rules = rpz_entries(conn)
        self._publish_policy_zone(conn, cfg, self.layout.rpz_zone, rules, keys=(RPZ_SERIAL, RPZ_DIGEST), now=now,
                                  reload=reload, force=force, timeout=COMMAND_TIMEOUT)
        count = len(rules.blocked) + len(rules.allowed)
        if feeds:
            listed = feed_entries(conn)
            self._publish_policy_zone(conn, cfg, self.layout.rpz_feeds_zone, listed, keys=(FEEDS_SERIAL, FEEDS_DIGEST),
                                      now=now, reload=reload, force=force, timeout=FEEDS_CHECK_TIMEOUT)
            count += len(listed.blocked)
        return count

    def _install_config(self, texts: dict[str, str]) -> bool:
        paths = {name: self.layout.conf_dir / name for name in texts}
        if all(is_current(paths[name], text) for name, text in texts.items()):
            return False
        candidates = {name: candidate_path(path) for name, path in paths.items()}
        try:
            for name, text in texts.items():
                write_text(candidates[name], text)
            self._check_config(candidates["options.conf"], candidates["zones.conf"])
        except Exception:
            for candidate in candidates.values():
                candidate.unlink(missing_ok=True)
            raise
        for name, path in paths.items():
            swap_in(candidates[name], path)
        return True

    def publish_config(self, conn: sqlite3.Connection, cfg: Config, *, reload: bool = True,
                       force: bool = False) -> bool:
        values = settings.get_many(conn, CONFIG_SETTINGS)
        changed = self._install_config({
            "options.conf": render_options(values, self.layout), "zones.conf": render_zones(cfg),
        })
        if reload and (changed or force):
            self._rndc("reconfig")
        return changed

    def publish_all(self, conn: sqlite3.Connection, cfg: Config, *, now: int, reload: bool = True) -> dict:
        """Write every BIND file from the database (dnsctl sync); one full `rndc reload` at the end."""
        summary = {
            "config_changed": self.publish_config(conn, cfg, reload=False),
            "zones_changed": [zone for zone in (cfg.zone, cfg.reverse_zone)
                              if self.publish_zone(conn, cfg, zone, reload=False)],
            "rpz_names": self.publish_rpz(conn, cfg, now=now, reload=False),
        }
        if reload:
            self._rndc("reload")
        return summary

    def check_all(self, cfg: Config) -> list[str]:
        """named-checkconf on Sentinel's includes and named-checkzone on every zone file it manages."""
        conf = self.layout.conf_dir
        report = [self._check_config(conf / "options.conf", conf / "zones.conf")]
        for zone in (cfg.zone, cfg.reverse_zone, self.layout.rpz_zone):
            report.append(self._check_zone_file(zone, self.layout.zone_path(zone)))
        feeds = self.layout.rpz_feeds_zone
        report.append(self._check_zone_file(feeds, self.layout.zone_path(feeds), FEEDS_CHECK_TIMEOUT))
        return report
