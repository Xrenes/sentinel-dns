"""Runtime configuration, read from environment variables (no hard-coded secrets)."""
from __future__ import annotations

import ipaddress
import logging
import os
import secrets
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .errors import ValidationError
from .timeutil import get_zone
from .validators import normalize_domain, validate_password

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INSTANCE_DIR = PROJECT_ROOT / "instance"
VALID_MODES = ("demo", "bind")
MIN_SECRET_KEY = 32


@dataclass(frozen=True)
class BindLayout:
    """bind mode: where the Sentinel-managed BIND files live and how to reach named.

    See docs/BIND_INTEGRATION.md for which component writes and reads each file.
    """

    conf_dir: Path = Path("/etc/bind/sentinel")
    zone_dir: Path = Path("/var/lib/bind/sentinel")
    key_dir: Path = Path("/var/lib/bind/keys")
    cache_dir: Path = Path("/var/cache/bind")  # named's working directory ("directory" option)
    log_file: Path = Path("/var/log/named/queries.log")
    server: str = "127.0.0.1"
    port: int = 53
    stats_url: str = "http://127.0.0.1:8053/json/v1"
    rpz_zone: str = "rpz.local"  # administrator rules and ML detections (small, changes often)
    rpz_feeds_zone: str = "rpz-feeds.local"  # downloaded threat feeds (large, changes on a feed sync)
    rndc: str = "rndc"
    rndc_conf: Path | None = None
    checkzone: str = "named-checkzone"
    checkconf: str = "named-checkconf"

    def zone_path(self, zone: str) -> Path:
        return self.zone_dir / f"db.{zone}"


@dataclass(frozen=True)
class Config:
    """Application settings.

    ``demo`` mode simulates DNS traffic so the dashboard works on any OS;
    ``bind`` mode manages the local BIND 9 on the Linux server (files written by dnscore.bind, applied with rndc).
    """

    mode: str = "demo"
    db_path: Path = INSTANCE_DIR / "sentinel.db"
    secret_key: str = ""
    secure_cookies: bool = False
    simulate: bool = True
    seed_history: bool = True
    background_jobs: bool = True
    admin_password: str | None = None
    host: str = "127.0.0.1"
    port: int = 8080
    zone: str = "lab.local"
    reverse_zone: str = "56.168.192.in-addr.arpa"
    upstream_timeout: float = 2.0
    timezone: str | None = None
    trusted_proxy: str | None = None  # reverse proxy allowed to set X-Forwarded-For / -Proto
    bind: BindLayout = BindLayout()

    def __post_init__(self) -> None:
        if self.mode not in VALID_MODES:
            raise ValueError(f"SENTINEL_MODE must be one of {VALID_MODES}, got {self.mode!r}")
        if not self.secret_key:
            raise ValueError("A secret key is required (set SENTINEL_SECRET_KEY)")
        get_zone(self.timezone)  # fail fast on an unknown SENTINEL_TZ


def write_private_file(path: Path, content: str) -> None:
    """Create a file readable only by its owner, atomically (no write-then-chmod window)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


def _restrict_windows_acl(path: Path) -> None:
    """Drop inherited permissions (e.g. Authenticated Users:M on D:\\) and grant only the current user."""
    icacls = shutil.which("icacls")
    user = os.environ.get("USERNAME", "")
    domain = os.environ.get("USERDOMAIN", "")
    if icacls is None or not user:
        logger.warning("Could not restrict access to %s (icacls or USERNAME unavailable)", path)
        return
    principal = f"{domain}\\{user}" if domain else user
    result = subprocess.run(
        [icacls, str(path), "/inheritance:r", "/grant:r", f"{principal}:(OI)(CI)F"],
        capture_output=True, text=True, check=False,
    )
    if result.returncode != 0:
        logger.warning("Could not restrict access to %s: %s", path, (result.stderr or result.stdout).strip())


def harden_directory(path: Path) -> None:
    """Create `path` (if needed) and make it private: POSIX mode 0700, owner-only ACL on Windows."""
    path.mkdir(parents=True, exist_ok=True)
    try:
        if os.name == "nt":
            _restrict_windows_acl(path)
        else:
            path.chmod(0o700)
    except OSError as error:  # e.g. a directory owned by another account
        logger.warning("Could not make %s private: %s", path, error)


def _flag(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_secret_key(env: Mapping[str, str], instance_dir: Path) -> str:
    """Prefer SENTINEL_SECRET_KEY; otherwise generate a random key once and keep it in instance/."""
    key = env.get("SENTINEL_SECRET_KEY", "").strip()
    if key:
        if len(key) < MIN_SECRET_KEY:
            raise ValueError(f"SENTINEL_SECRET_KEY must be at least {MIN_SECRET_KEY} characters")
        return key
    key_file = instance_dir / "secret_key"
    if not key_file.exists():
        try:
            write_private_file(key_file, secrets.token_hex(32))
        except FileExistsError:  # another process created it first - use theirs
            pass
    return key_file.read_text(encoding="utf-8").strip()


def _admin_password(env: Mapping[str, str]) -> str | None:
    password = env.get("SENTINEL_ADMIN_PASSWORD") or None
    if password is not None:
        try:
            validate_password(password, username="admin")
        except ValueError as error:
            raise ValueError(f"SENTINEL_ADMIN_PASSWORD rejected: {error}") from None
    return password


def _trusted_proxy(env: Mapping[str, str]) -> str | None:
    raw = env.get("SENTINEL_TRUSTED_PROXY", "").strip()
    if not raw:
        return None
    try:
        return str(ipaddress.ip_address(raw))  # canonical form: waitress compares it verbatim
    except ValueError:
        raise ValueError(f"SENTINEL_TRUSTED_PROXY must be the proxy's IP address, got {raw!r}") from None


def _bind_port(raw: str) -> int:
    if not raw.isdigit() or not 1 <= int(raw) <= 65_535:
        raise ValueError(f"SENTINEL_BIND_PORT must be a port number (1-65535), got {raw!r}")
    return int(raw)


def _bind_server(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        raise ValueError(f"SENTINEL_BIND_SERVER must be an IP address, got {raw!r}") from None


def _zone_name(name: str, raw: str) -> str:
    try:
        return normalize_domain(raw, name)
    except ValidationError as error:
        raise ValueError(f"{name} must be a domain name, got {raw!r} ({error})") from None


def _bind_layout(env: Mapping[str, str]) -> BindLayout:
    base = BindLayout()

    def path(name: str, default: Path) -> Path:
        return Path(env[name]) if env.get(name) else default

    rndc_conf = env.get("SENTINEL_RNDC_CONF")
    return BindLayout(
        conf_dir=path("SENTINEL_BIND_CONF_DIR", base.conf_dir),
        zone_dir=path("SENTINEL_BIND_ZONE_DIR", base.zone_dir),
        key_dir=path("SENTINEL_BIND_KEY_DIR", base.key_dir),
        cache_dir=path("SENTINEL_BIND_CACHE_DIR", base.cache_dir),
        log_file=path("SENTINEL_BIND_LOG", base.log_file),
        server=_bind_server(env.get("SENTINEL_BIND_SERVER") or base.server),
        port=_bind_port(env.get("SENTINEL_BIND_PORT") or str(base.port)),
        stats_url=env.get("SENTINEL_BIND_STATS_URL") or base.stats_url,
        rpz_zone=env.get("SENTINEL_RPZ_ZONE") or base.rpz_zone,
        rpz_feeds_zone=_zone_name("SENTINEL_RPZ_FEEDS_ZONE", env.get("SENTINEL_RPZ_FEEDS_ZONE") or base.rpz_feeds_zone),
        rndc=env.get("SENTINEL_RNDC") or base.rndc,
        rndc_conf=Path(rndc_conf) if rndc_conf else None,
        checkzone=env.get("SENTINEL_NAMED_CHECKZONE") or base.checkzone,
        checkconf=env.get("SENTINEL_NAMED_CHECKCONF") or base.checkconf,
    )


def load_config(env: Mapping[str, str] | None = None) -> Config:
    source = os.environ if env is None else env
    instance_dir = Path(source.get("SENTINEL_INSTANCE_DIR", INSTANCE_DIR))
    db_path = Path(source.get("SENTINEL_DB", instance_dir / "sentinel.db"))
    harden_directory(instance_dir)  # secret key, first-run credentials and the default database
    db_path.parent.mkdir(parents=True, exist_ok=True)  # a custom SENTINEL_DB folder keeps its own permissions
    mode = source.get("SENTINEL_MODE", "demo").strip().lower()
    return Config(
        mode=mode,
        db_path=db_path,
        secret_key=_load_secret_key(source, instance_dir),
        secure_cookies=_flag(source, "SENTINEL_SECURE_COOKIES", False),
        simulate=_flag(source, "SENTINEL_SIMULATE", mode == "demo"),
        seed_history=_flag(source, "SENTINEL_SEED_HISTORY", mode == "demo"),
        background_jobs=_flag(source, "SENTINEL_BACKGROUND_JOBS", True),
        admin_password=_admin_password(source),
        host=source.get("SENTINEL_HOST", "127.0.0.1"),
        port=int(source.get("SENTINEL_PORT", "8080")),
        zone=source.get("SENTINEL_ZONE", "lab.local"),
        reverse_zone=source.get("SENTINEL_REVERSE_ZONE", "56.168.192.in-addr.arpa"),
        timezone=source.get("SENTINEL_TZ") or None,
        trusted_proxy=_trusted_proxy(source),
        bind=_bind_layout(source),
    )
