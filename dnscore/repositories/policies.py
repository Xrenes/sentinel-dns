"""Blocklist categories, custom allow/block rules and the policy snapshot used for decisions."""
from __future__ import annotations

import random
import sqlite3
import threading
from collections.abc import Iterable, Mapping

from ..catalog import CATEGORIES, CATEGORY_BY_KEY, FEED_CATEGORIES
from ..db import rows_to_dicts
from ..errors import NotFoundError, ValidationError
from ..policy import PolicySnapshot
from . import settings

_RULE_COLUMNS = "id, domain, action, category, note, created_by, created_at"
SYNC_AGE_SECONDS = 2 * 3600
MAX_CACHED_SNAPSHOTS = 8
# Cheap fingerprint of everything a PolicySnapshot is built from (no full read of the blocklist).
_SIGNATURE = (
    "SELECT (SELECT group_concat(part, ',') FROM (SELECT category || ':' || COUNT(*) || ':' || SUM(length(domain)) "
    "|| ':' || MAX(domain) AS part FROM blocklist GROUP BY category ORDER BY category)), "
    "(SELECT COUNT(*) || ':' || IFNULL(MAX(id), 0) FROM custom_rules), "
    "(SELECT group_concat(key || ':' || enabled, ',') FROM (SELECT key, enabled FROM categories ORDER BY key)), "
    "(SELECT group_concat(name, ',') FROM (SELECT name FROM zones ORDER BY name)), "
    "(SELECT value FROM settings WHERE key = 'ml_threshold')"
)
_SNAPSHOT_LOCK = threading.Lock()
_SNAPSHOTS: dict[str, tuple[tuple, PolicySnapshot]] = {}


def ensure_categories(conn: sqlite3.Connection, *, demo: bool, now: int) -> None:
    rows = [
        (c.key, c.demo_count if demo else 0,
         now - SYNC_AGE_SECONDS if demo and c.key in FEED_CATEGORIES else None)
        for c in CATEGORIES
    ]
    with conn:
        conn.executemany(
            "INSERT OR IGNORE INTO categories (key, enabled, domain_count, last_synced_at) "
            "VALUES (?, 1, ?, ?)",
            rows,
        )


def list_categories(conn: sqlite3.Connection) -> list[dict]:
    state = {row["key"]: row for row in conn.execute("SELECT * FROM categories")}
    dynamic = {
        "ml": conn.execute("SELECT COUNT(DISTINCT domain) FROM query_log WHERE source = 'ml'").fetchone()[0],
        "other": conn.execute("SELECT COUNT(*) FROM custom_rules WHERE action = 'block'").fetchone()[0],
    }
    return [
        {
            "key": c.key, "name": c.name, "color": c.color, "severity": c.severity,
            "description": c.description, "feed": c.feed, "is_feed": c.key in FEED_CATEGORIES,
            "enabled": bool(state[c.key]["enabled"]),
            "domain_count": dynamic.get(c.key, state[c.key]["domain_count"]),
            "last_synced_at": state[c.key]["last_synced_at"],
        }
        for c in CATEGORIES
        if c.key in state
    ]


def set_category_enabled(conn: sqlite3.Connection, key: str, enabled: bool) -> None:
    if key not in CATEGORY_BY_KEY:
        raise NotFoundError(f"Unknown category '{key}'")
    with conn:
        conn.execute("UPDATE categories SET enabled = ? WHERE key = ?", (int(enabled), key))


def simulate_feed_sync(conn: sqlite3.Connection, *, now: int, rng: random.Random) -> int:
    """Demo mode: pretend each enabled feed downloaded a few new domains."""
    keys = [
        row["key"] for row in conn.execute("SELECT key FROM categories WHERE enabled = 1")
        if row["key"] in FEED_CATEGORIES
    ]
    with conn:
        conn.executemany(
            "UPDATE categories SET domain_count = domain_count + ?, last_synced_at = ? WHERE key = ?",
            [(rng.randint(3, 140), now, key) for key in keys],
        )
    return len(keys)


def replace_category_list(conn: sqlite3.Connection, category: str, domains: Iterable[str], *, now: int) -> int:
    """bind mode: swap a category's names for a freshly downloaded list in one transaction; returns how many it holds.

    A name already listed under another category keeps that category (one row per name).
    """
    with conn:
        conn.execute("DELETE FROM blocklist WHERE category = ?", (category,))
        conn.executemany("INSERT OR IGNORE INTO blocklist (domain, category) VALUES (?, ?)",
                         ((domain, category) for domain in domains))
        count = conn.execute("SELECT COUNT(*) FROM blocklist WHERE category = ?", (category,)).fetchone()[0]
        conn.execute("UPDATE categories SET domain_count = ?, last_synced_at = ? WHERE key = ?",
                     (count, now, category))
    return count


def drop_entries(conn: sqlite3.Connection, entries: Mapping[str, Iterable[str]]) -> None:
    """Delete exact (name, category) pairs, e.g. an older install's sample names; the feeds count as never synced."""
    with conn:
        conn.executemany("DELETE FROM blocklist WHERE domain = ? AND category = ?",
                         [(domain, category) for category, domains in entries.items() for domain in domains])
        conn.executemany(
            "UPDATE categories SET domain_count = (SELECT COUNT(*) FROM blocklist WHERE category = ?), "
            "last_synced_at = NULL WHERE key = ?",
            [(key, key) for key in FEED_CATEGORIES],
        )


def seed_blocklist(conn: sqlite3.Connection, entries: Mapping[str, Iterable[str]]) -> None:
    with conn:
        conn.executemany(
            "INSERT OR IGNORE INTO blocklist (domain, category) VALUES (?, ?)",
            [(domain, category) for category, domains in entries.items() for domain in domains],
        )


def list_rules(conn: sqlite3.Connection) -> list[dict]:
    return rows_to_dicts(conn.execute(f"SELECT {_RULE_COLUMNS} FROM custom_rules ORDER BY id DESC"))


def get_rule(conn: sqlite3.Connection, rule_id: int) -> dict | None:
    row = conn.execute(f"SELECT {_RULE_COLUMNS} FROM custom_rules WHERE id = ?", (rule_id,)).fetchone()
    return dict(row) if row else None


def create_rule(conn: sqlite3.Connection, *, domain: str, action: str, category: str, note: str,
                username: str, now: int, replace: bool = False) -> dict:
    """Insert a rule; with replace=True an existing rule for the domain is swapped in one transaction."""
    try:
        with conn:
            if replace:
                conn.execute("DELETE FROM custom_rules WHERE domain = ?", (domain,))
            cursor = conn.execute(
                "INSERT INTO custom_rules (domain, action, category, note, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (domain, action, category, note, username, now),
            )
    except sqlite3.IntegrityError:
        raise ValidationError(f"A rule for '{domain}' already exists", "domain") from None
    rule = get_rule(conn, cursor.lastrowid)
    if rule is None:
        raise NotFoundError("Rule was not saved")
    return rule


def delete_rule(conn: sqlite3.Connection, rule_id: int) -> dict:
    rule = get_rule(conn, rule_id)
    if rule is None:
        raise NotFoundError(f"Rule {rule_id} does not exist")
    with conn:
        conn.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))
    return rule


def _database_key(conn: sqlite3.Connection) -> str:
    return conn.execute("PRAGMA database_list").fetchone()[2] or f"memory:{id(conn)}"


def load_snapshot(conn: sqlite3.Connection) -> PolicySnapshot:
    """The current policy. Real feeds hold hundreds of thousands of names, so the snapshot is reused (across
    connections and threads) until a list, rule, category switch, local zone or the ML threshold changes."""
    key, signature = _database_key(conn), tuple(conn.execute(_SIGNATURE).fetchone())
    with _SNAPSHOT_LOCK:
        cached = _SNAPSHOTS.get(key)
    if cached is not None and cached[0] == signature:
        return cached[1]
    snapshot = _read_snapshot(conn)
    with _SNAPSHOT_LOCK:
        _SNAPSHOTS.pop(key, None)
        _SNAPSHOTS[key] = (signature, snapshot)
        while len(_SNAPSHOTS) > MAX_CACHED_SNAPSHOTS:
            _SNAPSHOTS.pop(next(iter(_SNAPSHOTS)))
    return snapshot


def _read_snapshot(conn: sqlite3.Connection) -> PolicySnapshot:
    rules = conn.execute("SELECT domain, action, category FROM custom_rules").fetchall()
    enabled = frozenset(row["key"] for row in conn.execute("SELECT key FROM categories WHERE enabled = 1"))
    return PolicySnapshot(
        enabled=enabled,
        blocklist={row["domain"]: row["category"] for row in conn.execute("SELECT domain, category FROM blocklist")},
        block_rules={row["domain"]: row["category"] for row in rules if row["action"] == "block"},
        allow_rules=frozenset(row["domain"] for row in rules if row["action"] == "allow"),
        local_zones=tuple(row["name"] for row in conn.execute("SELECT name FROM zones")),
        ml_threshold=float(settings.get(conn, "ml_threshold")),
        ml_auto_block="ml" in enabled,  # the ML category switch is the single source of truth
    )
