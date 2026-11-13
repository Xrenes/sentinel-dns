"""Key/value application settings, stored as JSON."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable, Mapping
from typing import Any

DEFAULTS: dict[str, Any] = {
    "forwarders": ["1.1.1.1", "8.8.8.8"],
    "acl": ["127.0.0.0/8", "192.168.56.0/24"],
    "retention_days": 7,
    "rrl_rps": 20,
    "anonymize_clients": False,
    "ml_threshold": 0.85,
}

_UPSERT = (
    "INSERT INTO settings (key, value) VALUES (?, ?) "
    "ON CONFLICT (key) DO UPDATE SET value = excluded.value"
)


def get(conn: sqlite3.Connection, key: str, default: Any = None) -> Any:
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    if row is None:
        return DEFAULTS.get(key, default)
    return json.loads(row["value"])


def get_many(conn: sqlite3.Connection, keys: Iterable[str]) -> dict[str, Any]:
    return {key: get(conn, key) for key in keys}


def put(conn: sqlite3.Connection, key: str, value: Any) -> None:
    with conn:
        conn.execute(_UPSERT, (key, json.dumps(value)))


def put_many(conn: sqlite3.Connection, values: Mapping[str, Any]) -> None:
    with conn:
        conn.executemany(_UPSERT, [(key, json.dumps(value)) for key, value in values.items()])


def delete(conn: sqlite3.Connection, key: str) -> None:
    with conn:
        conn.execute("DELETE FROM settings WHERE key = ?", (key,))


def ensure_defaults(conn: sqlite3.Connection, values: Mapping[str, Any]) -> None:
    with conn:
        conn.executemany(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            [(key, json.dumps(value)) for key, value in values.items()],
        )
