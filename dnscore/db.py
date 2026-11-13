"""SQLite helpers. Every thread / request opens its own connection; WAL allows concurrent reads."""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

SCHEMA_FILE = Path(__file__).with_name("schema.sql")


def connect(path: Path | str) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


# Columns added after the first release: (table, column, definition). Constants only.
_ADDED_COLUMNS = (
    ("users", "must_change_password", "INTEGER NOT NULL DEFAULT 0"),
    ("query_log", "measured", "INTEGER NOT NULL DEFAULT 1"),
)


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
    _add_missing_columns(conn)
    conn.commit()


def _add_missing_columns(conn: sqlite3.Connection) -> None:
    """Upgrade databases created by older versions (CREATE TABLE IF NOT EXISTS keeps old shapes)."""
    for table, column, definition in _ADDED_COLUMNS:
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def rows_to_dicts(rows: Iterable[sqlite3.Row]) -> list[dict]:
    return [dict(row) for row in rows]
