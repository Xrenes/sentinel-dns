"""DNS zones and resource records."""
from __future__ import annotations

import sqlite3
from datetime import datetime

from ..db import rows_to_dicts
from ..errors import NotFoundError, ValidationError
from ..validators import RecordInput
from ..zonefile import ZoneMeta, next_serial, render_zone

_RECORD_COLUMNS = "id, zone, name, type, value, ttl, priority, created_at, updated_at"
_INSERT = (
    "INSERT INTO records (zone, name, type, value, ttl, priority, created_at, updated_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
)


def list_zones(conn: sqlite3.Connection) -> list[dict]:
    rows = rows_to_dicts(conn.execute(
        "SELECT z.name, z.kind, z.serial, z.dnssec_enabled, z.updated_at, COUNT(r.id) AS record_count "
        "FROM zones z LEFT JOIN records r ON r.zone = z.name GROUP BY z.name ORDER BY z.kind, z.name"
    ))
    return [{**row, "dnssec_enabled": bool(row["dnssec_enabled"])} for row in rows]


def get_zone(conn: sqlite3.Connection, name: str) -> dict | None:
    row = conn.execute("SELECT * FROM zones WHERE name = ?", (name,)).fetchone()
    return dict(row) if row else None


def require_zone(conn: sqlite3.Connection, name: str) -> dict:
    zone = get_zone(conn, name)
    if zone is None:
        raise NotFoundError(f"Zone '{name}' does not exist")
    return zone


def create_zone(conn: sqlite3.Connection, name: str, kind: str, records: list[RecordInput], *,
                dnssec: bool, now: int) -> None:
    serial = next_serial(0, datetime.fromtimestamp(now).date())
    with conn:
        conn.execute(
            "INSERT INTO zones (name, kind, serial, dnssec_enabled, updated_at) VALUES (?, ?, ?, ?, ?)",
            (name, kind, serial, int(dnssec), now),
        )
        conn.executemany(_INSERT, [
            (name, r.name, r.type, r.value, r.ttl, r.priority, now, now) for r in records
        ])


def list_records(conn: sqlite3.Connection, zone: str) -> list[dict]:
    return rows_to_dicts(conn.execute(
        f"SELECT {_RECORD_COLUMNS} FROM records WHERE zone = ? "
        "ORDER BY name <> '@', name, type, value",
        (zone,),
    ))


def get_record(conn: sqlite3.Connection, record_id: int) -> dict | None:
    row = conn.execute(f"SELECT {_RECORD_COLUMNS} FROM records WHERE id = ?", (record_id,)).fetchone()
    return dict(row) if row else None


def require_record(conn: sqlite3.Connection, record_id: int) -> dict:
    record = get_record(conn, record_id)
    if record is None:
        raise NotFoundError(f"Record {record_id} does not exist")
    return record


def check_conflicts(conn: sqlite3.Connection, zone: str, rec: RecordInput, exclude_id: int | None) -> None:
    rows = conn.execute(
        "SELECT type, value FROM records WHERE zone = ? AND name = ? AND id <> ?",
        (zone, rec.name, exclude_id or 0),
    ).fetchall()
    if any(row["type"] == rec.type and row["value"] == rec.value for row in rows):
        raise ValidationError("This record already exists", "value")
    if rec.type == "CNAME" and rows:
        raise ValidationError(f"'{rec.name}' already has records; a CNAME must be the only record", "name")
    if any(row["type"] == "CNAME" for row in rows):
        raise ValidationError(f"'{rec.name}' is a CNAME alias and cannot have other records", "name")


def bump_serial(conn: sqlite3.Connection, zone: str, now: int) -> int:
    current = require_zone(conn, zone)["serial"]
    serial = next_serial(current, datetime.fromtimestamp(now).date())
    conn.execute("UPDATE zones SET serial = ?, updated_at = ? WHERE name = ?", (serial, now, zone))
    return serial


def create_record(conn: sqlite3.Connection, zone: str, rec: RecordInput, now: int) -> dict:
    with conn:
        check_conflicts(conn, zone, rec, None)
        cursor = conn.execute(_INSERT, (zone, rec.name, rec.type, rec.value, rec.ttl, rec.priority, now, now))
        bump_serial(conn, zone, now)
    return require_record(conn, cursor.lastrowid)


def update_record(conn: sqlite3.Connection, record_id: int, zone: str, rec: RecordInput, now: int) -> dict:
    with conn:
        check_conflicts(conn, zone, rec, record_id)
        conn.execute(
            "UPDATE records SET name = ?, type = ?, value = ?, ttl = ?, priority = ?, updated_at = ? "
            "WHERE id = ?",
            (rec.name, rec.type, rec.value, rec.ttl, rec.priority, now, record_id),
        )
        bump_serial(conn, zone, now)
    return require_record(conn, record_id)


def delete_record(conn: sqlite3.Connection, record_id: int, now: int) -> dict:
    record = require_record(conn, record_id)
    with conn:
        conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        bump_serial(conn, record["zone"], now)
    return record


def lookup(conn: sqlite3.Connection, zone: str, name: str, rtype: str) -> list[dict]:
    return rows_to_dicts(conn.execute(
        "SELECT name, type, value, ttl, priority FROM records WHERE zone = ? AND name = ? AND type = ?",
        (zone, name, rtype),
    ))


def name_exists(conn: sqlite3.Connection, zone: str, name: str) -> bool:
    row = conn.execute("SELECT 1 FROM records WHERE zone = ? AND name = ? LIMIT 1", (zone, name)).fetchone()
    return row is not None


def zone_file(conn: sqlite3.Connection, zone_name: str, forward_zone: str) -> str:
    zone = require_zone(conn, zone_name)
    meta = ZoneMeta.for_zone(zone_name, zone["serial"], forward_zone)
    return render_zone(meta, list_records(conn, zone_name))


def ptr_hostnames(conn: sqlite3.Connection) -> dict[str, str]:
    """Map client IPs to hostnames using PTR records of the reverse zones."""
    rows = conn.execute(
        "SELECT r.name, r.value, r.zone FROM records r JOIN zones z ON z.name = r.zone "
        "WHERE z.kind = 'reverse' AND r.type = 'PTR'"
    ).fetchall()
    result = {}
    for row in rows:
        octets = f"{row['name']}.{row['zone']}".replace(".in-addr.arpa", "").split(".")
        result[".".join(reversed(octets))] = row["value"].rstrip(".")
    return result
