"""Time helpers. Timestamps are stored as UTC epoch seconds; calendar days and hours follow
the configured zone (SENTINEL_TZ) or, by default, the server's local zone.

All calendar maths uses real dates, so DST days are 23 or 25 hours long and zones with
half-hour offsets (e.g. Asia/Kolkata) get correct hour boundaries.
"""
from __future__ import annotations

import time
from datetime import date, datetime, timedelta, tzinfo
from datetime import time as clock
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .validators import ValidationError

RANGES = {"1h": 3600, "24h": 86_400, "7d": 7 * 86_400}


def now_ts() -> int:
    return int(time.time())


def get_zone(name: str | None) -> tzinfo | None:
    """IANA zone by name; None means the server's local zone (DST-aware through the C library)."""
    if not name:
        return None
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError(f"Unknown time zone {name!r} - use an IANA name such as Asia/Dhaka") from None


def to_local(ts: int, tz: tzinfo | None = None) -> datetime:
    return datetime.fromtimestamp(ts, tz) if tz else datetime.fromtimestamp(ts)


def _epoch(moment: datetime) -> int:
    # Naive datetimes are interpreted as local time via mktime, which applies the right DST offset.
    return int(moment.timestamp())


def _midnight_of(day: date, tz: tzinfo | None) -> int:
    return _epoch(datetime.combine(day, clock.min, tzinfo=tz))


def local_midnight(ts: int, tz: tzinfo | None = None) -> int:
    return _midnight_of(to_local(ts, tz).date(), tz)


def day_starts(now: int, days: int, tz: tzinfo | None = None) -> list[int]:
    """Midnights of the last `days` calendar days (oldest first) followed by the next midnight."""
    today = to_local(now, tz).date()
    return [_midnight_of(today - timedelta(days=offset), tz) for offset in range(days - 1, -2, -1)]


def hour_start(ts: int, tz: tzinfo | None = None) -> int:
    return _epoch(to_local(ts, tz).replace(minute=0, second=0, microsecond=0))


def range_start(range_key: str, now: int) -> int:
    if range_key not in RANGES:
        raise ValidationError(f"Range must be one of: {', '.join(RANGES)}", "range")
    return now - RANGES[range_key]


def humanize_duration(seconds: float) -> str:
    total = max(0, int(seconds))
    days, rem = divmod(total, 86_400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"
