"""Validation for every value that can reach BIND configuration, zone files or the database.

Zone files are plain text, so names and values are restricted to safe character sets
(no whitespace, quotes or control characters) to prevent zone-file injection. Every
pattern is applied with ``re.fullmatch`` so a trailing newline can never slip through.
"""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .catalog import RECORD_TYPES
from .errors import ValidationError

__all__ = [
    "RecordInput", "ValidationError", "normalize_domain", "validate_choice", "validate_cidr",
    "validate_int", "validate_ip", "validate_password", "validate_record", "validate_ttl",
    "validate_username",
]

TTL_MIN, TTL_MAX, DEFAULT_TTL = 60, 604_800, 3600
MAX_DOMAIN_LENGTH = 253
MAX_TXT_LENGTH = 1024
PASSWORD_MIN, PASSWORD_MAX = 10, 128

_DOMAIN_LABEL = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")
_HOST_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
_RECORD_LABEL = re.compile(r"_?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_OCTET = re.compile(r"[0-9]{1,3}")
_USERNAME = re.compile(r"[a-z0-9_.-]{3,32}")

COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "passw0rd", "1234567890", "0123456789", "12345678910",
    "qwertyuiop", "qwerty1234", "qwerty123456", "letmein123", "administrator", "admin12345",
    "welcome123", "iloveyou12", "changeme123", "sentinel123", "abc1234567",
})


@dataclass(frozen=True)
class RecordInput:
    name: str
    type: str
    value: str
    ttl: int
    priority: int | None = None


def _short(value: object, limit: int = 40) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _to_ascii(text: str, field: str) -> str:
    if text.isascii():
        return text
    try:
        return text.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValidationError("Domain contains characters that cannot be encoded", field) from None


def _reject_control(value: str, field: str) -> str:
    """Refuse control characters anywhere (even at the edges) instead of silently trimming them."""
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValidationError("Control characters (newlines, tabs, ...) are not allowed", field)
    return value


def _check_length(text: str, field: str) -> None:
    if len(text) > MAX_DOMAIN_LENGTH:
        raise ValidationError(f"Domain is too long (max {MAX_DOMAIN_LENGTH} characters)", field)


def _split_labels(value: object, field: str, pattern: re.Pattern[str]) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("A domain name is required", field)
    raw = _reject_control(value, field).strip().lower().rstrip(".")
    _check_length(raw, field)  # before IDNA: punycode encoding is quadratic in the input length
    text = _to_ascii(raw, field)
    _check_length(text, field)
    labels = text.split(".")
    for label in labels:
        if not label:
            raise ValidationError("Domain contains an empty label (two dots in a row)", field)
        if not pattern.fullmatch(label):
            raise ValidationError(f"Invalid label '{_short(label)}' in domain", field)
    return labels


def normalize_domain(value: object, field: str = "domain") -> str:
    """Lower-case, IDNA-encode and validate a fully qualified domain name."""
    labels = _split_labels(value, field, _DOMAIN_LABEL)
    if len(labels) < 2:
        raise ValidationError("Enter a fully qualified domain such as example.com", field)
    if labels[-1].isdigit():
        raise ValidationError("The top-level domain cannot be numeric", field)
    return ".".join(labels)


def validate_ip(value: object, field: str = "value", version: int | None = None) -> str:
    text = str(value).strip()
    try:
        if "%" in text:  # scoped IPv6 (fe80::1%eth0) is meaningless in DNS data
            raise ValueError(text)
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ValidationError(f"'{_short(value)}' is not a valid IP address", field) from None
    if version is not None and address.version != version:
        raise ValidationError(f"Expected an IPv{version} address", field)
    return str(address)


def validate_cidr(value: object, field: str = "value") -> str:
    try:
        network = ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError:
        raise ValidationError(
            f"'{_short(value)}' is not a valid network (use CIDR such as 192.168.56.0/24)", field
        ) from None
    return str(network)


def _coerce_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?[0-9]{1,12}", value.strip()):
        return int(value.strip())
    return None


def validate_int(value: object, field: str, low: int, high: int, label: str) -> int:
    number = _coerce_int(value)
    if number is None:
        raise ValidationError(f"{label} must be a whole number", field)
    if not low <= number <= high:
        raise ValidationError(f"{label} must be between {low:,} and {high:,}", field)
    return number


def validate_bool(data: Mapping[str, object], field: str, label: str) -> bool:
    value = data.get(field)
    if not isinstance(value, bool):
        raise ValidationError(f"{label} must be true or false", field)
    return value


def validate_ttl(value: object, field: str = "ttl") -> int:
    return validate_int(value, field, TTL_MIN, TTL_MAX, "TTL")


def validate_choice(value: object, choices: Iterable[str], field: str, label: str) -> str:
    options = tuple(choices)
    text = str(value or "").strip().lower()
    if text not in options:
        raise ValidationError(f"{label} must be one of: {', '.join(options)}", field)
    return text


def _hostname_target(value: object, zone: str, *, allow_relative: bool, field: str = "value") -> str:
    """Absolute hostname with a trailing dot. A bare label is relative to the zone when allowed."""
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("A target hostname is required", field)
    raw = value.strip().lower()
    if raw == "@":
        return f"{zone}."
    is_relative = "." not in raw.rstrip(".") and not raw.endswith(".")
    if is_relative and not allow_relative:
        raise ValidationError(
            f"Use a fully qualified hostname such as {_short(raw)}.lab.local", field
        )
    name = ".".join(_split_labels(raw, field, _HOST_LABEL))
    return f"{name}.{zone}." if is_relative else f"{name}."


def _txt_value(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("TXT text is required", "value")
    text = value.strip()
    if len(text) > MAX_TXT_LENGTH:
        raise ValidationError(f"TXT text is limited to {MAX_TXT_LENGTH} characters", "value")
    if any(not 32 <= ord(char) <= 126 for char in text):
        raise ValidationError("TXT text may only contain printable ASCII characters", "value")
    return text


def _reverse_name(raw: str, original: object) -> str:
    labels = raw.split(".")
    if len(labels) > 3 or not all(_OCTET.fullmatch(label) and int(label) <= 255 for label in labels):
        raise ValidationError(
            f"'{_short(original)}' is not a host octet (use e.g. 20 for 192.168.56.20)", "name"
        )
    return ".".join(str(int(label)) for label in labels)


def _record_name(value: object, zone: str, kind: str) -> str:
    raw = _reject_control(str(value or ""), "name").strip().lower().rstrip(".")
    if raw in ("", "@", zone):
        return "@"
    if raw.endswith("." + zone):
        raw = raw[: -len(zone) - 1]
    if kind == "reverse":
        return _reverse_name(raw, value)
    for index, label in enumerate(raw.split(".")):
        if label == "*" and index == 0:
            continue
        if not _RECORD_LABEL.fullmatch(label):
            raise ValidationError(f"Invalid record name '{_short(value)}'", "name")
    if len(raw) + len(zone) + 1 > MAX_DOMAIN_LENGTH:
        raise ValidationError("Record name is too long", "name")
    return raw


def _record_value(rtype: str, payload: Mapping[str, object], zone: str, kind: str) -> tuple[str, int | None]:
    value = payload.get("value")
    if rtype == "A":
        return validate_ip(value, version=4), None
    if rtype == "AAAA":
        return validate_ip(value, version=6), None
    if rtype == "TXT":
        return _txt_value(value), None
    # Bare labels in a reverse zone would expand to e.g. printer.56.168.192.in-addr.arpa.
    target = _hostname_target(value, zone, allow_relative=kind == "forward")
    if rtype == "MX":
        raw_priority = payload.get("priority")
        priority = 10 if raw_priority in (None, "") else raw_priority
        return target, validate_int(priority, "priority", 0, 65_535, "Priority")
    return target, None  # CNAME, NS, PTR


def validate_record(zone: str, zone_kind: str, payload: Mapping[str, object]) -> RecordInput:
    rtype = str(payload.get("type") or "").strip().upper()
    allowed = RECORD_TYPES.get(zone_kind, ())
    if rtype not in allowed:
        raise ValidationError(f"Record type must be one of: {', '.join(allowed)}", "type")
    name = _record_name(payload.get("name"), zone, zone_kind)
    if rtype == "CNAME" and name == "@":
        raise ValidationError("A CNAME cannot be placed at the zone apex (@)", "name")
    raw_ttl = payload.get("ttl")
    ttl = DEFAULT_TTL if raw_ttl in (None, "") else validate_ttl(raw_ttl)
    value, priority = _record_value(rtype, payload, zone, zone_kind)
    return RecordInput(name=name, type=rtype, value=value, ttl=ttl, priority=priority)


def validate_username(value: object) -> str:
    text = value.strip().lower() if isinstance(value, str) else ""
    if not _USERNAME.fullmatch(text):
        raise ValidationError(
            "Username must be 3-32 characters: letters, digits, dot, dash or underscore", "username"
        )
    return text


def validate_password(value: object, field: str = "password", username: str | None = None) -> str:
    """Length 10-128, not trivially guessable and not containing the username."""
    if not isinstance(value, str) or not PASSWORD_MIN <= len(value) <= PASSWORD_MAX:
        raise ValidationError(f"Password must be between {PASSWORD_MIN} and {PASSWORD_MAX} characters", field)
    lowered = value.lower()
    if len(set(value)) == 1 or lowered in COMMON_PASSWORDS:
        raise ValidationError("This password is too common - choose something harder to guess", field)
    if username and len(username) >= 3 and username.lower() in lowered:
        raise ValidationError("The password must not contain the username", field)
    return value
