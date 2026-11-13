"""Domain errors shared by the core and the web layer."""
from __future__ import annotations


class ValidationError(ValueError):
    """Rejected user input. ``field`` names the offending form field, if any."""

    def __init__(self, message: str, field: str | None = None) -> None:
        super().__init__(message)
        self.field = field


class NotFoundError(LookupError):
    """The requested zone, record, rule, user or category does not exist."""
