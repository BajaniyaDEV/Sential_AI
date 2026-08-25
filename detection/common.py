"""Shared normalization helpers for Phase 3 detection modules."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any


def event_value(event: Any, field: str) -> Any:
    """Return a field from a SecurityEvent, mapping, or compatible object."""
    if isinstance(event, Mapping):
        return event[field]
    if is_dataclass(event):
        return asdict(event)[field]
    return getattr(event, field)


def event_timestamp(event: Any) -> datetime:
    """Return a parsed authentication-event timestamp."""
    return datetime.strptime(str(event_value(event, "timestamp")), "%Y-%m-%d %H:%M:%S")


def event_dict(event: Any) -> dict[str, Any]:
    """Return the fields needed in a detection result."""
    result = {
        "timestamp": str(event_value(event, "timestamp")),
        "user": str(event_value(event, "user")),
        "event": str(event_value(event, "event")),
        "ip": str(event_value(event, "ip")),
    }
    try:
        result["source_line"] = event_value(event, "source_line")
    except (AttributeError, KeyError):
        pass
    return result
