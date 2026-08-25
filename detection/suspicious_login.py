"""Detect successful authentication after repeated failures."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Any

from detection.common import event_dict, event_timestamp, event_value


def detect_success_after_failures(
    logs: list[Any], threshold: int = 3, window_minutes: int = 5
) -> list[dict]:
    """Flag a successful login preceded by failed attempts from the same IP/user."""
    if threshold < 1 or window_minutes <= 0:
        raise ValueError("threshold and window_minutes must be positive")

    events = sorted(logs, key=event_timestamp)
    failures: dict[tuple[str, str], deque] = defaultdict(deque)
    alerts: list[dict] = []
    duration = timedelta(minutes=window_minutes)

    for event in events:
        key = (str(event_value(event, "user")), str(event_value(event, "ip")))
        timestamp = event_timestamp(event)
        history = failures[key]
        while history and timestamp - event_timestamp(history[0]) > duration:
            history.popleft()

        if str(event_value(event, "event")).lower() == "failed":
            history.append(event)
        elif len(history) >= threshold:
            alerts.append(
                {
                    "type": "success_after_failures",
                    "severity": "high",
                    "user": key[0],
                    "ip": key[1],
                    "failed_attempts": len(history),
                    "window_minutes": window_minutes,
                    "first_failure": event_dict(history[0])["timestamp"],
                    "successful_login": event_dict(event),
                    "message": (
                        f"Successful login for {key[0]} followed {len(history)} failed "
                        f"attempt(s) from {key[1]}"
                    ),
                }
            )
            history.clear()
    return alerts
