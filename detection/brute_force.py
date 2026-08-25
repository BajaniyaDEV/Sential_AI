"""Detect repeated failed authentication attempts in a short time window."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import timedelta
from typing import Any

from detection.common import event_dict, event_timestamp, event_value


def detect_brute_force(
    logs: list[Any], threshold: int = 5, window_minutes: int = 5
) -> list[dict]:
    """Return alerts for failed attempts by one user/IP within a time window.

    An alert is emitted when the threshold is first reached, preventing one
    alert per log line during a single password-guessing burst.
    """
    if threshold < 2 or window_minutes <= 0:
        raise ValueError("threshold must be at least 2 and window_minutes must be positive")

    failures = sorted(
        (event for event in logs if str(event_value(event, "event")).lower() == "failed"),
        key=event_timestamp,
    )
    windows: dict[tuple[str, str], deque] = defaultdict(deque)
    alerted: set[tuple[str, str]] = set()
    alerts: list[dict] = []
    duration = timedelta(minutes=window_minutes)

    for event in failures:
        key = (str(event_value(event, "user")), str(event_value(event, "ip")))
        current_window = windows[key]
        timestamp = event_timestamp(event)
        while current_window and timestamp - event_timestamp(current_window[0]) > duration:
            current_window.popleft()
            alerted.discard(key)
        current_window.append(event)
        if len(current_window) >= threshold and key not in alerted:
            alerts.append(
                {
                    "type": "brute_force",
                    "severity": "high",
                    "user": key[0],
                    "ip": key[1],
                    "failed_attempts": len(current_window),
                    "window_minutes": window_minutes,
                    "first_seen": event_dict(current_window[0])["timestamp"],
                    "last_seen": event_dict(event)["timestamp"],
                    "message": f"{len(current_window)} failed logins for {key[0]} from {key[1]}",
                }
            )
            alerted.add(key)
    return alerts
