"""Detect repeated failed logins from public IP addresses."""

from __future__ import annotations

from collections import Counter
from ipaddress import ip_address
from typing import Any

from detection.common import event_dict, event_value


def detect_suspicious_ip(logs: list[Any], threshold: int = 5) -> list[dict]:
    """Flag public IPs with at least ``threshold`` failed logins."""
    if threshold < 1:
        raise ValueError("threshold must be positive")
    failures = [
        event
        for event in logs
        if str(event_value(event, "event")).lower() == "failed"
        and not ip_address(str(event_value(event, "ip"))).is_private
    ]
    counts = Counter(str(event_value(event, "ip")) for event in failures)
    alerts = []
    for ip, count in sorted(counts.items()):
        if count >= threshold:
            sample = next(event for event in failures if str(event_value(event, "ip")) == ip)
            alerts.append(
                {
                    "type": "suspicious_ip",
                    "severity": "medium",
                    "ip": ip,
                    "failed_attempts": count,
                    "sample_event": event_dict(sample),
                    "message": f"Public IP {ip} generated {count} failed login(s)",
                }
            )
    return alerts
