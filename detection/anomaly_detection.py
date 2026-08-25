"""Isolation Forest-based anomaly detection for authentication events."""

from __future__ import annotations

from collections import Counter
from ipaddress import ip_address
from typing import Any

from sklearn.ensemble import IsolationForest

from detection.common import event_dict, event_timestamp, event_value


def detect_anomalies(logs: list[Any], contamination: float = 0.15) -> list[dict]:
    """Return unusual events using time, failure, and event-frequency features.

    At least five events are required: smaller samples do not provide a useful
    baseline and therefore produce no ML alerts.
    """
    if not 0 < contamination <= 0.5:
        raise ValueError("contamination must be greater than 0 and at most 0.5")
    if len(logs) < 5:
        return []

    ip_counts = Counter(str(event_value(event, "ip")) for event in logs)
    user_counts = Counter(str(event_value(event, "user")) for event in logs)
    features = []
    for event in logs:
        timestamp = event_timestamp(event)
        ip = ip_address(str(event_value(event, "ip")))
        features.append(
            [
                timestamp.hour + timestamp.minute / 60,
                int(str(event_value(event, "event")).lower() == "failed"),
                int(not ip.is_private),
                ip_counts[str(ip)],
                user_counts[str(event_value(event, "user"))],
            ]
        )

    model = IsolationForest(contamination=contamination, random_state=42)
    predictions = model.fit_predict(features)
    scores = model.decision_function(features)
    return [
        {
            "type": "anomaly",
            "severity": "medium",
            "score": round(float(scores[index]), 4),
            "event": event_dict(event),
            "message": "Authentication event differs from the observed baseline",
        }
        for index, event in enumerate(logs)
        if predictions[index] == -1
    ]
