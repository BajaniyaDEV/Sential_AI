"""SQLite persistence layer for SentinelAI events, alerts, and incidents."""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DATABASE_PATH = Path(__file__).resolve().parents[2] / "data" / "sentinelai.db"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connection(database_path: str | Path = DATABASE_PATH) -> sqlite3.Connection:
    path = Path(database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database(database_path: str | Path = DATABASE_PATH) -> None:
    """Create the SentinelAI schema when it does not already exist."""
    with _connection(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_line INTEGER,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                primary_user TEXT,
                source_ip TEXT,
                first_event_at TEXT,
                last_event_at TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                alert_timestamp TEXT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                description TEXT NOT NULL,
                status TEXT NOT NULL,
                mitre_technique_id TEXT,
                anomaly_score REAL,
                evidence_json TEXT NOT NULL,
                incident_id TEXT REFERENCES incidents(incident_id)
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_incident_id ON alerts(incident_id);
            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
            """
        )


def insert_events(events: Iterable[Any], database_path: str | Path = DATABASE_PATH) -> list[int]:
    """Persist normalized events and return their database IDs."""
    initialize_database(database_path)
    records = [
        (
            event.timestamp if hasattr(event, "timestamp") else event["timestamp"],
            event.user if hasattr(event, "user") else event["user"],
            event.event if hasattr(event, "event") else event["event"],
            event.ip if hasattr(event, "ip") else event["ip"],
            event.source_line if hasattr(event, "source_line") else event.get("source_line"),
            _now(),
        )
        for event in events
    ]
    if not records:
        return []
    with _connection(database_path) as connection:
        cursor = connection.cursor()
        ids = []
        for record in records:
            cursor.execute(
                """INSERT INTO events
                (timestamp, username, event_type, source_ip, source_line, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""",
                record,
            )
            ids.append(cursor.lastrowid)
    return ids


def _alert_timestamp(alert: dict[str, Any]) -> str | None:
    for key in ("last_seen", "first_seen", "first_failure"):
        if alert.get(key):
            return str(alert[key])
    for key in ("successful_login", "sample_event", "event"):
        nested = alert.get(key)
        if isinstance(nested, dict) and nested.get("timestamp"):
            return str(nested["timestamp"])
    return None


def insert_alerts(alerts: Iterable[dict[str, Any]], database_path: str | Path = DATABASE_PATH) -> list[dict[str, Any]]:
    """Persist alerts, returning copies enriched with stable alert IDs and status."""
    initialize_database(database_path)
    saved: list[dict[str, Any]] = []
    with _connection(database_path) as connection:
        for alert in alerts:
            stored = dict(alert)
            stored["alert_id"] = str(uuid.uuid4())
            stored["status"] = "open"
            connection.execute(
                """INSERT INTO alerts
                (alert_id, created_at, alert_timestamp, alert_type, severity, source_ip,
                 username, description, status, mitre_technique_id, anomaly_score, evidence_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    stored["alert_id"],
                    _now(),
                    _alert_timestamp(stored),
                    stored["type"],
                    stored["severity"],
                    stored.get("ip"),
                    stored.get("user"),
                    stored["message"],
                    stored["status"],
                    stored.get("mitre_technique_id"),
                    stored.get("score"),
                    json.dumps(alert),
                ),
            )
            saved.append(stored)
    return saved


def _alert_from_row(row: sqlite3.Row) -> dict[str, Any]:
    alert = dict(row)
    alert["evidence"] = json.loads(alert.pop("evidence_json"))
    return alert


def get_recent_alerts(limit: int = 100, database_path: str | Path = DATABASE_PATH) -> list[dict[str, Any]]:
    """Return the newest alerts, capped to a safe query limit."""
    initialize_database(database_path)
    limit = max(1, min(limit, 500))
    with _connection(database_path) as connection:
        rows = connection.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
    return [_alert_from_row(row) for row in rows]


def get_alert(alert_id: str, database_path: str | Path = DATABASE_PATH) -> dict[str, Any] | None:
    """Retrieve a single alert by ID."""
    initialize_database(database_path)
    with _connection(database_path) as connection:
        row = connection.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    return _alert_from_row(row) if row else None


def update_alert_status(alert_id: str, status: str, database_path: str | Path = DATABASE_PATH) -> dict[str, Any] | None:
    """Update an alert's analyst workflow status."""
    if status not in {"open", "investigating", "closed"}:
        raise ValueError("status must be open, investigating, or closed")
    initialize_database(database_path)
    with _connection(database_path) as connection:
        cursor = connection.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
    return get_alert(alert_id, database_path) if cursor.rowcount else None


def create_incident(
    title: str,
    severity: str,
    alert_ids: list[str],
    database_path: str | Path = DATABASE_PATH,
) -> dict[str, Any]:
    """Create an incident and associate the specified existing alerts with it."""
    initialize_database(database_path)
    incident_id = str(uuid.uuid4())
    now = _now()
    with _connection(database_path) as connection:
        alerts = connection.execute(
            f"SELECT * FROM alerts WHERE alert_id IN ({','.join('?' for _ in alert_ids)})", alert_ids
        ).fetchall() if alert_ids else []
        if len(alerts) != len(set(alert_ids)):
            raise ValueError("every alert_id must refer to an existing alert")
        source_ips = {row["source_ip"] for row in alerts if row["source_ip"]}
        users = {row["username"] for row in alerts if row["username"]}
        timestamps = [row["alert_timestamp"] for row in alerts if row["alert_timestamp"]]
        connection.execute(
            """INSERT INTO incidents
            (incident_id, created_at, updated_at, title, severity, status, primary_user,
             source_ip, first_event_at, last_event_at)
            VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)""",
            (incident_id, now, now, title, severity, next(iter(users), None), next(iter(source_ips), None),
             min(timestamps) if timestamps else None, max(timestamps) if timestamps else None),
        )
        if alert_ids:
            connection.executemany("UPDATE alerts SET incident_id = ? WHERE alert_id = ?", [(incident_id, alert_id) for alert_id in alert_ids])
    return get_incident(incident_id, database_path)  # type: ignore[return-value]


def get_incidents(database_path: str | Path = DATABASE_PATH) -> list[dict[str, Any]]:
    """Retrieve incidents with their number of associated alerts."""
    initialize_database(database_path)
    with _connection(database_path) as connection:
        rows = connection.execute(
            """SELECT incidents.*, COUNT(alerts.alert_id) AS alert_count
            FROM incidents LEFT JOIN alerts ON alerts.incident_id = incidents.incident_id
            GROUP BY incidents.incident_id ORDER BY incidents.created_at DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


def get_incident(incident_id: str, database_path: str | Path = DATABASE_PATH) -> dict[str, Any] | None:
    """Retrieve an incident with its alerts and related source-IP events."""
    initialize_database(database_path)
    with _connection(database_path) as connection:
        incident = connection.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        if not incident:
            return None
        alerts = connection.execute("SELECT * FROM alerts WHERE incident_id = ? ORDER BY created_at", (incident_id,)).fetchall()
        events = []
        if incident["source_ip"]:
            events = connection.execute(
                "SELECT * FROM events WHERE source_ip = ? ORDER BY timestamp", (incident["source_ip"],)
            ).fetchall()
    result = dict(incident)
    result["alerts"] = [_alert_from_row(row) for row in alerts]
    result["events"] = [dict(row) for row in events]
    return result
