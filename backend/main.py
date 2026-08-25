"""SentinelAI backend entry point."""

import sys
from pathlib import Path

# Support both `python backend/main.py` (documented quick start) and
# `python -m backend.main` (package execution).
if __package__ in (None, ""):
    project_root = str(Path(__file__).resolve().parents[1])
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from backend.database.repository import (
    create_incident,
    get_alert,
    get_incident,
    get_incidents,
    get_recent_alerts,
    insert_alerts,
    insert_events,
    update_alert_status,
)

from backend.services.log_parser import LogParseError, parse_log_lines

from detection.anomaly_detection import detect_anomalies
from detection.brute_force import detect_brute_force
from detection.suspicious_login import detect_success_after_failures
from detection.suspicious_ip import detect_suspicious_ip

# MITRE ATT&CK mapper
from mitre.mapper import get_mitre_mapping


app = FastAPI(
    title="SentinelAI",
    version="0.1.0"
)


class LogTextRequest(BaseModel):
    """Plaintext authentication logs submitted for normalization."""

    logs: str
    strict: bool = False


class AlertStatusRequest(BaseModel):
    """Request model for updating an alert status."""

    status: str


class IncidentRequest(BaseModel):
    """Request model for creating an incident."""

    title: str
    severity: str
    alert_ids: list[str]


@app.get("/")
def read_root() -> dict:
    """Check whether the SentinelAI backend is running."""

    return {
        "message": "SentinelAI backend is running."
    }


@app.get("/health")
def health_check() -> dict:
    """Health check endpoint."""

    return {
        "status": "ok"
    }


@app.post("/logs/parse")
def parse_logs(request: LogTextRequest) -> dict:
    """Normalize supported plaintext authentication logs into JSON records."""

    try:
        events, errors = parse_log_lines(
            request.logs.splitlines(),
            strict=request.strict
        )

    except LogParseError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error)
        ) from error

    return {
        "events": [
            event.__dict__
            for event in events
        ],
        "parsed_count": len(events),
        "errors": errors,
    }


def add_mitre_context(alerts):
    """
    Add MITRE ATT&CK context to each generated alert.

    Supports dictionary-based alerts and object-based alerts.
    """

    enriched_alerts = []

    for alert in alerts:

        # Handle dictionary-based alerts
        if isinstance(alert, dict):

            alert_type = (
                alert.get("alert_type")
                or alert.get("type")
                or alert.get("detection_type")
            )

            if alert_type:
                mitre_context = get_mitre_mapping(alert_type)

                alert["mitre"] = mitre_context

            enriched_alerts.append(alert)

        # Handle object-based alerts
        else:

            alert_type = (
                getattr(alert, "alert_type", None)
                or getattr(alert, "type", None)
                or getattr(alert, "detection_type", None)
            )

            if alert_type:

                mitre_context = get_mitre_mapping(alert_type)

                try:
                    setattr(
                        alert,
                        "mitre",
                        mitre_context
                    )
                except AttributeError:
                    pass

            enriched_alerts.append(alert)

    return enriched_alerts


@app.post("/logs/analyze")
def analyze_logs(request: LogTextRequest) -> dict:
    """
    Parse plaintext logs, run all detection methods,
    add MITRE ATT&CK context, and store results.
    """

    try:
        events, errors = parse_log_lines(
            request.logs.splitlines(),
            strict=request.strict
        )

    except LogParseError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error)
        ) from error


    # ------------------------------------------
    # RUN DETECTION MODULES
    # ------------------------------------------

    brute_force = detect_brute_force(events)

    suspicious_ips = detect_suspicious_ip(events)

    successful_after_failures = detect_success_after_failures(events)

    anomalies = detect_anomalies(events)


    # ------------------------------------------
    # STORE NORMALIZED EVENTS
    # ------------------------------------------

    stored_event_ids = insert_events(events)


    # ------------------------------------------
    # COMBINE ALL DETECTED ALERTS
    # ------------------------------------------

    all_alerts = (
        brute_force
        + suspicious_ips
        + successful_after_failures
        + anomalies
    )


    # ------------------------------------------
    # ADD MITRE ATT&CK CONTEXT
    # ------------------------------------------

    enriched_alerts = add_mitre_context(all_alerts)


    # ------------------------------------------
    # STORE ALERTS
    # ------------------------------------------

    stored_alerts = insert_alerts(enriched_alerts)


    # ------------------------------------------
    # RETURN ANALYSIS RESULTS
    # ------------------------------------------

    return {

        "events": [
            event.__dict__
            for event in events
        ],

        "stored_event_ids": stored_event_ids,

        "parse_errors": errors,

        "alerts": stored_alerts,

        "summary": {

            "brute_force": len(brute_force),

            "suspicious_ip": len(suspicious_ips),

            "success_after_failures": len(
                successful_after_failures
            ),

            "anomaly": len(anomalies),
        },
    }


@app.post("/logs/analyze-and-store")
def analyze_and_store_logs(
    request: LogTextRequest
) -> dict:
    """
    Compatibility alias for the storage-enabled
    /logs/analyze endpoint.
    """

    return analyze_logs(request)


@app.get("/alerts")
def list_alerts(limit: int = 100) -> dict:
    """Return recent SentinelAI alerts."""

    alerts = get_recent_alerts(limit)

    return {
        "alerts": alerts,
        "count": len(alerts)
    }


@app.get("/alerts/{alert_id}")
def read_alert(alert_id: str) -> dict:
    """Return a specific alert."""

    alert = get_alert(alert_id)

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return alert


@app.patch("/alerts/{alert_id}/status")
def set_alert_status(
    alert_id: str,
    request: AlertStatusRequest
) -> dict:
    """Update the status of an existing alert."""

    try:

        alert = update_alert_status(
            alert_id,
            request.status
        )

    except ValueError as error:

        raise HTTPException(
            status_code=422,
            detail=str(error)
        ) from error

    if not alert:

        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return alert


@app.get("/incidents")
def list_incidents() -> dict:
    """Return all SentinelAI incidents."""

    incidents = get_incidents()

    return {
        "incidents": incidents,
        "count": len(incidents)
    }


@app.post("/incidents")
def create_new_incident(
    request: IncidentRequest
) -> dict:
    """Create a new incident from selected alerts."""

    try:

        return create_incident(
            request.title,
            request.severity,
            request.alert_ids
        )

    except ValueError as error:

        raise HTTPException(
            status_code=422,
            detail=str(error)
        ) from error


@app.get("/incidents/{incident_id}")
def read_incident(
    incident_id: str
) -> dict:
    """Return a specific incident."""

    incident = get_incident(incident_id)

    if not incident:

        raise HTTPException(
            status_code=404,
            detail="Incident not found"
        )

    return incident


if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )