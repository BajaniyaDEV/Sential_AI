"""Parsing and preprocessing for SentinelAI authentication logs.

The parser deliberately uses the Python standard library so that collecting
logs remains available even in a minimal deployment.  Its normalized records
are suitable input for later detection and machine-learning phases.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable


LOG_PATTERN = re.compile(
    r"^\s*"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<status>INFO|FAILED)\s+"
    r"User=(?P<user>\S+)\s+"
    r"Login\s+(?P<action>successful|failed)\s+"
    r"IP=(?P<ip>\S+)\s*$",
    re.IGNORECASE,
)

EVENT_LOG_PATTERN = re.compile(
    r"^\s*"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<status>INFO|FAILED)\s+"
    r"User=(?P<user>\S+)\s+"
    r"Event=(?P<event>LOGIN_SUCCESS|LOGIN_FAILED)\s+"
    r"IP=(?P<ip>\S+)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SecurityEvent:
    """A normalized authentication event."""

    timestamp: str
    user: str
    event: str
    ip: str
    source_line: int


class LogParseError(ValueError):
    """Raised when strict parsing encounters an invalid log entry."""


def parse_log_line(line: str, line_number: int = 1) -> SecurityEvent:
    """Convert one supported authentication-log line into a SecurityEvent."""
    match = LOG_PATTERN.match(line) or EVENT_LOG_PATTERN.match(line)
    if not match:
        raise LogParseError(f"Line {line_number}: unsupported log format")

    fields = match.groupdict()
    try:
        timestamp = datetime.strptime(fields["timestamp"], "%Y-%m-%d %H:%M:%S")
    except ValueError as error:
        raise LogParseError(f"Line {line_number}: invalid timestamp") from error

    try:
        ip = str(ip_address(fields["ip"]))
    except ValueError as error:
        raise LogParseError(f"Line {line_number}: invalid IP address") from error

    status = fields["status"].upper()
    action = fields.get("action")
    event_name = fields.get("event")
    successful = action.lower() == "successful" if action else event_name.upper() == "LOGIN_SUCCESS"
    # Legacy lines encode outcome in the status word; the guide's Event= form
    # uses INFO as a log level and encodes outcome in Event instead.
    if action and ((status == "INFO" and not successful) or (status == "FAILED" and successful)):
        raise LogParseError(f"Line {line_number}: status and login result disagree")

    return SecurityEvent(
        timestamp=timestamp.isoformat(sep=" "),
        user=fields["user"],
        event="Success" if successful else "Failed",
        ip=ip,
        source_line=line_number,
    )


def parse_log_lines(lines: Iterable[str], strict: bool = False) -> tuple[list[SecurityEvent], list[str]]:
    """Parse log lines, collecting malformed-line messages unless strict."""
    events: list[SecurityEvent] = []
    errors: list[str] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            events.append(parse_log_line(line, number))
        except LogParseError as error:
            if strict:
                raise
            errors.append(str(error))
    return events, errors


def parse_log_file(path: str | Path, strict: bool = False) -> tuple[list[SecurityEvent], list[str]]:
    """Read and parse a UTF-8 plaintext log file."""
    with Path(path).open(encoding="utf-8") as log_file:
        return parse_log_lines(log_file, strict=strict)


def write_events(events: Iterable[SecurityEvent], output_path: str | Path, output_format: str) -> Path:
    """Write events as CSV or JSON and return the created output path."""
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    records = [asdict(event) for event in events]

    if output_format == "csv":
        with destination.open("w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=SecurityEvent.__dataclass_fields__.keys())
            writer.writeheader()
            writer.writerows(records)
    elif output_format == "json":
        with destination.open("w", encoding="utf-8") as output:
            json.dump(records, output, indent=2)
    else:
        raise ValueError("output_format must be 'csv' or 'json'")
    return destination
