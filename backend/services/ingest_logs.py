"""Command-line entry point for Phase 2 log ingestion.

Example:
    python -m backend.services.ingest_logs data/raw_logs/sample_auth.log
"""

from __future__ import annotations

import argparse
from pathlib import Path

from backend.services.log_parser import LogParseError, parse_log_file, write_events


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert SentinelAI authentication logs to structured data.")
    parser.add_argument("input", type=Path, help="Path to a plaintext authentication log")
    parser.add_argument("--format", choices=("csv", "json"), default="csv", help="Output format (default: csv)")
    parser.add_argument("--output", type=Path, help="Destination file (defaults to data/processed_logs)")
    parser.add_argument("--strict", action="store_true", help="Stop on the first malformed log line")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        events, errors = parse_log_file(args.input, strict=args.strict)
    except (OSError, LogParseError) as error:
        print(f"Ingestion failed: {error}")
        return 1

    output = args.output or Path("data/processed_logs") / f"{args.input.stem}.{args.format}"
    write_events(events, output, args.format)
    print(f"Parsed {len(events)} event(s) into {output}")
    for error in errors:
        print(f"Warning: {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
