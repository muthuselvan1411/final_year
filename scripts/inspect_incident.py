#!/usr/bin/env python3
"""Inspect one persisted RansomShield incident without modifying its JSONL store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def find_incident(path: str | Path, event_id: str | None = None) -> dict[str, Any]:
    """Return the selected incident, skipping malformed JSONL lines."""
    incidents: list[dict[str, Any]] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                incidents.append(record)
    if not incidents:
        raise LookupError("No valid incident records found")
    if event_id is None:
        return incidents[-1]
    for record in incidents:
        event = record.get("event", {})
        if event.get("source_event_id") == event_id:
            return record
    raise LookupError(f"Incident not found for event ID: {event_id}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("incidents_jsonl", type=Path)
    parser.add_argument("--event-id")
    args = parser.parse_args()
    try:
        record = find_incident(args.incidents_jsonl, args.event_id)
    except (OSError, LookupError) as exc:
        print(f"Incident inspection failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
