#!/usr/bin/env python3
"""Run deterministic, non-destructive RansomShield simulation scenarios.

Scenarios use in-memory normalized event records. No files are created,
renamed, deleted, encrypted, or sent to a sensor.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from collector.normalizer import EventNormalizer
from ransomshield.integration import LiveDecisionPipeline
from ransomshield.storage import IncidentStore


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Unsupported simulation value: {type(value).__name__}")


def _event(
    timestamp: float,
    event_type: str,
    path: str,
    *,
    pid: int = 9001,
    process: str = "simulation",
    old_path: str | None = None,
) -> dict[str, Any]:
    extra: dict[str, Any] = {
        "scenario_source": "synthetic_simulation",
        "success_evidence": "unavailable",
    }
    if old_path is not None:
        extra["old_path"] = old_path
    return {
        "timestamp": timestamp,
        "pid": pid,
        "ppid": 1,
        "process": process,
        "exe": f"/usr/bin/{process}",
        "event_type": event_type,
        "path": path,
        "bytes": 0,
        "success": None,
        "extra": extra,
    }


def scenario_events(name: str) -> tuple[str, list[dict[str, Any]]]:
    if name == "benign_file_operations":
        return (
            "benign_file_operations",
            [
                _event(100.0, "FILE_OPEN", "/tmp/simulation/note.txt"),
                _event(100.1, "FILE_CLOSE", "/tmp/simulation/note.txt"),
                _event(100.2, "FILE_RENAME", "/tmp/simulation/archive.txt",
                       old_path="/tmp/simulation/note.txt"),
                _event(100.3, "FILE_DELETE", "/tmp/simulation/archive.txt"),
            ],
        )
    if name == "synthetic_rapid_file_burst":
        return (
            "synthetic_rapid_file_burst",
            [
                _event(200.0 + index * 0.01, "FILE_RENAME",
                       f"/tmp/simulation/renamed-{index}.txt",
                       old_path=f"/tmp/simulation/file-{index}.txt",
                       pid=9002,
                       process="synthetic-pattern")
                for index in range(12)
            ],
        )
    raise ValueError(f"Unknown scenario: {name}")


def run_scenario(name: str, output_dir: str | Path | None = None) -> dict[str, Any]:
    scenario_name, raw_events = scenario_events(name)
    normalizer = EventNormalizer(compute_entropy=False)
    decisions: Counter[str] = Counter()
    observed_types: Counter[str] = Counter()
    failures: list[str] = []
    normalized_events = []
    for index, raw_event in enumerate(raw_events, 1):
        try:
            normalized_events.append(
                normalizer.normalize(
                    raw_event,
                    source_context=f"simulation:{scenario_name}",
                    occurrence_index=index,
                )
            )
        except (TypeError, ValueError, KeyError, OverflowError) as exc:
            failures.append(f"event {index}: normalization failed: {exc}")

    store = None
    if output_dir is not None:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        incident_path = output / "incidents.jsonl"
        summary_path = output / "simulation_summary.json"
        existing = [path for path in (incident_path, summary_path) if path.exists()]
        if existing:
            raise FileExistsError(
                "Refusing to append to existing simulation output: "
                + ", ".join(str(path) for path in existing)
            )
        store = IncidentStore(incident_path)
    pipeline = LiveDecisionPipeline(store=store)
    decision_rows = []
    for event in normalized_events:
        observed_types[event["event_type"]] += 1
        decision = pipeline.process_event(event)
        decisions[decision.action] += 1
        decision_rows.append(
            {
                "event_type": event["event_type"],
                "path": event["path"],
                "decision": decision.action,
                "source_event_id": event["source_event_id"],
                "supporting_event_ids": list(
                    pipeline.last_record.get("supporting_event_ids", [])
                ),
                "features": pipeline.last_record["features"]["values"],
                "event_window": pipeline.last_record["evidence"]["event_window"],
            }
        )

    result = {
        "scenario": scenario_name,
        "source": "synthetic_simulation",
        "expected_event_count": len(raw_events),
        "observed_event_count": len(normalized_events),
        "expected_event_types": dict(Counter(event["event_type"] for event in raw_events)),
        "observed_event_types": dict(observed_types),
        "processing_failures": failures,
        "decision_counts": dict(decisions),
        "decisions": decision_rows,
        "detector_status": "unavailable",
        "interpretation": (
            "Generated behavior pattern only; not ransomware execution and not "
            "detection efficacy evidence."
        ),
    }
    if output_dir is not None:
        output = Path(output_dir)
        (output / "simulation_summary.json").write_text(
            json.dumps(result, indent=2, sort_keys=True, default=_json_default) + "\n",
            encoding="utf-8",
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=("benign_file_operations", "synthetic_rapid_file_burst"),
        default="benign_file_operations",
    )
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    result = run_scenario(args.scenario, args.output_dir)
    print(f"Scenario: {result['scenario']}")
    print(f"Source: {result['source']}")
    print(f"Events: {result['observed_event_count']}/{result['expected_event_count']}")
    print(f"Decisions: {result['decision_counts']}")
    print(f"Processing failures: {len(result['processing_failures'])}")
    print("Detector status: unavailable; decisions must not be interpreted as benign.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
