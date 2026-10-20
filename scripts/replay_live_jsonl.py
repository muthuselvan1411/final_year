#!/usr/bin/env python3
"""Replay captured normalized sensor JSONL through the live advisory pipeline.

This is functional pipeline validation only. It does not execute workloads,
load BPF programs, invoke the MLRan model, or enable containment.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from collector.normalizer import EventNormalizer
from ransomshield.integration import LiveDecisionPipeline
from ransomshield.storage import IncidentStore, StorageError


def _invalid_identifier(value: Any) -> bool:
    if value is None:
        return True
    try:
        return int(value) <= 0
    except (TypeError, ValueError):
        return True


def _prepare_output(output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    incidents = output_dir / "incidents.jsonl"
    summary = output_dir / "replay_summary.json"
    existing = [path for path in (incidents, summary) if path.exists()]
    if existing:
        names = ", ".join(str(path) for path in existing)
        raise FileExistsError(
            f"Refusing to overwrite existing replay output: {names}"
        )
    return incidents, summary


def replay_jsonl(
    input_path: str | Path,
    output_dir: str | Path,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    """Replay one JSON object per line and return a machine-readable summary."""
    source = Path(input_path)
    if not source.is_file():
        raise FileNotFoundError(f"Input JSONL not found: {source}")
    incidents_path, summary_path = _prepare_output(Path(output_dir))

    normalizer = EventNormalizer(compute_entropy=False)
    pipeline = LiveDecisionPipeline(store=IncidentStore(incidents_path))
    event_types: Counter[str] = Counter()
    decisions: Counter[str] = Counter()
    summary: dict[str, Any] = {
        "input_path": str(source),
        "output_dir": str(Path(output_dir)),
        "input_lines": 0,
        "valid_json_records": 0,
        "malformed_json_records": 0,
        "non_object_records": 0,
        "normalization_failures": 0,
        "processed_events": 0,
        "pipeline_failures": 0,
        "storage_failures": 0,
        "incident_records_written": 0,
        "abstentions": 0,
        "event_type_counts": {},
        "decision_counts": {},
        "missing_or_invalid_pid": 0,
        "missing_or_invalid_ppid": 0,
        "errors": [],
    }

    def record_error(line_number: int, category: str, message: str) -> None:
        summary["errors"].append(
            {"line": line_number, "category": category, "message": message}
        )

    try:
        with source.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                summary["input_lines"] += 1
                if not line.strip():
                    record_error(line_number, "malformed_json", "blank line")
                    summary["malformed_json_records"] += 1
                    if strict:
                        raise ValueError(f"Blank line at {source}:{line_number}")
                    continue
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    summary["malformed_json_records"] += 1
                    record_error(line_number, "malformed_json", str(exc))
                    if strict:
                        raise ValueError(f"Invalid JSON at {source}:{line_number}") from exc
                    continue
                summary["valid_json_records"] += 1
                if not isinstance(raw, dict):
                    summary["non_object_records"] += 1
                    record_error(line_number, "non_object", "expected a JSON object")
                    if strict:
                        raise ValueError(f"Expected object at {source}:{line_number}")
                    continue

                if _invalid_identifier(raw.get("pid")):
                    summary["missing_or_invalid_pid"] += 1
                if _invalid_identifier(raw.get("ppid")):
                    summary["missing_or_invalid_ppid"] += 1

                try:
                    event = normalizer.normalize(
                        raw,
                        source_context=f"replay:{source.resolve()}",
                        occurrence_index=line_number,
                    )
                except (TypeError, ValueError, KeyError, OverflowError) as exc:
                    summary["normalization_failures"] += 1
                    record_error(line_number, "normalization", str(exc))
                    if strict:
                        raise
                    continue
                event_types[event["event_type"]] += 1
                try:
                    decision = pipeline.process_event(event)
                except StorageError as exc:
                    summary["storage_failures"] += 1
                    record_error(line_number, "storage", str(exc))
                    raise
                except Exception as exc:
                    summary["pipeline_failures"] += 1
                    record_error(line_number, "pipeline", str(exc))
                    if strict:
                        raise
                    continue
                summary["processed_events"] += 1
                decisions[decision.action] += 1
                if decision.action == "ABSTAIN":
                    summary["abstentions"] += 1
    except Exception:
        summary["event_type_counts"] = dict(event_types)
        summary["decision_counts"] = dict(decisions)
        summary["incident_records_written"] = (
            sum(1 for _ in incidents_path.open(encoding="utf-8"))
            if incidents_path.exists()
            else 0
        )
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        raise

    summary["event_type_counts"] = dict(event_types)
    summary["decision_counts"] = dict(decisions)
    summary["incident_records_written"] = (
        sum(1 for _ in incidents_path.open(encoding="utf-8"))
        if incidents_path.exists()
        else 0
    )
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_jsonl", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Stop on malformed, non-object, or normalization errors.",
    )
    args = parser.parse_args()
    try:
        summary = replay_jsonl(
            args.input_jsonl,
            args.output_dir,
            strict=args.strict,
        )
    except (FileExistsError, FileNotFoundError, ValueError, StorageError) as exc:
        print(f"Replay failed: {exc}", file=sys.stderr)
        return 1

    print(f"Input lines: {summary['input_lines']}")
    print(f"Processed events: {summary['processed_events']}")
    print(f"Malformed records: {summary['malformed_json_records']}")
    print(f"Normalization failures: {summary['normalization_failures']}")
    print(f"Pipeline failures: {summary['pipeline_failures']}")
    print(f"Storage failures: {summary['storage_failures']}")
    print(f"Decisions: {summary['decision_counts']}")
    print(f"Abstentions: {summary['abstentions']}")
    print(f"Incidents written: {summary['incident_records_written']}")
    print(f"Summary: {args.output_dir / 'replay_summary.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
