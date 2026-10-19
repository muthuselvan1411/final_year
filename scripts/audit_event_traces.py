#!/usr/bin/env python3
"""Audit recorded telemetry and emit a data-gap report.

This command does not train, score, tune, or execute any detector.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ransomshield.evaluation.trace_audit import audit_events


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        events = [json.loads(line) for line in handle if line.strip()]
    if not events or not all(isinstance(event, dict) for event in events):
        raise ValueError(f"{path} is empty or contains non-object records")
    return events


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir", default="results/event_level_data_audit_v1"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output_dir = root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    traces = [
        ("benign_events.jsonl", 0, "controlled_benign_workload"),
        ("ransomware_events.jsonl", 1, "controlled_synthetic_ransomware_workload"),
    ]
    audits = []
    provenance = []
    for filename, label, group in traces:
        source_path = root / "datasets" / filename
        events = read_jsonl(source_path)
        audit = audit_events(events, trace_group=group)
        audits.append(
            {
                "file": filename,
                "reporting_label": label,
                "label_provenance": "companion controlled-workload report",
                **audit.to_dict(),
            }
        )
        provenance.append(
            {
                "file": filename,
                "sha256": hashlib.sha256(source_path.read_bytes()).hexdigest(),
                "label": label,
                "label_source": str(
                    root
                    / "datasets"
                    / filename.replace("_events.jsonl", "_results.json")
                ),
                "classification": (
                    "BENIGN" if label == 0 else "RANSOMWARE_LIKE"
                ),
                "independent_real_world_benchmark": False,
            }
        )

    report = {
        "result_category": "data_gap_audit",
        "efficacy_evaluation_run": False,
        "audits": audits,
        "label_provenance": provenance,
        "detector_compatibility": {
            "mlran_schema_id": "schema-mlran-rfe-483",
            "mlran_feature_count": 483,
            "recorded_event_schema": [
                "timestamp",
                "pid",
                "ppid",
                "process",
                "event_type",
                "path",
                "bytes",
            ],
            "compatible_per_window_model_available": False,
            "raw_event_to_mlran_mapping_validated": False,
            "decision": "blocked_before_efficacy",
            "reason": "Event records are not the 483-feature MLRan input schema and no compatible per-window model artifact exists.",
        },
        "minimum_data_needed": [
            "Independently labeled event traces with many benign workloads and ransomware families.",
            "Per-window detector scores generated from the same event schema.",
            "Trace/process group IDs and process lifetime information for leakage-safe splits.",
            "Train/validation/test partitions at trace or process-group level.",
            "Provenance, license, acquisition date, checksums, and label definitions.",
        ],
    }
    (output_dir / "audit.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    lines = [
        "# Event-level data gap report",
        "",
        "Status: **blocked before efficacy evaluation**.",
        "",
        "The MLRan detector expects 483 tabular features with schema "
        "`schema-mlran-rfe-483`. Recorded traces contain normalized event "
        "objects and no validated mapping or compatible per-window model.",
        "No probability-only versus evidence-policy efficacy result was run.",
        "",
        "## Trace audits",
        "",
    ]
    for audit in audits:
        lines.extend(
            [
                f"### {audit['file']}",
                f"- Label for reporting only: `{audit['reporting_label']}`",
                f"- Provenance: {audit['label_provenance']}",
                f"- Events: {audit['event_count']}",
                f"- Valid timestamps: {audit['valid_timestamp_count']}/{audit['event_count']}",
                f"- Timestamp order in file: `{audit['timestamps_monotonic_in_file_order']}`",
                f"- Distinct PIDs/PPIDs: `{audit['distinct_pids']}` / `{audit['distinct_ppids']}`",
                f"- Events with paths: `{audit['events_with_path']}`",
                f"- Duplicate events: `{audit['duplicate_event_count']}`",
                f"- Duration seconds: `{audit['trace_duration_seconds']}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Experiment design once compatible data exists",
            "",
            "- Unit: one fixed-length event window grouped by trace/process.",
            "- Labels: source-provided window labels; never used to construct evidence.",
            "- Splits: group-disjoint train/validation/test at trace/process level.",
            "- Evidence: causal timestamp-window features and process context available at decision time.",
            "- Arms: probability-only, temporal-only, process-only, combined.",
            "- Tuning: calibration and thresholds on training/validation only.",
            "- Metrics: classifier metrics separately from action-tier metrics.",
            "",
            "This artifact is an audit and design record, not a detection result.",
        ]
    )
    (output_dir / "data_gap_report.md").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    (output_dir / "experiment_design.md").write_text(
        "# Deferred event-level comparison design\n\n"
        "This design is not executed because no compatible per-window detector "
        "is available.\n\n"
        "## Experimental unit\n"
        "A fixed-duration event window, grouped by source trace and process "
        "lifetime. All windows from one group stay in one partition.\n\n"
        "## Arms\n"
        "1. Probability-only EADL. 2. Temporal evidence policy. 3. Process "
        "evidence policy. 4. Combined temporal/process policy.\n\n"
        "## Evidence and causality\n"
        "Only events at or before the decision timestamp may be used. Missing "
        "timestamps, PIDs, PPIDs, or insufficient observations remain "
        "unavailable/insufficient; they are never converted to zero.\n\n"
        "## Tuning and metrics\n"
        "Fit preprocessing, calibration, and policy thresholds on train and "
        "validation groups only. Keep classifier precision/recall/F1/FPR "
        "separate from containment precision/recall, alert-or-higher recall, "
        "and benign escalation counts.\n\n"
        "## Required compatible data\n"
        "A detector must produce a score for every event window from the same "
        "event feature schema, with independent labels and provenance. The "
        "current MLRan 483-feature detector cannot consume these raw events.\n",
        encoding="utf-8",
    )
    print(f"Saved event-level data audit to {output_dir}")


if __name__ == "__main__":
    main()
