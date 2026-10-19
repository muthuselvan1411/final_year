#!/usr/bin/env python3
"""Run a safe recorded telemetry replay through both EADL policy modes.

The repository's event traces come from controlled workloads. This command is
for end-to-end functional validation only; it is not an MLRan benchmark and
does not execute workloads or enable containment.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ransomshield.decision.contract import PredictionRecord
from ransomshield.decision.evidence import build_evidence_record
from ransomshield.decision.policy import OperationalDecisionPolicy
from ransomshield.evaluation.metrics import compute_action_tier_metrics
from ransomshield.telemetry.process import build_process_context
from ransomshield.telemetry.temporal import extract_temporal_features
from collector.normalizer import EventNormalizer


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise FileNotFoundError(f"Recorded trace not found: {path}")
    events = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_number}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"Expected an event object at {path}:{line_number}")
            events.append(value)
    if not events:
        raise ValueError(f"Recorded trace is empty: {path}")
    return events


def load_trace_windows(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    with path.open(encoding="utf-8") as handle:
        result = json.load(handle)
    assessment = result["max_threat_assessment"]
    windows = result["window_assessments"]
    return assessment, windows


def run_trace(
    trace_path: Path,
    result_path: Path,
    label: int,
    output_rows: list[dict[str, Any]],
) -> None:
    events = load_jsonl(trace_path)
    events = [EventNormalizer(compute_entropy=False).normalize(event) for event in events]
    assessment, windows = load_trace_windows(result_path)
    probability = float(assessment["confidence"])
    policy_probability = OperationalDecisionPolicy(
        policy_version="eadl-replay-probability-v1",
        mode="probability_only",
    )
    policy_enhanced = OperationalDecisionPolicy(
        policy_version="eadl-replay-enhanced-v1",
        mode="enhanced_evidence",
        require_temporal_for_containment=True,
    )
    policy_temporal_only = policy_enhanced
    policy_process_only = OperationalDecisionPolicy(
        policy_version="eadl-replay-process-only-v1",
        mode="enhanced_evidence",
        require_process_for_containment=True,
    )
    policy_temporal_process = OperationalDecisionPolicy(
        policy_version="eadl-replay-temporal-process-v1",
        mode="enhanced_evidence",
        require_temporal_for_containment=True,
        require_process_for_containment=True,
    )

    for index, window in enumerate(windows):
        start = float(window["window_info"]["start"])
        end = float(window["window_info"]["start"]) + float(
            window["window_info"]["duration"]
        )
        window_events = [
            event
            for event in events
            if start <= float(event.get("timestamp", -1)) <= end
        ]
        if not window_events:
            raise ValueError(f"No events found for recorded window {window['window_info']}")
        decision_time = max(float(event["timestamp"]) for event in window_events)
        temporal = extract_temporal_features(
            window_events, window_seconds=float(window["window_info"]["duration"]),
            decision_time=decision_time,
        )
        process = build_process_context(window_events, decision_time=decision_time)
        prediction = PredictionRecord(
            sample_id=f"{trace_path.stem}-window-{index}",
            baseline_label=int(probability >= 0.5),
            raw_score=probability,
            malicious_probability=probability,
            model_id="recorded_behavioral_detector",
            model_version=str(assessment.get("model_version", "unknown")),
            feature_schema_id="normalized-event-v1",
            inference_ms=0.0,
        )
        evidence = build_evidence_record(
            prediction,
            calibrated_prob=probability,
            temporal_consistency=temporal.temporal_consistency,
            observation_count=temporal.observation_count,
            evidence_availability={
                "model_probability": "measured",
                "temporal_consistency": (
                    "measured" if temporal.temporal_consistency is not None else "insufficient"
                ),
                "process_trace": (
                    "measured"
                    if (
                        process.process_id is not None
                        and process.parent_process_id is not None
                        and process.ordered
                        and not process.unavailable_fields
                    )
                    else "insufficient"
                ),
            },
            process_context={
                "pid": process.process_id,
                "ppid": process.parent_process_id,
                "process": process.process_name,
            },
            evidence_summary=(
                f"{temporal.observation_count} timestamped events in the causal window",
                f"{temporal.distinct_files} distinct paths observed",
            ),
            limitations=process.limitations,
        )
        probability_decision = policy_probability.evaluate_decision(prediction, evidence)
        enhanced_decision = policy_temporal_only.evaluate_decision(prediction, evidence)
        process_decision = policy_process_only.evaluate_decision(prediction, evidence)
        temporal_process_decision = policy_temporal_process.evaluate_decision(
            prediction, evidence
        )
        output_rows.append(
            {
                "sample_id": prediction.sample_id,
                "true_label_for_reporting_only": label,
                "trace": trace_path.name,
                "window_start": start,
                "window_end": end,
                "observation_count": temporal.observation_count,
                "pid": process.process_id,
                "ppid": process.parent_process_id,
                "probability": probability,
                "probability_source": str(result_path.name)
                + ":max_threat_assessment.confidence",
                "temporal_consistency": temporal.temporal_consistency,
                "temporal_file_modifications": temporal.file_modifications,
                "temporal_rename_count": temporal.rename_count,
                "temporal_delete_count": temporal.delete_count,
                "temporal_distinct_files": temporal.distinct_files,
                "temporal_repeated_files": temporal.repeated_files,
                "temporal_event_rate": temporal.event_rate,
                "temporal_burst_ratio": temporal.burst_ratio,
                "temporal_availability": evidence.evidence_availability.get(
                    "temporal_consistency"
                ),
                "process_availability": evidence.evidence_availability.get(
                    "process_trace"
                ),
                "process_ordered": process.ordered,
                "process_unavailable_fields": "|".join(process.unavailable_fields),
                "process_limitations": "|".join(process.limitations),
                "evidence_sources": "|".join(evidence.evidence_sources),
                "missing_evidence": "|".join(evidence.missing_evidence),
                "probability_only_policy": policy_probability.policy_version,
                "temporal_only_policy": policy_temporal_only.policy_version,
                "process_only_policy": policy_process_only.policy_version,
                "temporal_process_policy": policy_temporal_process.policy_version,
                "probability_only_action": probability_decision.action,
                "enhanced_action": enhanced_decision.action,
                "process_only_action": process_decision.action,
                "temporal_process_action": temporal_process_decision.action,
                "probability_only_explanation": probability_decision.explanation,
                "enhanced_explanation": enhanced_decision.explanation,
                "process_only_explanation": process_decision.explanation,
                "temporal_process_explanation": temporal_process_decision.explanation,
                "probability_only_rule_ids": "|".join(
                    probability_decision.rule_ids
                ),
                "temporal_only_rule_ids": "|".join(enhanced_decision.rule_ids),
                "process_only_rule_ids": "|".join(process_decision.rule_ids),
                "temporal_process_rule_ids": "|".join(
                    temporal_process_decision.rule_ids
                ),
            }
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir", default="results/recorded_event_replay_diagnostics_v2"
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    output_dir = root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    run_trace(
        root / "datasets/benign_events.jsonl",
        root / "datasets/benign_results.json",
        0,
        rows,
    )
    run_trace(
        root / "datasets/ransomware_events.jsonl",
        root / "datasets/ransomware_results.json",
        1,
        rows,
    )
    frame = pd.DataFrame(rows)
    frame.to_csv(output_dir / "decisions.csv", index=False)
    metrics = {
        "result_category": "functional_recorded_replay_only",
        "not_detection_performance": True,
        "reason": "Controlled benign and synthetic-ransomware workload traces; no independent real-world benchmark.",
        "probability_source": "companion result max_threat_assessment.confidence; not recalculated from each event",
        "sample_count": len(frame),
        "diagnostic_summary": {
            "probability_range": [
                float(frame["probability"].min()),
                float(frame["probability"].max()),
            ],
            "temporal_consistency_by_trace": frame.groupby("trace")[
                "temporal_consistency"
            ].apply(list).to_dict(),
            "process_availability_by_trace": frame.groupby("trace")[
                "process_availability"
            ].apply(list).to_dict(),
            "action_columns": {
                "probability_only": "probability_only_action",
                "temporal_only": "enhanced_action",
                "process_only": "process_only_action",
                "temporal_and_process": "temporal_process_action",
            },
        },
        "probability_only": compute_action_tier_metrics(
            frame["true_label_for_reporting_only"].to_numpy(),
            frame["probability_only_action"].tolist(),
        ),
        "enhanced_evidence": compute_action_tier_metrics(
            frame["true_label_for_reporting_only"].to_numpy(),
            frame["enhanced_action"].tolist(),
        ),
        "temporal_only": compute_action_tier_metrics(
            frame["true_label_for_reporting_only"].to_numpy(),
            frame["enhanced_action"].tolist(),
        ),
        "process_only": compute_action_tier_metrics(
            frame["true_label_for_reporting_only"].to_numpy(),
            frame["process_only_action"].tolist(),
        ),
        "temporal_and_process": compute_action_tier_metrics(
            frame["true_label_for_reporting_only"].to_numpy(),
            frame["temporal_process_action"].tolist(),
        ),
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    (output_dir / "config.json").write_text(
        json.dumps(
            {
                "traces": ["datasets/benign_events.jsonl", "datasets/ransomware_events.jsonl"],
                "policies": [
                    "probability_only",
                    "temporal_only",
                    "process_only",
                    "temporal_and_process",
                ],
                "ablation_modes": [
                    "probability_only",
                    "temporal_only",
                    "process_only",
                    "temporal_and_process",
                ],
                "containment_is_advisory_only": True,
                "labels_used_only_for_reporting": True,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (output_dir / "experiment_log.md").write_text(
        "# Recorded event replay diagnostics\n\n"
        "- Result category: `functional_recorded_replay_only`\n"
        "- Dataset: controlled benign and synthetic-ransomware JSONL traces\n"
        "- Eligible windows: 3\n"
        "- Policies: probability-only, temporal-only, process-only, temporal-plus-process\n"
        "- Diagnostic fields: raw evidence features, availability, policy versions, rule IDs, and explanations\n"
        "- Labels: used only for reporting metrics, never evidence construction\n"
        "- Future-event leakage: prevented with decision-time cutoffs\n"
        "- Automatic containment: disabled; all containment outputs are advisory\n"
        "- Command: `python scripts/run_recorded_event_replay.py`\n\n"
        "These outputs are functional pipeline checks, not independent "
        "real-world detection-performance results.\n",
        encoding="utf-8",
    )
    print(f"Saved functional replay artifacts to {output_dir}")


if __name__ == "__main__":
    main()
