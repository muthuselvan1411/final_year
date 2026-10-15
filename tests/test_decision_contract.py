"""
Unit tests for EADL decision contracts and invariant validation.
"""

from __future__ import annotations

from ransomshield.decision.contract import (
    ContractValidationError,
    DecisionRecord,
    EvidenceRecord,
    PredictionRecord,
    validate_decision_record,
    validate_evidence_record,
    validate_prediction_record,
)
from tests.compat import assert_raises


def test_valid_prediction_record() -> None:
    rec = PredictionRecord(
        sample_id="SAMPLE-001",
        baseline_label=1,
        raw_score=2.34,
        malicious_probability=0.88,
        model_id="b2-random-forest",
        model_version="1.0.0",
        feature_schema_id="schema-v1",
        inference_ms=1.45,
    )
    validate_prediction_record(rec)


def test_prediction_record_allows_none_probability_for_hard_label_model() -> None:
    rec = PredictionRecord(
        sample_id="SAMPLE-002",
        baseline_label="malicious",
        raw_score=None,
        malicious_probability=None,
        model_id="b0-majority",
        model_version="1.0.0",
        feature_schema_id="schema-v1",
        inference_ms=0.1,
    )
    validate_prediction_record(rec)


def test_prediction_record_rejects_out_of_bound_probability() -> None:
    rec = PredictionRecord(
        sample_id="SAMPLE-003",
        baseline_label=1,
        raw_score=None,
        malicious_probability=1.5,
        model_id="b1",
        model_version="1.0",
        feature_schema_id="schema-v1",
        inference_ms=1.0,
    )
    with assert_raises(ContractValidationError, match=r"must be in \[0\.0, 1\.0\]"):
        validate_prediction_record(rec)


def test_prediction_record_rejects_empty_sample_id() -> None:
    rec = PredictionRecord(
        sample_id="",
        baseline_label=1,
        raw_score=None,
        malicious_probability=0.5,
        model_id="b1",
        model_version="1.0",
        feature_schema_id="schema-v1",
        inference_ms=1.0,
    )
    with assert_raises(ContractValidationError, match="must be non-empty"):
        validate_prediction_record(rec)


def test_valid_evidence_record() -> None:
    rec = EvidenceRecord(
        sample_id="SAMPLE-001",
        calibrated_probability=0.85,
        confidence_band="high",
        temporal_consistency=0.90,
        observation_count=5,
        evidence_sources=("baseline_model", "platt_calibrator", "process_window"),
        missing_evidence=(),
    )
    validate_evidence_record(rec)


def test_evidence_record_with_missing_temporal_evidence() -> None:
    rec = EvidenceRecord(
        sample_id="SAMPLE-002",
        calibrated_probability=0.75,
        confidence_band="medium",
        temporal_consistency=None,
        observation_count=None,
        evidence_sources=("baseline_model",),
        missing_evidence=("temporal_consistency", "process_window"),
    )
    validate_evidence_record(rec)


def test_valid_decision_record() -> None:
    rec = DecisionRecord(
        sample_id="SAMPLE-001",
        action="ALERT",
        severity="suspicious",
        policy_version="eadl-v1",
        rule_ids=("rule-01",),
        explanation="ALERT because calibrated probability 0.85 exceeded threshold 0.50.",
        decision_ms=0.22,
    )
    validate_decision_record(rec)


def test_decision_record_rejects_invalid_action() -> None:
    rec = DecisionRecord(
        sample_id="SAMPLE-001",
        action="EXECUTE_CONTAINMENT",  # type: ignore[arg-type] # Prohibited action
        severity="high_risk",
        policy_version="eadl-v1",
        rule_ids=("rule-01",),
        explanation="Prohibited action test",
        decision_ms=0.1,
    )
    with assert_raises(ContractValidationError, match="must be one of"):
        validate_decision_record(rec)
