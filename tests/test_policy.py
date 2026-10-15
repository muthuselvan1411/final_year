"""
Unit tests for EADL operational decision policy and deterministic explanations.
"""

from __future__ import annotations

from ransomshield.decision.contract import PredictionRecord
from ransomshield.decision.evidence import build_evidence_record
from ransomshield.decision.policy import OperationalDecisionPolicy


def create_mock_prediction(sample_id: str, prob: float | None) -> PredictionRecord:
    return PredictionRecord(
        sample_id=sample_id,
        baseline_label=1 if (prob is not None and prob >= 0.5) else 0,
        raw_score=prob,
        malicious_probability=prob,
        model_id="b4-random-forest",
        model_version="1.0.0",
        feature_schema_id="schema-rfe-483",
        inference_ms=1.2,
    )


def test_policy_high_confidence_triggers_containment_recommended() -> None:
    pred = create_mock_prediction("SAMPLE-01", 0.95)
    evidence = build_evidence_record(pred, calibrated_prob=0.95)
    policy = OperationalDecisionPolicy(tau_alert=0.50, tau_contain=0.85)

    decision = policy.evaluate_decision(pred, evidence)
    assert decision.action == "CONTAINMENT_RECOMMENDED"
    assert decision.severity == "high_risk"
    assert "0.85" in decision.explanation
    assert "Advisory recommendation only" in decision.explanation


def test_policy_intermediate_confidence_triggers_alert() -> None:
    pred = create_mock_prediction("SAMPLE-02", 0.65)
    evidence = build_evidence_record(pred, calibrated_prob=0.65)
    policy = OperationalDecisionPolicy(tau_alert=0.50, tau_contain=0.85)

    decision = policy.evaluate_decision(pred, evidence)
    assert decision.action == "ALERT"
    assert decision.severity == "suspicious"
    assert "0.50" in decision.explanation


def test_policy_low_confidence_triggers_no_alert() -> None:
    pred = create_mock_prediction("SAMPLE-03", 0.10)
    evidence = build_evidence_record(pred, calibrated_prob=0.10)
    policy = OperationalDecisionPolicy(tau_alert=0.50, tau_contain=0.85)

    decision = policy.evaluate_decision(pred, evidence)
    assert decision.action == "NO_ALERT"
    assert decision.severity == "benign"


def test_policy_missing_probability_triggers_abstain() -> None:
    pred = create_mock_prediction("SAMPLE-04", None)
    evidence = build_evidence_record(pred, calibrated_prob=None)
    policy = OperationalDecisionPolicy(tau_alert=0.50, tau_contain=0.85)

    decision = policy.evaluate_decision(pred, evidence)
    assert decision.action == "ABSTAIN"
    assert decision.severity == "unassigned"
    assert "ABSTAIN" in decision.explanation
