from ransomshield.decision.contract import PredictionRecord
from ransomshield.decision.evidence import build_evidence_record
from ransomshield.decision.policy import OperationalDecisionPolicy


def test_enhanced_policy_requires_measured_temporal_evidence_when_configured() -> None:
    prediction = PredictionRecord(
        sample_id="SAMPLE-ENHANCED",
        baseline_label=1,
        raw_score=0.95,
        malicious_probability=0.95,
        model_id="test",
        model_version="1",
        feature_schema_id="schema",
        inference_ms=0.1,
    )
    evidence = build_evidence_record(prediction, calibrated_prob=0.95)
    policy = OperationalDecisionPolicy(
        mode="enhanced_evidence",
        require_temporal_for_containment=True,
    )
    decision = policy.evaluate_decision(prediction, evidence)
    assert decision.action == "ALERT"


def test_enhanced_policy_uses_measured_temporal_evidence() -> None:
    prediction = PredictionRecord(
        sample_id="SAMPLE-ENHANCED-2",
        baseline_label=1,
        raw_score=0.95,
        malicious_probability=0.95,
        model_id="test",
        model_version="1",
        feature_schema_id="schema",
        inference_ms=0.1,
    )
    evidence = build_evidence_record(
        prediction,
        calibrated_prob=0.95,
        temporal_consistency=0.9,
        observation_count=5,
    )
    policy = OperationalDecisionPolicy(
        mode="enhanced_evidence",
        require_temporal_for_containment=True,
    )
    assert policy.evaluate_decision(prediction, evidence).action == "CONTAINMENT_RECOMMENDED"
