from ransomshield.decision.contract import PredictionRecord
from ransomshield.decision.evidence import build_evidence_record
from ransomshield.decision.policy import OperationalDecisionPolicy


def _prediction(probability: float = 0.95) -> PredictionRecord:
    return PredictionRecord(
        sample_id="signal-sensitivity",
        baseline_label=1,
        raw_score=probability,
        malicious_probability=probability,
        model_id="test",
        model_version="1",
        feature_schema_id="schema",
        inference_ms=0.0,
    )


def test_temporal_signal_changes_containment_decision() -> None:
    prediction = _prediction()
    policy = OperationalDecisionPolicy(
        mode="enhanced_evidence",
        require_temporal_for_containment=True,
        min_temporal_consistency=0.5,
    )
    unavailable = build_evidence_record(prediction, calibrated_prob=0.95)
    measured = build_evidence_record(
        prediction, calibrated_prob=0.95, temporal_consistency=0.9, observation_count=4
    )
    assert policy.evaluate_decision(prediction, unavailable).action == "ALERT"
    assert (
        policy.evaluate_decision(prediction, measured).action
        == "CONTAINMENT_RECOMMENDED"
    )


def test_process_signal_changes_containment_decision() -> None:
    prediction = _prediction()
    policy = OperationalDecisionPolicy(
        mode="enhanced_evidence",
        require_process_for_containment=True,
    )
    unavailable = build_evidence_record(prediction, calibrated_prob=0.95)
    measured = build_evidence_record(
        prediction,
        calibrated_prob=0.95,
        evidence_availability={"process_trace": "measured"},
        process_context={"pid": 10, "ppid": 1, "process": "worker"},
    )
    assert policy.evaluate_decision(prediction, unavailable).action == "ALERT"
    assert (
        policy.evaluate_decision(prediction, measured).action
        == "CONTAINMENT_RECOMMENDED"
    )
