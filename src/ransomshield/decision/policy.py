"""
Evidence-Aware Operational Decision Policy Engine for RansomShield.
Replaces brittle heuristic rules with statistical calibrated threshold tiers.
"""

from __future__ import annotations

import time
from typing import List, Tuple

from ransomshield.config import PolicyConfig, PolicyThresholds
from ransomshield.decision.contract import (
    Action,
    DecisionRecord,
    EvidenceRecord,
    PredictionRecord,
    Severity,
    validate_decision_record,
)
from ransomshield.decision.explanations import generate_decision_explanation


class OperationalDecisionPolicy:
    """
    Transparent, versioned operational policy engine.
    Maps calibrated probabilities to tiered actions:
    - ALLOW_LOG / NO_ALERT
    - ALERT_REVIEW / ALERT
    - CONTAIN_CANDIDATE / CONTAINMENT_RECOMMENDED (strictly advisory)
    - ABSTAIN (on data quality failure)
    """

    def __init__(
        self,
        policy_version: str = "eadl-policy-v1",
        tau_alert: float = 0.50,
        tau_contain: float = 0.85,
        min_confidence: float = 0.50,
    ):
        if not (0.0 <= tau_alert <= tau_contain <= 1.0):
            raise ValueError(f"Invalid thresholds: tau_alert ({tau_alert}) must be <= tau_contain ({tau_contain}) within [0, 1]")
        self.policy_version = policy_version
        self.tau_alert = tau_alert
        self.tau_contain = tau_contain
        self.min_confidence = min_confidence

    def evaluate_decision(
        self,
        prediction: PredictionRecord,
        evidence: EvidenceRecord,
    ) -> DecisionRecord:
        t0 = time.perf_counter()
        prob = evidence.calibrated_probability

        # 1. Check data quality / missing score
        if prob is None:
            action: Action = "ABSTAIN"
            severity: Severity = "unassigned"
            rule_ids = ("rule-quality-fail-abstain",)
        elif prob >= self.tau_contain:
            action = "CONTAINMENT_RECOMMENDED"
            severity = "high_risk"
            rule_ids = ("rule-tier-contain",)
        elif prob >= self.tau_alert:
            action = "ALERT"
            severity = "suspicious"
            rule_ids = ("rule-tier-alert",)
        elif prob >= (self.tau_alert - 0.15) and prob < self.tau_alert:
            # Low ambiguous range: Recommend monitoring
            action = "MONITOR"
            severity = "suspicious"
            rule_ids = ("rule-tier-monitor",)
        else:
            action = "NO_ALERT"
            severity = "benign"
            rule_ids = ("rule-tier-allow",)

        decision_ms = (time.perf_counter() - t0) * 1000.0

        explanation = generate_decision_explanation(
            action=action,
            prediction=prediction,
            evidence=evidence,
            tau_alert=self.tau_alert,
            tau_contain=self.tau_contain,
            policy_version=self.policy_version,
            rule_ids=rule_ids,
        )

        rec = DecisionRecord(
            sample_id=prediction.sample_id,
            action=action,
            severity=severity,
            policy_version=self.policy_version,
            rule_ids=rule_ids,
            explanation=explanation,
            decision_ms=decision_ms,
        )
        validate_decision_record(rec)
        return rec
