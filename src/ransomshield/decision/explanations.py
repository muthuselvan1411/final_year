"""
Deterministic Explanation Generator for RansomShield Decisions.
Constructs audit-grade natural language explanations from structured evidence fields.
"""

from __future__ import annotations

from typing import Tuple

from ransomshield.decision.contract import Action, EvidenceRecord, PredictionRecord


def generate_decision_explanation(
    action: Action,
    prediction: PredictionRecord,
    evidence: EvidenceRecord,
    tau_alert: float,
    tau_contain: float,
    policy_version: str,
    rule_ids: Tuple[str, ...],
) -> str:
    """
    Renders deterministic explanation text from strictly verified inputs.
    """
    prob = evidence.calibrated_probability
    prob_str = f"{prob:.4f}" if prob is not None else "N/A"
    rule_str = ",".join(rule_ids)

    missing_str = (
        f" [Unavailable evidence: {', '.join(evidence.missing_evidence)}]"
        if evidence.missing_evidence
        else ""
    )
    summary_str = (
        f" Evidence: {'; '.join(evidence.evidence_summary)}."
        if evidence.evidence_summary
        else ""
    )

    if action == "ABSTAIN":
        return f"ABSTAIN: Data quality or schema check failed for sample {prediction.sample_id}. Policy: {policy_version}/{rule_str}."

    if action in ["CONTAINMENT_RECOMMENDED", "CONTAIN_CANDIDATE"]:
        return (
            f"{action}: High-confidence malicious probability {prob_str} exceeded containment threshold "
            f"{tau_contain:.2f} (band: {evidence.confidence_band}). Advisory recommendation only; no automated endpoint disruption."
            f"{missing_str}{summary_str} Policy: {policy_version}/{rule_str}."
        )

    if action in ["ALERT", "ALERT_REVIEW"]:
        return (
            f"{action}: Malicious probability {prob_str} exceeded alert threshold {tau_alert:.2f} "
            f"but remained below containment threshold {tau_contain:.2f} (band: {evidence.confidence_band})."
            f"{missing_str}{summary_str} Policy: {policy_version}/{rule_str}."
        )

    if action in ["MONITOR", "REVIEW"]:
        return (
            f"{action}: Ambiguous score or low confidence (probability: {prob_str}, band: {evidence.confidence_band})."
            f"{missing_str}{summary_str} Policy: {policy_version}/{rule_str}."
        )

    # NO_ALERT / ALLOW_LOG
    return (
        f"{action}: Malicious probability {prob_str} is below alert threshold {tau_alert:.2f} (band: {evidence.confidence_band})."
        f"{missing_str}{summary_str} Policy: {policy_version}/{rule_str}."
    )
