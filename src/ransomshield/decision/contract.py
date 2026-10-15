"""
RansomShield Decision Contract Interfaces and Validators.

Implements the typed contracts defined in docs/decision_contract.md and 06-decision-policy-contract.md:
- PredictionRecord: normalized baseline detector output.
- EvidenceRecord: contextual evidence (calibration, temporal consistency, sources).
- DecisionRecord: deterministic, auditable operational action and explanation.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal, Tuple, Union

# Supported operational actions
Action = Literal[
    "NO_ALERT",
    "MONITOR",
    "ALERT",
    "CONTAINMENT_RECOMMENDED",
    # Mapped synonyms from 06-decision-policy-contract.md:
    "ALLOW_LOG",
    "ALERT_REVIEW",
    "CONTAIN_CANDIDATE",
    "ABSTAIN",
]

Severity = Literal["benign", "suspicious", "high_risk", "unassigned"]


class ContractValidationError(ValueError):
    """Raised when record contract invariants are violated."""
    pass


@dataclass(frozen=True)
class PredictionRecord:
    """Normalized baseline detector prediction record."""
    sample_id: str
    baseline_label: int | str
    raw_score: float | None
    malicious_probability: float | None
    model_id: str
    model_version: str
    feature_schema_id: str
    inference_ms: float


@dataclass(frozen=True)
class EvidenceRecord:
    """Contextual evidence record."""
    sample_id: str
    calibrated_probability: float | None
    confidence_band: str | None
    temporal_consistency: float | None
    observation_count: int | None
    evidence_sources: Tuple[str, ...]
    missing_evidence: Tuple[str, ...]


@dataclass(frozen=True)
class DecisionRecord:
    """Auditable operational decision record."""
    sample_id: str
    action: Action
    severity: Severity
    policy_version: str
    rule_ids: Tuple[str, ...]
    explanation: str
    decision_ms: float


def validate_prediction_record(record: PredictionRecord) -> None:
    """Validates PredictionRecord invariants."""
    if not record.sample_id or not str(record.sample_id).strip():
        raise ContractValidationError("PredictionRecord 'sample_id' must be non-empty.")

    if not record.model_id or not str(record.model_id).strip():
        raise ContractValidationError("PredictionRecord 'model_id' must be specified.")

    if not record.model_version or not str(record.model_version).strip():
        raise ContractValidationError("PredictionRecord 'model_version' must be specified.")

    if not record.feature_schema_id or not str(record.feature_schema_id).strip():
        raise ContractValidationError("PredictionRecord 'feature_schema_id' must be specified.")

    if record.inference_ms < 0.0 or not math.isfinite(record.inference_ms):
        raise ContractValidationError(
            f"PredictionRecord 'inference_ms' must be non-negative and finite, got {record.inference_ms}"
        )

    if record.raw_score is not None:
        if not math.isfinite(record.raw_score):
            raise ContractValidationError(
                f"PredictionRecord 'raw_score' must be finite when provided, got {record.raw_score}"
            )

    if record.malicious_probability is not None:
        if not math.isfinite(record.malicious_probability):
            raise ContractValidationError(
                f"PredictionRecord 'malicious_probability' must be finite, got {record.malicious_probability}"
            )
        if not (0.0 <= record.malicious_probability <= 1.0):
            raise ContractValidationError(
                f"PredictionRecord 'malicious_probability' must be in [0.0, 1.0], got {record.malicious_probability}"
            )


def validate_evidence_record(record: EvidenceRecord) -> None:
    """Validates EvidenceRecord invariants."""
    if not record.sample_id or not str(record.sample_id).strip():
        raise ContractValidationError("EvidenceRecord 'sample_id' must be non-empty.")

    if record.calibrated_probability is not None:
        if not math.isfinite(record.calibrated_probability):
            raise ContractValidationError(
                f"EvidenceRecord 'calibrated_probability' must be finite, got {record.calibrated_probability}"
            )
        if not (0.0 <= record.calibrated_probability <= 1.0):
            raise ContractValidationError(
                f"EvidenceRecord 'calibrated_probability' must be in [0.0, 1.0], got {record.calibrated_probability}"
            )

    if record.temporal_consistency is not None:
        if not math.isfinite(record.temporal_consistency):
            raise ContractValidationError(
                f"EvidenceRecord 'temporal_consistency' must be finite, got {record.temporal_consistency}"
            )
        if not (0.0 <= record.temporal_consistency <= 1.0):
            raise ContractValidationError(
                f"EvidenceRecord 'temporal_consistency' must be in [0.0, 1.0], got {record.temporal_consistency}"
            )

    if record.observation_count is not None:
        if record.observation_count < 0:
            raise ContractValidationError(
                f"EvidenceRecord 'observation_count' cannot be negative, got {record.observation_count}"
            )


def validate_decision_record(record: DecisionRecord) -> None:
    """Validates DecisionRecord invariants."""
    if not record.sample_id or not str(record.sample_id).strip():
        raise ContractValidationError("DecisionRecord 'sample_id' must be non-empty.")

    valid_actions = {
        "NO_ALERT",
        "MONITOR",
        "ALERT",
        "CONTAINMENT_RECOMMENDED",
        "ALLOW_LOG",
        "ALERT_REVIEW",
        "CONTAIN_CANDIDATE",
        "ABSTAIN",
    }
    if record.action not in valid_actions:
        raise ContractValidationError(
            f"DecisionRecord 'action' must be one of {sorted(valid_actions)}, got '{record.action}'"
        )

    valid_severities = {"benign", "suspicious", "high_risk", "unassigned"}
    if record.severity not in valid_severities:
        raise ContractValidationError(
            f"DecisionRecord 'severity' must be one of {sorted(valid_severities)}, got '{record.severity}'"
        )

    if not record.policy_version or not str(record.policy_version).strip():
        raise ContractValidationError("DecisionRecord 'policy_version' must be specified.")

    if not record.explanation or not str(record.explanation).strip():
        raise ContractValidationError("DecisionRecord 'explanation' must be non-empty.")

    if record.decision_ms < 0.0 or not math.isfinite(record.decision_ms):
        raise ContractValidationError(
            f"DecisionRecord 'decision_ms' must be non-negative and finite, got {record.decision_ms}"
        )
