"""
Evidence Builder for RansomShield EADL.
Constructs immutable EvidenceRecords tracking source provenance and explicit missingness.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from ransomshield.decision.contract import EvidenceRecord, PredictionRecord, validate_evidence_record


def determine_confidence_band(prob: float | None) -> str | None:
    if prob is None:
        return None
    if prob < 0.30:
        return "very_low"
    elif prob < 0.50:
        return "low"
    elif prob < 0.75:
        return "medium"
    elif prob < 0.90:
        return "high"
    else:
        return "very_high"


def build_evidence_record(
    prediction: PredictionRecord,
    calibrated_prob: float | None = None,
    calibrator_id: str | None = None,
    temporal_consistency: float | None = None,
    observation_count: int | None = None,
) -> EvidenceRecord:
    """
    Builds a validated EvidenceRecord.
    Explicitly tracks available evidence vs missing modalities.
    """
    sources: List[str] = [prediction.model_id]
    missing: List[str] = []

    final_prob = calibrated_prob if calibrated_prob is not None else prediction.malicious_probability

    if calibrated_prob is not None:
        sources.append(calibrator_id or "calibrator_v1")
    else:
        missing.append("probability_calibration")

    if temporal_consistency is not None:
        sources.append("temporal_consistency_aggregator")
    else:
        missing.append("temporal_consistency")
        missing.append("process_trace_ordering")

    band = determine_confidence_band(final_prob)

    rec = EvidenceRecord(
        sample_id=prediction.sample_id,
        calibrated_probability=final_prob,
        confidence_band=band,
        temporal_consistency=temporal_consistency,
        observation_count=observation_count,
        evidence_sources=tuple(sources),
        missing_evidence=tuple(missing),
    )
    validate_evidence_record(rec)
    return rec
