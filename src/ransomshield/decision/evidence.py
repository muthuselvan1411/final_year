"""
Evidence Builder for RansomShield EADL.
Constructs immutable EvidenceRecords tracking source provenance and explicit missingness.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Mapping

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
    model_probability: float | None = None,
    evidence_availability: Mapping[str, str] | None = None,
    event_window: tuple[datetime, datetime] | None = None,
    process_context: Mapping[str, str | int | None] | None = None,
    evidence_summary: tuple[str, ...] = (),
    limitations: tuple[str, ...] = (),
    feature_schema_id: str | None = None,
    feature_values: Mapping[str, float] | None = None,
    supporting_event_ids: tuple[str, ...] = (),
    event_types: tuple[str, ...] = (),
    timestamp_source: str | None = None,
    source_context: str | None = None,
    detector_status: str | None = None,
    decision_basis: str | None = None,
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

    availability = dict(evidence_availability or {})
    availability.setdefault(
        "model_probability", "measured" if final_prob is not None else "unavailable"
    )
    if temporal_consistency is not None:
        sources.append("temporal_consistency_aggregator")
        availability.setdefault("temporal_consistency", "measured")
    else:
        missing.append("temporal_consistency")
        missing.append("process_trace_ordering")
        availability.setdefault("temporal_consistency", "unavailable")
        availability.setdefault("process_trace", "unavailable")

    band = determine_confidence_band(final_prob)

    rec = EvidenceRecord(
        sample_id=prediction.sample_id,
        calibrated_probability=final_prob,
        confidence_band=band,
        temporal_consistency=temporal_consistency,
        observation_count=observation_count,
        evidence_sources=tuple(sources),
        missing_evidence=tuple(missing),
        model_probability=model_probability if model_probability is not None else final_prob,
        evidence_availability=availability,
        event_window=event_window,
        process_context=process_context or {},
        evidence_summary=evidence_summary,
        limitations=limitations,
        feature_schema_id=feature_schema_id,
        feature_values=dict(feature_values or {}),
        supporting_event_ids=supporting_event_ids,
        supporting_event_count=len(supporting_event_ids),
        event_types=event_types,
        timestamp_source=timestamp_source,
        source_context=source_context,
        detector_status=detector_status,
        decision_basis=decision_basis,
    )
    validate_evidence_record(rec)
    return rec
