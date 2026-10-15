"""
Baseline Adapter for RansomShield.
Normalizes arbitrary scikit-learn compatible detector outputs into immutable PredictionRecord objects.
"""

from __future__ import annotations

import time
from typing import Any, List, Optional

import numpy as np

from ransomshield.decision.contract import PredictionRecord, validate_prediction_record


class BaselineAdapter:
    """
    Adapter normalizing a detector's raw output into PredictionRecords.
    Preserves raw probabilities, measures per-record latency, and enforces contract invariants.
    """

    def __init__(
        self,
        model: Any,
        model_id: str,
        model_version: str = "1.0.0",
        feature_schema_id: str = "schema-mlran-rfe-483",
    ):
        self.model = model
        self.model_id = model_id
        self.model_version = model_version
        self.feature_schema_id = feature_schema_id

    def predict_records(
        self,
        X: np.ndarray,
        sample_ids: List[str | int],
    ) -> List[PredictionRecord]:
        if len(X) != len(sample_ids):
            raise ValueError(f"Mismatch between feature rows ({len(X)}) and sample_ids ({len(sample_ids)})")

        has_proba = hasattr(self.model, "predict_proba")
        t0 = time.perf_counter()
        raw_preds = self.model.predict(X)
        if has_proba:
            raw_probas = self.model.predict_proba(X)
        else:
            raw_probas = None
        total_time_ms = (time.perf_counter() - t0) * 1000.0
        avg_latency_ms = total_time_ms / max(len(X), 1)

        records: List[PredictionRecord] = []
        for i, sid in enumerate(sample_ids):
            pred_lbl = int(raw_preds[i]) if isinstance(raw_preds[i], (np.integer, int)) else raw_preds[i]
            mal_prob: Optional[float] = None
            raw_score: Optional[float] = None

            if raw_probas is not None:
                # Malicious class probability (class index 1 if binary)
                if raw_probas.shape[1] >= 2:
                    mal_prob = float(raw_probas[i, 1])
                    raw_score = mal_prob
                else:
                    mal_prob = float(raw_probas[i, 0])
                    raw_score = mal_prob

            rec = PredictionRecord(
                sample_id=str(sid),
                baseline_label=pred_lbl,
                raw_score=raw_score,
                malicious_probability=mal_prob,
                model_id=self.model_id,
                model_version=self.model_version,
                feature_schema_id=self.feature_schema_id,
                inference_ms=avg_latency_ms,
            )
            validate_prediction_record(rec)
            records.append(rec)

        return records
