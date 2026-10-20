"""Connect normalized events to features, evidence, policy, and storage.

The pipeline is deliberately advisory. When no validated event-window model is
configured, it creates an explicit unavailable prediction and the policy
returns ``ABSTAIN`` rather than treating missing model output as benign.
"""

from __future__ import annotations

import time
from collections import deque
from datetime import datetime
from dataclasses import asdict
from math import isfinite
from typing import Any, Protocol

from ransomshield.decision.contract import (
    EvidenceRecord,
    PredictionRecord,
    DecisionRecord,
    validate_prediction_record,
)
from ransomshield.decision.evidence import build_evidence_record
from ransomshield.decision.policy import OperationalDecisionPolicy
from ransomshield.storage import IncidentStore
from ransomshield.telemetry.event_features import EventWindowFeatures, extract_event_window_features
from ransomshield.telemetry.guardfs_features import extract_guardfs_features
from ransomshield.telemetry.process import build_process_context
from ransomshield.telemetry.temporal import extract_temporal_features


class EventWindowDetector(Protocol):
    model_id: str
    model_version: str
    feature_schema_id: str

    def predict(
        self, features: EventWindowFeatures, events: list[dict[str, Any]]
    ) -> PredictionRecord:
        ...


class UnavailableDetector:
    """Detector used until a validated live-compatible model is supplied."""

    model_id = "unavailable-event-detector"
    model_version = "none"
    feature_schema_id = "schema-event-window-v1"

    def predict(
        self, features: EventWindowFeatures, events: list[dict[str, Any]]
    ) -> PredictionRecord:
        return PredictionRecord(
            sample_id="live-window",
            baseline_label="unavailable",
            raw_score=None,
            malicious_probability=None,
            model_id=self.model_id,
            model_version=self.model_version,
            feature_schema_id=features.schema_id,
            inference_ms=0.0,
        )


class LiveDecisionPipeline:
    """Process one normalized event at a time and emit an auditable decision."""

    def __init__(
        self,
        *,
        detector: EventWindowDetector | None = None,
        policy: OperationalDecisionPolicy | None = None,
        store: IncidentStore | None = None,
        window_seconds: float = 10.0,
        max_events: int = 4096,
    ):
        if max_events <= 0:
            raise ValueError("max_events must be greater than zero")
        self.detector = detector or UnavailableDetector()
        self.policy = policy or OperationalDecisionPolicy()
        self.store = store
        self.window_seconds = window_seconds
        self.events: deque[dict[str, Any]] = deque(maxlen=max_events)
        self._records: deque[tuple[int, tuple[Any, ...], dict[str, Any]]] = deque(
            maxlen=max_events
        )
        self._events_by_identity: dict[
            tuple[Any, ...], deque[tuple[int, dict[str, Any]]]
        ] = {}
        self._pid_signatures: dict[int, tuple[tuple[Any, ...], int]] = {}
        self._sequence = 0

    def process_event(self, event: dict[str, Any]) -> DecisionRecord:
        normalized_event = dict(event)
        identity, identity_limitations = self._identity(normalized_event)
        self._append_event(identity, normalized_event)
        events = self._causal_events(identity, self._timestamp(normalized_event))
        decision_time = self._timestamp(normalized_event)
        features = extract_event_window_features(
            events,
            window_seconds=self.window_seconds,
            decision_time=decision_time,
        )
        temporal = extract_temporal_features(
            events,
            window_seconds=self.window_seconds,
            decision_time=decision_time,
        )
        prediction = self.detector.predict(features, events)
        validate_prediction_record(prediction)
        prediction = self._with_sample_id(prediction, event)
        process = build_process_context(events, decision_time=decision_time)
        evidence = build_evidence_record(
            prediction,
            temporal_consistency=(
                features.values["temporal_consistency"]
                if features.available["temporal_consistency"]
                else None
            ),
            observation_count=int(features.values["observation_count"]),
            process_context={
                "process_id": process.process_id,
                "parent_process_id": process.parent_process_id,
                "process_name": process.process_name,
                "process_identity": self._identity_label(identity),
            },
            evidence_availability={
                "event_window_features": "measured" if features.available["observation_count"] else "unavailable",
                "guardfs_style_features": "measured",
                "process_trace": "measured" if process.event_count else "unavailable",
            },
            evidence_summary=(
                f"event_window_schema={features.schema_id}",
                f"guardfs_style_features={extract_guardfs_features(events, decision_time=decision_time)}",
            ),
            limitations=tuple(
                dict.fromkeys(
                    features.limitations + process.limitations + identity_limitations
                )
            ),
            event_window=self._event_window(temporal.window_start, temporal.window_end),
        )
        decision = self.policy.evaluate_decision(prediction, evidence)
        if self.store is not None:
            self.store.append(
                self._record(
                    normalized_event, features, prediction, evidence, decision
                )
            )
        return decision

    def _append_event(
        self, identity: tuple[Any, ...], event: dict[str, Any]
    ) -> None:
        sequence = self._sequence
        self._sequence += 1
        self.events.append(event)
        if len(self._records) == self._records.maxlen:
            old_sequence, old_identity, _ = self._records[0]
            old_bucket = self._events_by_identity[old_identity]
            if old_bucket and old_bucket[0][0] == old_sequence:
                old_bucket.popleft()
            if not old_bucket:
                del self._events_by_identity[old_identity]
        self._records.append((sequence, identity, event))
        self._events_by_identity.setdefault(identity, deque()).append((sequence, event))

    def _causal_events(
        self, identity: tuple[Any, ...], decision_time: float | None
    ) -> list[dict[str, Any]]:
        if decision_time is None:
            return []
        events = []
        for _, event in self._events_by_identity.get(identity, ()):
            timestamp = self._timestamp(event)
            if timestamp is None:
                continue
            if timestamp <= decision_time:
                events.append(event)
        return events

    def _identity(
        self, event: dict[str, Any]
    ) -> tuple[tuple[Any, ...], tuple[str, ...]]:
        pid = self._positive_int(event.get("pid"))
        explicit = self._explicit_instance_id(event)
        if explicit is not None:
            return ("instance", pid, explicit), ()
        if pid is None:
            return ("missing-pid", self._sequence), (
                "missing pid; event isolated without process association",
            )

        signature = (
            self._value_key(event.get("ppid")),
            self._value_key(event.get("process")),
            self._value_key(event.get("exe")),
        )
        previous = self._pid_signatures.get(pid)
        generation = 0
        reused = False
        if previous is not None:
            previous_signature, previous_generation = previous
            generation = previous_generation
            if signature != previous_signature:
                generation += 1
                reused = True
        self._pid_signatures[pid] = (signature, generation)
        limitations = [
            "stable process-instance identifier unavailable; PID generation fallback used"
        ]
        if reused:
            limitations.append(
                "possible PID reuse or identity change; isolated into a new PID generation"
            )
        return ("pid", pid, generation), tuple(limitations)

    @staticmethod
    def _explicit_instance_id(event: dict[str, Any]) -> str | None:
        extra = event.get("extra")
        candidates = {}
        if isinstance(extra, dict):
            candidates.update(extra)
        for name in ("process_instance_id", "process_start_time", "start_time"):
            value = event.get(name, candidates.get(name))
            if value not in (None, ""):
                return f"{name}={value}"
        return None

    @staticmethod
    def _positive_int(value: Any) -> int | None:
        try:
            integer = int(value)
        except (TypeError, ValueError):
            return None
        return integer if integer > 0 else None

    @staticmethod
    def _value_key(value: Any) -> Any:
        if value in (None, ""):
            return None
        return str(value)

    @staticmethod
    def _identity_label(identity: tuple[Any, ...]) -> str:
        return ":".join(str(part) for part in identity)

    @staticmethod
    def _timestamp(event: dict[str, Any]) -> float | None:
        try:
            value = float(event.get("timestamp"))
        except (TypeError, ValueError):
            return None
        return value if isfinite(value) else None

    @staticmethod
    def _with_sample_id(
        prediction: PredictionRecord, event: dict[str, Any]
    ) -> PredictionRecord:
        sample_id = f"live-pid-{event.get('pid', 0)}"
        return PredictionRecord(
            sample_id=sample_id,
            baseline_label=prediction.baseline_label,
            raw_score=prediction.raw_score,
            malicious_probability=prediction.malicious_probability,
            model_id=prediction.model_id,
            model_version=prediction.model_version,
            feature_schema_id=prediction.feature_schema_id,
            inference_ms=prediction.inference_ms,
        )

    @staticmethod
    def _event_window(
        window_start: float | None, window_end: float | None
    ) -> tuple[datetime, datetime] | None:
        if window_start is None or window_end is None:
            return None
        return (
            datetime.fromtimestamp(window_start),
            datetime.fromtimestamp(window_end),
        )

    @staticmethod
    def _record(
        event: dict[str, Any],
        features: EventWindowFeatures,
        prediction: PredictionRecord,
        evidence: EvidenceRecord,
        decision: DecisionRecord,
    ) -> dict[str, Any]:
        return {
            "record_type": "ransomshield_incident",
            "recorded_at": time.time(),
            "event": event,
            "features": features.to_dict(),
            "prediction": asdict(prediction),
            "evidence": asdict(evidence),
            "decision": asdict(decision),
        }
