"""Versioned, causal event-level feature contract.

This contract is independent of the frozen 483-feature MLRan schema.  It is
intended for a future event-level detector and does not train or score one.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from math import isfinite
from typing import Any, Iterable

from .process import build_process_context
from .temporal import extract_temporal_features, select_causal_window_events

EVENT_FEATURE_SCHEMA_ID = "schema-event-window-v1"
EVENT_FEATURE_NAMES = (
    "observation_count",
    "file_modifications",
    "rename_count",
    "delete_count",
    "distinct_files",
    "repeated_files",
    "event_rate",
    "burst_ratio",
    "temporal_consistency",
    "distinct_pids",
    "distinct_ppids",
    "single_process_available",
    "process_event_count",
    "process_ordered",
    "has_pid",
    "has_ppid",
)


@dataclass(frozen=True)
class EventWindowFeatures:
    """Numeric features and explicit availability for one causal window."""

    schema_id: str
    decision_time: float | None
    values: dict[str, float]
    available: dict[str, bool]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def vector(self) -> list[float]:
        """Return values in the immutable ``EVENT_FEATURE_NAMES`` order."""
        return [self.values[name] for name in EVENT_FEATURE_NAMES]


def extract_event_window_features(
    events: Iterable[dict[str, Any]],
    *,
    window_seconds: float = 10.0,
    decision_time: float | None = None,
) -> EventWindowFeatures:
    """Extract only information observed at or before ``decision_time``.

    Missing temporal and process observations remain unavailable through the
    accompanying mask; they are not silently converted into evidence.
    """
    materialized = list(events)
    eligible = select_causal_window_events(
        materialized,
        window_seconds=window_seconds,
        decision_time=decision_time,
    )
    temporal = extract_temporal_features(
        materialized,
        window_seconds=window_seconds,
        decision_time=decision_time,
    )
    process = build_process_context(eligible, decision_time=decision_time)

    temporal_available = temporal.observation_count > 0
    process_available = process.event_count > 0
    values = {
        "observation_count": float(temporal.observation_count),
        "file_modifications": float(temporal.file_modifications),
        "rename_count": float(temporal.rename_count),
        "delete_count": float(temporal.delete_count),
        "distinct_files": float(temporal.distinct_files),
        "repeated_files": float(temporal.repeated_files),
        "event_rate": float(temporal.event_rate or 0.0),
        "burst_ratio": float(temporal.burst_ratio or 0.0),
        "temporal_consistency": float(temporal.temporal_consistency or 0.0),
        "distinct_pids": float(
            len({event.get("pid") for event in eligible if event.get("pid") is not None})
        ),
        "distinct_ppids": float(
            len({event.get("ppid") for event in eligible if event.get("ppid") is not None})
        ),
        "single_process_available": float(process.process_id is not None),
        "process_event_count": float(process.event_count),
        "process_ordered": float(process.ordered),
        "has_pid": float("pid" not in process.unavailable_fields),
        "has_ppid": float("ppid" not in process.unavailable_fields),
    }
    available = {
        name: temporal_available
        for name in (
            "observation_count",
            "file_modifications",
            "rename_count",
            "delete_count",
            "distinct_files",
            "repeated_files",
            "burst_ratio",
            "temporal_consistency",
        )
    }
    available["event_rate"] = temporal_available and temporal.event_rate is not None
    available.update(
        {
            "distinct_pids": process_available,
            "distinct_ppids": process_available,
            "single_process_available": process.process_id is not None,
            "process_event_count": process_available,
            "process_ordered": process_available,
            "has_pid": "pid" not in process.unavailable_fields,
            "has_ppid": "ppid" not in process.unavailable_fields,
        }
    )
    limitations = list(process.limitations)
    if temporal.unavailable_reason:
        limitations.append(temporal.unavailable_reason)
    return EventWindowFeatures(
        schema_id=EVENT_FEATURE_SCHEMA_ID,
        decision_time=decision_time,
        values=values,
        available=available,
        limitations=tuple(dict.fromkeys(limitations)),
    )
