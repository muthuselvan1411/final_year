"""Audit recorded event traces without using labels as evidence."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from math import isfinite
from typing import Any, Iterable


@dataclass(frozen=True)
class TraceAudit:
    event_count: int
    event_type_counts: dict[str, int]
    valid_timestamp_count: int
    invalid_timestamp_count: int
    timestamps_monotonic_in_file_order: bool
    duplicate_event_count: int
    distinct_pids: int
    distinct_ppids: int
    events_with_pid: int
    events_with_ppid: int
    events_with_path: int
    first_timestamp: float | None
    last_timestamp: float | None
    trace_duration_seconds: float | None
    missing_required_fields: dict[str, int]
    trace_group: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify_group_disjointness(partitions: dict[str, Iterable[str]]) -> None:
    """Reject trace/process groups appearing in more than one partition."""
    seen: dict[str, str] = {}
    for partition, groups in partitions.items():
        for group in groups:
            previous = seen.get(group)
            if previous is not None and previous != partition:
                raise ValueError(
                    f"Trace/process group {group!r} appears in both "
                    f"{previous!r} and {partition!r} partitions."
                )
            seen[group] = partition


def audit_events(
    events: Iterable[dict[str, Any]],
    *,
    trace_group: str,
) -> TraceAudit:
    materialized = list(events)
    required = ("timestamp", "pid", "ppid", "event_type")
    missing = {
        field: sum(field not in event for event in materialized)
        for field in required
    }
    timestamps: list[float] = []
    invalid = 0
    for event in materialized:
        try:
            value = float(event.get("timestamp"))
        except (TypeError, ValueError):
            invalid += 1
            continue
        if not isfinite(value):
            invalid += 1
        else:
            timestamps.append(value)
    file_order_monotonic = all(
        left <= right for left, right in zip(timestamps, timestamps[1:])
    )
    event_keys = [
        repr(sorted((key, repr(value)) for key, value in event.items()))
        for event in materialized
    ]
    duplicate_count = len(event_keys) - len(set(event_keys))
    valid_timestamps = timestamps
    return TraceAudit(
        event_count=len(materialized),
        event_type_counts=dict(Counter(str(e.get("event_type", "MISSING")) for e in materialized)),
        valid_timestamp_count=len(valid_timestamps),
        invalid_timestamp_count=invalid,
        timestamps_monotonic_in_file_order=file_order_monotonic,
        duplicate_event_count=duplicate_count,
        distinct_pids=len({e.get("pid") for e in materialized if e.get("pid") is not None}),
        distinct_ppids=len({e.get("ppid") for e in materialized if e.get("ppid") is not None}),
        events_with_pid=sum(e.get("pid") is not None for e in materialized),
        events_with_ppid=sum(e.get("ppid") is not None for e in materialized),
        events_with_path=sum(e.get("path") not in (None, "") for e in materialized),
        first_timestamp=min(valid_timestamps) if valid_timestamps else None,
        last_timestamp=max(valid_timestamps) if valid_timestamps else None,
        trace_duration_seconds=(
            max(valid_timestamps) - min(valid_timestamps)
            if valid_timestamps
            else None
        ),
        missing_required_fields=missing,
        trace_group=trace_group,
    )
