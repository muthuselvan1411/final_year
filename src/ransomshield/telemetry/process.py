"""Auditable process association for normalized telemetry events."""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Any, Iterable


@dataclass(frozen=True)
class ProcessContext:
    process_id: int | None
    parent_process_id: int | None
    process_name: str | None
    event_count: int
    ordered: bool
    unavailable_fields: tuple[str, ...]
    limitations: tuple[str, ...]


def build_process_context(
    events: Iterable[dict[str, Any]],
    *,
    decision_time: float | None = None,
) -> ProcessContext:
    """Build context only from supplied PID/PPID fields.

    A PID is not treated as globally unique; the result is a summary for the
    supplied event window and reports missing identifiers explicitly.
    """
    materialized = []
    for event in events:
        if decision_time is None:
            materialized.append(event)
            continue
        try:
            timestamp = float(event.get("timestamp"))
        except (TypeError, ValueError):
            continue
        if isfinite(timestamp) and timestamp <= decision_time:
            materialized.append(event)
    pids = {event.get("pid") for event in materialized if event.get("pid") is not None}
    ppids = {
        event.get("ppid") for event in materialized if event.get("ppid") is not None
    }
    names = {
        str(event["process"])
        for event in materialized
        if event.get("process") not in (None, "")
    }
    timestamps = [event.get("timestamp") for event in materialized]
    ordered = all(
        isinstance(left, (int, float))
        and isinstance(right, (int, float))
        and left <= right
        for left, right in zip(timestamps, timestamps[1:])
    )
    missing = []
    if not pids:
        missing.append("pid")
    if not ppids:
        missing.append("ppid")
    if not names:
        missing.append("process")
    limitations = []
    if len(pids) > 1:
        limitations.append("multiple process identifiers in event window")
    if not ordered:
        limitations.append("events were not supplied in timestamp order")
    return ProcessContext(
        process_id=next(iter(pids)) if len(pids) == 1 else None,
        parent_process_id=next(iter(ppids)) if len(ppids) == 1 else None,
        process_name=next(iter(names)) if len(names) == 1 else None,
        event_count=len(materialized),
        ordered=ordered,
        unavailable_fields=tuple(missing),
        limitations=tuple(limitations),
    )
