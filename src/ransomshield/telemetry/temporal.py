"""Causal temporal features for normalized file-event telemetry.

This module accepts only events with an explicit numeric timestamp. It never
uses labels and never invents ordering for records without timestamps.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Any, Iterable


@dataclass(frozen=True)
class TemporalFeatures:
    window_start: float | None
    window_end: float | None
    observation_count: int
    file_modifications: int
    rename_count: int
    delete_count: int
    distinct_files: int
    repeated_files: int
    event_rate: float | None
    burst_ratio: float | None
    temporal_consistency: float | None
    unavailable_reason: str | None = None


def extract_temporal_features(
    events: Iterable[dict[str, Any]],
    *,
    window_seconds: float = 10.0,
    score_threshold: float | None = None,
    score_key: str = "score",
    decision_time: float | None = None,
) -> TemporalFeatures:
    """Summarize one causal event window.

    Events with missing, non-numeric, or non-finite timestamps are excluded and
    reported through ``unavailable_reason`` when no valid event remains.
    """
    if window_seconds <= 0 or not isfinite(window_seconds):
        raise ValueError("window_seconds must be finite and greater than zero")

    valid = []
    for event in events:
        timestamp = event.get("timestamp")
        try:
            timestamp = float(timestamp)
        except (TypeError, ValueError):
            continue
        if isfinite(timestamp) and (
            decision_time is None or timestamp <= decision_time
        ):
            valid.append((timestamp, event))

    if not valid:
        return TemporalFeatures(
            None, None, 0, 0, 0, 0, 0, 0, None, None, None,
            "no valid event timestamps",
        )

    valid.sort(key=lambda item: item[0])
    start = valid[0][0]
    end = min(valid[-1][0], start + window_seconds)
    window = [(ts, event) for ts, event in valid if ts <= end]
    paths = [
        str(event.get("path"))
        for _, event in window
        if event.get("path") not in (None, "")
    ]
    counts: dict[str, int] = {}
    for path in paths:
        counts[path] = counts.get(path, 0) + 1

    event_count = len(window)
    duration = max(end - start, 0.0)
    scores = []
    for _, event in window:
        try:
            score = float(event[score_key])
        except (KeyError, TypeError, ValueError):
            continue
        if isfinite(score) and 0.0 <= score <= 1.0:
            scores.append(score)

    if score_threshold is not None and scores:
        consistency = sum(score >= score_threshold for score in scores) / len(scores)
    else:
        subwindow_count = max(1, min(4, int(window_seconds)))
        subwindow_width = window_seconds / subwindow_count
        occupied = {
            min(subwindow_count - 1, int((ts - start) / subwindow_width))
            for ts, _ in window
        }
        consistency = len(occupied) / subwindow_count if occupied else None
    return TemporalFeatures(
        window_start=start,
        window_end=end,
        observation_count=event_count,
        file_modifications=sum(
            event.get("event_type") in {"FILE_WRITE", "FILE_CREATE"}
            for _, event in window
        ),
        rename_count=sum(event.get("event_type") == "FILE_RENAME" for _, event in window),
        delete_count=sum(event.get("event_type") == "FILE_DELETE" for _, event in window),
        distinct_files=len(counts),
        repeated_files=sum(count > 1 for count in counts.values()),
        event_rate=event_count / duration if duration > 0 else None,
        burst_ratio=(
            max(counts.values()) / event_count if counts and event_count else None
        ),
        temporal_consistency=consistency,
    )
