"""GuardFS-compatible feature derivation for normalized events.

These five features mirror the friend's documented FUSE-window representation.
They are an analysis adapter only: no GuardFS model is bundled or used for live
predictions.
"""

from __future__ import annotations

from math import isfinite
from typing import Any, Iterable


GUARDFS_FEATURE_NAMES = (
    "entropy_min",
    "entropy_mean",
    "entropy_max",
    "sum_writes",
    "sum_reads",
)


def extract_guardfs_features(
    events: Iterable[dict[str, Any]],
    *,
    decision_time: float | None = None,
    window_seconds: float = 5.0,
) -> dict[str, float]:
    """Derive GuardFS-style read/write and entropy aggregates without guessing.

    Only measured numeric ``extra.entropy`` values are included. Missing entropy
    is not replaced with a fabricated value.
    """
    if window_seconds <= 0 or not isfinite(window_seconds):
        raise ValueError("window_seconds must be finite and greater than zero")

    eligible: list[dict[str, Any]] = []
    for event in events:
        try:
            timestamp = float(event.get("timestamp"))
        except (TypeError, ValueError):
            continue
        if not isfinite(timestamp):
            continue
        if decision_time is not None and timestamp > decision_time:
            continue
        eligible.append(event)

    if eligible:
        start = min(float(event["timestamp"]) for event in eligible)
        eligible = [
            event
            for event in eligible
            if float(event["timestamp"]) <= start + window_seconds
        ]

    entropies: list[float] = []
    writes = 0
    reads = 0
    for event in eligible:
        event_type = str(event.get("event_type", "")).upper()
        if event_type == "FILE_WRITE":
            writes += 1
        elif event_type == "FILE_READ":
            reads += 1
        raw_entropy = event.get("extra", {}).get("entropy")
        try:
            entropy = float(raw_entropy)
        except (TypeError, ValueError):
            continue
        if isfinite(entropy) and 0.0 <= entropy <= 8.0:
            entropies.append(entropy)

    return {
        "entropy_min": min(entropies) if entropies else 0.0,
        "entropy_mean": sum(entropies) / len(entropies) if entropies else 0.0,
        "entropy_max": max(entropies) if entropies else 0.0,
        "sum_writes": float(writes),
        "sum_reads": float(reads),
    }
