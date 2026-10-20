import math
import os
import hashlib
import json
from typing import Dict, Any, Optional

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates the Shannon Entropy (0.0 - 8.0) of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def sample_file_entropy(path: Optional[str], sample_size: int = 4096) -> float:
    """Reads a sample of bytes from the file to calculate Shannon entropy."""
    if not path or not os.path.exists(path) or os.path.isdir(path):
        return 0.0
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
            return calculate_shannon_entropy(chunk)
    except Exception:
        return 0.0

class EventNormalizer:
    """
    Normalizes raw kernel telemetry events to 100% conform to Member 2's
    RansomShield NormalizedEvent schema.
    """
    def __init__(self, compute_entropy: bool = True):
        self.compute_entropy = compute_entropy
        self._occurrences: dict[str, int] = {}

    @staticmethod
    def _integer_or_sentinel(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default

    def normalize(
        self,
        raw_event: Dict[str, Any],
        *,
        source_context: str | None = None,
        occurrence_index: int | None = None,
    ) -> Dict[str, Any]:
        """Enriches and standardizes an event dictionary."""
        event_type = str(raw_event.get("event_type", "OTHER")).upper()
        path = raw_event.get("path") or None
        extra = dict(raw_event.get("extra", {})) if isinstance(raw_event.get("extra"), dict) else {}

        # If file write, optionally calculate header entropy
        if self.compute_entropy and event_type == "FILE_WRITE" and path:
            entropy_val = sample_file_entropy(path)
            extra["entropy"] = entropy_val

        supplied_id = raw_event.get("source_event_id", raw_event.get("event_id"))
        if supplied_id in (None, ""):
            supplied_id = extra.get("source_event_id")
        context = source_context or str(raw_event.get("source_context") or "normalizer")
        canonical = json.dumps(raw_event, sort_keys=True, separators=(",", ":"), default=str)
        digest = hashlib.sha256(
            f"{context}|{canonical}".encode("utf-8")
        ).hexdigest()
        if occurrence_index is None:
            occurrence_index = self._occurrences.get(digest, 0) + 1
        self._occurrences[digest] = occurrence_index
        source_event_id = (
            str(supplied_id)
            if supplied_id not in (None, "")
            else f"rs-event-{hashlib.sha256(f'{digest}|{occurrence_index}'.encode()).hexdigest()[:24]}"
        )

        normalized = {
            "timestamp": float(raw_event.get("timestamp", 0.0)),
            "timestamp_ns": (
                int(raw_event["timestamp_ns"])
                if raw_event.get("timestamp_ns") is not None
                else None
            ),
            "receive_timestamp": (
                float(raw_event["receive_timestamp"])
                if raw_event.get("receive_timestamp") is not None
                else None
            ),
            "pid": self._integer_or_sentinel(raw_event.get("pid", 0)),
            "ppid": self._integer_or_sentinel(raw_event.get("ppid", 0)),
            "process": str(raw_event.get("process", "unknown")),
            "exe": str(raw_event.get("exe", raw_event.get("process", "unknown"))),
            "event_type": event_type,
            "path": path,
            "bytes": int(raw_event.get("bytes", 0)),
            "dst_ip": raw_event.get("dst_ip"),
            "dst_port": int(raw_event["dst_port"]) if raw_event.get("dst_port") is not None else None,
            "protocol": raw_event.get("protocol"),
            "success": (
                None
                if "success" in raw_event and raw_event["success"] is None
                else bool(raw_event.get("success", True))
            ),
            "extra": extra,
            "source_event_id": source_event_id,
            "source_context": context,
        }
        return normalized
