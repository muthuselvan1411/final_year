"""Bounded, evidence-only behavioral correlation for normalized events.

The correlation view is intentionally separate from ``schema-event-window-v1``.
It organizes relationships that are supported by the capture; it does not
classify events, produce probabilities, or replace the per-process window.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, asdict
from math import isfinite
import json
from typing import Any


CORRELATION_SCHEMA_ID = "schema-behavior-correlation-v1"
CORRELATION_FEATURE_NAMES = (
    "observation_count",
    "operation_type_diversity",
    "related_process_count",
    "parent_child_relationship_count",
    "file_operation_count",
    "network_activity_count",
    "rename_count",
    "delete_count",
    "distinct_file_paths",
    "repeated_file_paths",
    "cross_process_activity",
    "file_network_temporal_relation",
    "process_identity_quality",
)

_FILE_OPERATIONS = {
    "FILE_OPEN",
    "FILE_READ",
    "FILE_WRITE",
    "FILE_CLOSE",
    "FILE_CREATE",
    "FILE_DELETE",
    "FILE_RENAME",
}


@dataclass(frozen=True)
class CorrelationRelationship:
    relationship_type: str
    source_event_id: str | None
    target_event_id: str | None
    evidence: str
    inferred: bool
    details: dict[str, Any]
    source_entity_id: str | None = None
    target_entity_id: str | None = None


@dataclass(frozen=True)
class BehaviorCorrelationResult:
    schema_id: str
    capture_context: str | None
    triggering_event_id: str | None
    supporting_event_ids: tuple[str, ...]
    relationships: tuple[CorrelationRelationship, ...]
    feature_values: dict[str, float]
    available: dict[str, bool]
    window_start: int | float | None
    window_end: int | float | None
    timestamp_source: str | None
    timestamp_unit: str | None
    ordered_event_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    correlation_rationale: str
    duplicate_event_ids: tuple[str, ...]
    conflicting_event_ids: tuple[str, ...]
    conflicting_event_details: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BehaviorCorrelationEngine:
    """Maintain bounded capture-scoped state and emit deterministic views."""

    def __init__(
        self,
        *,
        window_seconds: float = 10.0,
        max_events: int = 4096,
        max_contexts: int = 32,
    ) -> None:
        if not isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("window_seconds must be finite and greater than zero")
        if max_events <= 0 or max_contexts <= 0:
            raise ValueError("max_events and max_contexts must be greater than zero")
        self.window_seconds = window_seconds
        self.max_events = max_events
        self.max_contexts = max_contexts
        self._events: dict[str, deque[dict[str, Any]]] = {}
        self._event_index: dict[str, dict[str, tuple[str, dict[str, Any]]]] = {}
        self._context_order: deque[str] = deque()
        self._sequence = 0
        self._duplicate_event_ids: dict[str, set[str]] = {}
        self._conflicting_event_ids: dict[str, set[str]] = {}
        self._conflicting_event_details: dict[str, dict[str, Any]] = {}

    def observe(self, event: dict[str, Any]) -> BehaviorCorrelationResult:
        """Add one event and return the view supported by the current event."""
        context = self._context(event, self._sequence)
        if context not in self._events:
            self._events[context] = deque(maxlen=self.max_events)
            self._event_index[context] = {}
            self._duplicate_event_ids[context] = set()
            self._conflicting_event_ids[context] = set()
            self._conflicting_event_details[context] = {}
            self._context_order.append(context)
            while len(self._context_order) > self.max_contexts:
                expired = self._context_order.popleft()
                self._events.pop(expired, None)
                self._event_index.pop(expired, None)
                self._duplicate_event_ids.pop(expired, None)
                self._conflicting_event_ids.pop(expired, None)
                self._conflicting_event_details.pop(expired, None)

        stored = dict(event)
        stored["_correlation_sequence"] = self._sequence
        self._sequence += 1
        event_id = self._event_id(stored)
        if event_id is not None:
            fingerprint = self._fingerprint(stored)
            existing = self._event_index[context].get(event_id)
            if existing is not None:
                if existing[0] == fingerprint:
                    self._duplicate_event_ids[context].add(event_id)
                    self._bound_audit(context)
                    return self._build(
                        context,
                        existing[1],
                        extra_limitations=(
                            f"duplicate delivery ignored for source_event_id={event_id}",
                        ),
                    )
                self._conflicting_event_ids[context].add(event_id)
                self._conflicting_event_details[context][event_id] = {
                    "source_event_id": event_id,
                    "existing_event": {
                        key: value
                        for key, value in existing[1].items()
                        if key != "_correlation_sequence"
                    },
                    "conflicting_event": {
                        key: value
                        for key, value in stored.items()
                        if key != "_correlation_sequence"
                    },
                }
                self._bound_audit(context)
                return self._build(
                    context,
                    existing[1],
                    extra_limitations=(
                        f"conflicting payload excluded for source_event_id={event_id}",
                    ),
                )
            self._event_index[context][event_id] = (fingerprint, stored)
        self._append(context, stored)
        return self._build(context, stored)

    def _build(
        self,
        context: str,
        triggering_event: dict[str, Any],
        *,
        extra_limitations: tuple[str, ...] = (),
    ) -> BehaviorCorrelationResult:
        trigger_order = self._ordering_key(triggering_event)
        limitations: list[str] = []
        if trigger_order is None:
            limitations.append("triggering event has no valid causal timestamp")
            eligible: list[dict[str, Any]] = []
        else:
            eligible = self._eligible(context, trigger_order)
            if trigger_order[0] == "kernel_monotonic":
                if any(self._ordering_key(item) is None for item in self._events[context]):
                    limitations.append("events without valid timestamps excluded from causal ordering")
                if any(
                    self._ordering_key(item) is not None
                    and self._ordering_key(item)[0] != "kernel_monotonic"
                    for item in self._events[context]
                ):
                    limitations.append(
                        "events without kernel monotonic timestamps excluded from this ordering view"
                    )
            else:
                if any(
                    self._ordering_key(item) is not None
                    and self._ordering_key(item)[0] == "kernel_monotonic"
                    for item in self._events[context]
                ):
                    limitations.append(
                        "events with kernel monotonic timestamps excluded from wall-clock ordering view"
                    )

        trigger_pid = self._positive_int(triggering_event.get("pid"))
        if trigger_pid is None:
            related = [triggering_event] if trigger_order is not None else []
            limitations.append("missing or invalid triggering pid prevents process correlation")
        else:
            related_pids, parent_edges = self._related_processes(
                eligible, trigger_pid
            )
            related = [
                item
                for item in eligible
                if self._positive_int(item.get("pid")) in related_pids
            ]
            if not related and trigger_order is not None:
                related = [triggering_event]
            if not parent_edges:
                limitations.append(
                    "cross-process correlation requires observed parent-child metadata"
                )

        ordered = sorted(
            related,
            key=lambda item: (
                self._ordering_key(item)[1]
                if self._ordering_key(item) is not None
                else float("inf"),
                int(item.get("_correlation_sequence", 0)),
            ),
        )
        event_ids = tuple(self._event_id(item) for item in ordered if self._event_id(item))
        relationships = self._relationships(
            ordered, parent_edges if trigger_pid is not None else []
        )
        values, available = self._features(ordered, parent_edges if trigger_pid is not None else [])
        window_start, window_end = self._window_bounds(ordered)
        timestamp_source = self._timestamp_source(ordered)
        timestamp_unit = (
            "nanoseconds" if timestamp_source == "kernel_monotonic" else
            "seconds" if timestamp_source == "event_timestamp" else None
        )
        if trigger_pid is not None and len({self._positive_int(item.get("pid")) for item in ordered}) > 1:
            values["cross_process_activity"] = 1.0
            available["cross_process_activity"] = True
        return BehaviorCorrelationResult(
            schema_id=CORRELATION_SCHEMA_ID,
            capture_context=None if context.startswith("missing-context:") else context,
            triggering_event_id=self._event_id(triggering_event),
            supporting_event_ids=event_ids,
            relationships=tuple(relationships),
            feature_values=values,
            available=available,
            window_start=window_start,
            window_end=window_end,
            timestamp_source=timestamp_source,
            timestamp_unit=timestamp_unit,
            ordered_event_ids=event_ids,
            limitations=tuple(dict.fromkeys((*limitations, *extra_limitations))),
            correlation_rationale=(
                "Related events are included only when they share capture context and "
                "their process identifiers are connected by observed pid/ppid metadata."
            ),
            duplicate_event_ids=tuple(sorted(self._duplicate_event_ids[context])),
            conflicting_event_ids=tuple(sorted(self._conflicting_event_ids[context])),
            conflicting_event_details=tuple(
                self._conflicting_event_details[context][event_id]
                for event_id in sorted(self._conflicting_event_details[context])
            ),
        )

    def _append(self, context: str, event: dict[str, Any]) -> None:
        bucket = self._events[context]
        if len(bucket) == self.max_events:
            evicted = bucket[0]
            evicted_id = self._event_id(evicted)
            if evicted_id is not None:
                self._event_index[context].pop(evicted_id, None)
        bucket.append(event)

    def _bound_audit(self, context: str) -> None:
        """Keep duplicate/conflict provenance bounded with event retention."""
        duplicate_ids = sorted(self._duplicate_event_ids[context])
        if len(duplicate_ids) > self.max_events:
            self._duplicate_event_ids[context] = set(duplicate_ids[-self.max_events :])
        conflict_ids = sorted(self._conflicting_event_details[context])
        if len(conflict_ids) > self.max_events:
            retained = conflict_ids[-self.max_events :]
            self._conflicting_event_details[context] = {
                event_id: self._conflicting_event_details[context][event_id]
                for event_id in retained
            }
            self._conflicting_event_ids[context] = set(retained)

    def _eligible(
        self, context: str, trigger_order: tuple[str, int | float]
    ) -> list[dict[str, Any]]:
        kind, value = trigger_order
        cutoff = value - (
            self.window_seconds * 1_000_000_000
            if kind == "kernel_monotonic"
            else self.window_seconds
        )
        candidates = []
        for event in self._events[context]:
            ordering = self._ordering_key(event)
            if ordering is None or ordering[0] != kind:
                continue
            if cutoff <= ordering[1] <= value:
                candidates.append(event)
        return sorted(
            candidates,
            key=lambda item: (
                self._ordering_key(item)[1],
                int(item.get("_correlation_sequence", 0)),
            ),
        )

    def _related_processes(
        self, events: list[dict[str, Any]], trigger_pid: int
    ) -> tuple[set[int], list[tuple[dict[str, Any], dict[str, Any]]]]:
        pids = {trigger_pid}
        edges: list[tuple[dict[str, Any], dict[str, Any]]] = []
        changed = True
        while changed:
            changed = False
            for parent in events:
                parent_pid = self._positive_int(parent.get("pid"))
                for child in events:
                    child_pid = self._positive_int(child.get("pid"))
                    child_ppid = self._positive_int(child.get("ppid"))
                    if (
                        parent_pid is None
                        or child_pid is None
                        or child_pid == parent_pid
                        or child_ppid != parent_pid
                    ):
                        continue
                    if parent_pid in pids or child_pid in pids:
                        if (parent, child) not in edges:
                            edges.append((parent, child))
                        for process_id in (parent_pid, child_pid):
                            if process_id not in pids:
                                pids.add(process_id)
                                changed = True
        if trigger_pid not in pids:
            pids.add(trigger_pid)
        return pids, edges

    def _relationships(
        self,
        events: list[dict[str, Any]],
        parent_edges: list[tuple[dict[str, Any], dict[str, Any]]],
    ) -> list[CorrelationRelationship]:
        relationships: list[CorrelationRelationship] = []
        for parent, child in parent_edges:
            relationships.append(
                CorrelationRelationship(
                    "process_spawned_by",
                    self._event_id(parent),
                    self._event_id(child),
                    "child pid matches parent event pid through child ppid",
                    True,
                    {
                        "parent_pid": self._positive_int(parent.get("pid")),
                        "child_pid": self._positive_int(child.get("pid")),
                    },
                    self._process_entity_id(parent),
                    self._process_entity_id(child),
                )
            )
        for event in events:
            event_id = self._event_id(event)
            event_type = str(event.get("event_type", "OTHER")).upper()
            pid = self._positive_int(event.get("pid"))
            if pid is not None and event_type in _FILE_OPERATIONS:
                relationships.append(
                    CorrelationRelationship(
                        "process_performed_file_operation",
                        event_id,
                        event_id,
                        "event pid and file operation type are present",
                        False,
                        {"pid": pid, "event_type": event_type, "path": event.get("path")},
                        self._process_entity_id(event),
                        self._file_entity_id(event),
                    )
                )
            if pid is not None and (
                event_type == "NET_CONNECT"
                or event.get("dst_ip") is not None
                or event.get("dst_port") is not None
            ):
                relationships.append(
                    CorrelationRelationship(
                        "process_made_network_connection_attempt",
                        event_id,
                        event_id,
                        "event pid and network destination evidence are present",
                        False,
                        {
                            "pid": pid,
                            "dst_ip": event.get("dst_ip"),
                            "dst_port": event.get("dst_port"),
                            "success": event.get("success"),
                        },
                        self._process_entity_id(event),
                        self._network_entity_id(event),
                    )
                )
            if event_type == "FILE_RENAME":
                old_path = event.get("extra", {}).get("old_path")
                if old_path not in (None, ""):
                    relationships.append(
                        CorrelationRelationship(
                            "file_rename_observed",
                            event_id,
                            event_id,
                            "rename event contains old_path and current path",
                            False,
                            {"old_path": old_path, "new_path": event.get("path")},
                            self._file_entity_id_for_path(event, old_path),
                            self._file_entity_id(event),
                        )
                    )
        for left, right in zip(events, events[1:]):
            if self._event_id(left) and self._event_id(right):
                relationships.append(
                    CorrelationRelationship(
                        "event_order",
                        self._event_id(left),
                        self._event_id(right),
                        "valid causal timestamps ordered the observations",
                        True,
                        {},
                        self._event_entity_id(left),
                        self._event_entity_id(right),
                    )
                )
        return relationships

    @staticmethod
    def _context_prefix(event: dict[str, Any]) -> str:
        return str(event.get("source_context") or "unknown-context")

    @classmethod
    def _process_entity_id(cls, event: dict[str, Any]) -> str | None:
        pid = cls._positive_int(event.get("pid"))
        return (
            f"process:{cls._context_prefix(event)}:pid:{pid}"
            if pid is not None
            else None
        )

    @classmethod
    def _file_entity_id(cls, event: dict[str, Any]) -> str | None:
        return cls._file_entity_id_for_path(event, event.get("path"))

    @classmethod
    def _file_entity_id_for_path(cls, event: dict[str, Any], path: Any) -> str | None:
        if path in (None, ""):
            return None
        return f"file:{cls._context_prefix(event)}:path:{path}"

    @classmethod
    def _network_entity_id(cls, event: dict[str, Any]) -> str | None:
        address = event.get("dst_ip") or event.get("dst_host")
        port = event.get("dst_port")
        if address in (None, "") and port in (None, ""):
            return None
        return f"network:{cls._context_prefix(event)}:{address or 'unknown'}:{port or 'unknown'}"

    @classmethod
    def _event_entity_id(cls, event: dict[str, Any]) -> str | None:
        event_id = cls._event_id(event)
        return f"event:{cls._context_prefix(event)}:{event_id}" if event_id else None

    def _features(
        self,
        events: list[dict[str, Any]],
        parent_edges: list[tuple[dict[str, Any], dict[str, Any]]],
    ) -> tuple[dict[str, float], dict[str, bool]]:
        paths = [
            str(event["path"])
            for event in events
            if event.get("path") not in (None, "")
        ]
        counts: dict[str, int] = {}
        for path in paths:
            counts[path] = counts.get(path, 0) + 1
        pids = {
            pid
            for event in events
            if (pid := self._positive_int(event.get("pid"))) is not None
        }
        types = {str(event.get("event_type", "OTHER")).upper() for event in events}
        file_count = sum(
            str(event.get("event_type", "OTHER")).upper() in _FILE_OPERATIONS
            for event in events
        )
        network_count = sum(
            str(event.get("event_type", "OTHER")).upper() == "NET_CONNECT"
            or event.get("dst_ip") is not None
            or event.get("dst_port") is not None
            for event in events
        )
        file_times = [
            self._ordering_key(event)[1]
            for event in events
            if str(event.get("event_type", "OTHER")).upper() in _FILE_OPERATIONS
            and self._ordering_key(event) is not None
        ]
        network_times = [
            self._ordering_key(event)[1]
            for event in events
            if (
                str(event.get("event_type", "OTHER")).upper() == "NET_CONNECT"
                or event.get("dst_ip") is not None
                or event.get("dst_port") is not None
            )
            and self._ordering_key(event) is not None
        ]
        relation = bool(
            file_times
            and network_times
            and min(abs(file_time - network_time) for file_time in file_times for network_time in network_times)
            <= (
                self.window_seconds * 1_000_000_000
                if self._ordering_key(events[0]) and self._ordering_key(events[0])[0] == "kernel_monotonic"
                else self.window_seconds
            )
        )
        values = {
            "observation_count": float(len(events)),
            "operation_type_diversity": float(len(types)),
            "related_process_count": float(len(pids)),
            "parent_child_relationship_count": float(len(parent_edges)),
            "file_operation_count": float(file_count),
            "network_activity_count": float(network_count),
            "rename_count": float(sum(
                str(event.get("event_type", "")).upper() == "FILE_RENAME"
                for event in events
            )),
            "delete_count": float(sum(
                str(event.get("event_type", "")).upper() == "FILE_DELETE"
                for event in events
            )),
            "distinct_file_paths": float(len(counts)),
            "repeated_file_paths": float(sum(count > 1 for count in counts.values())),
            "cross_process_activity": float(len(pids) > 1),
            "file_network_temporal_relation": float(relation),
            "process_identity_quality": float(
                all(self._positive_int(event.get("pid")) is not None for event in events)
                if events
                else False
            ),
        }
        available = {
            name: bool(events)
            for name in CORRELATION_FEATURE_NAMES
        }
        available["parent_child_relationship_count"] = bool(parent_edges)
        available["file_network_temporal_relation"] = bool(file_times and network_times)
        available["cross_process_activity"] = len(pids) > 1
        available["process_identity_quality"] = bool(events)
        return values, available

    @staticmethod
    def _context(event: dict[str, Any], sequence: int) -> str:
        context = event.get("source_context")
        return str(context) if context not in (None, "") else f"missing-context:{sequence}"

    @staticmethod
    def _fingerprint(event: dict[str, Any]) -> str:
        payload = {
            key: value
            for key, value in event.items()
            if key != "_correlation_sequence"
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)

    @staticmethod
    def _event_id(event: dict[str, Any]) -> str | None:
        value = event.get("source_event_id")
        return str(value) if value not in (None, "") else None

    @staticmethod
    def _positive_int(value: Any) -> int | None:
        try:
            integer = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return integer if integer > 0 else None

    @staticmethod
    def _ordering_key(event: dict[str, Any]) -> tuple[str, int | float] | None:
        raw_ns = event.get("timestamp_ns")
        try:
            timestamp_ns = int(raw_ns)
        except (TypeError, ValueError, OverflowError):
            timestamp_ns = None
        if timestamp_ns is not None and timestamp_ns >= 0:
            return "kernel_monotonic", timestamp_ns
        try:
            timestamp = float(event.get("timestamp"))
        except (TypeError, ValueError, OverflowError):
            return None
        return ("event_timestamp", timestamp) if isfinite(timestamp) else None

    @classmethod
    def _timestamp_source(cls, events: list[dict[str, Any]]) -> str | None:
        kinds = {key[0] for event in events if (key := cls._ordering_key(event))}
        return next(iter(kinds), None)

    @classmethod
    def _window_bounds(
        cls, events: list[dict[str, Any]]
    ) -> tuple[int | float | None, int | float | None]:
        values = [
            key[1]
            for event in events
            if (key := cls._ordering_key(event)) is not None
        ]
        return (min(values), max(values)) if values else (None, None)
