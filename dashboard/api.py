"""Read-only FastAPI views over bounded RansomShield JSONL evidence stores."""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse


@dataclass(frozen=True)
class DashboardSource:
    name: str
    kind: str
    incidents_path: Path
    events_path: Path | None = None
    label: str | None = None


class DashboardDataError(RuntimeError):
    """Raised when a configured dashboard source cannot be read."""


def _record_lines(path: Path, *, limit: int = 100_000) -> tuple[list[dict[str, Any]], int, list[str]]:
    if not path.is_file():
        raise DashboardDataError(f"Configured store is missing: {path}")
    records: list[dict[str, Any]] = []
    malformed = 0
    errors: list[str] = []
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                if len(records) >= limit:
                    errors.append(f"record limit reached at line {line_number}")
                    break
                if not line.strip():
                    malformed += 1
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                if isinstance(value, dict):
                    records.append(value)
                else:
                    malformed += 1
    except OSError as exc:
        raise DashboardDataError(f"Unable to read configured store: {path}") from exc
    return records, malformed, errors


def _event_timestamp(event: dict[str, Any]) -> tuple[str, int | float] | None:
    try:
        timestamp_ns = int(event["timestamp_ns"])
    except (KeyError, TypeError, ValueError, OverflowError):
        timestamp_ns = None
    if timestamp_ns is not None and timestamp_ns >= 0:
        return "kernel_monotonic", timestamp_ns
    try:
        timestamp = float(event["timestamp"])
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    return ("event_timestamp", timestamp) if timestamp == timestamp else None


def _source_payload(source: DashboardSource, *, malformed: int = 0, errors: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": source.name,
        "label": source.label or source.name,
        "kind": source.kind,
        "incidents_path": str(source.incidents_path),
        "events_path": str(source.events_path) if source.events_path else None,
        "malformed_records": malformed,
        "errors": errors or [],
    }


def _deduplicate_incidents(
    records: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Collapse exact repeated persisted rows without merging distinct events."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    duplicates = 0
    for record in records:
        event = record.get("event", {})
        key = json.dumps(
            {
                "source_event_id": event.get("source_event_id"),
                "source_context": event.get("source_context"),
                "event": event,
                "decision": record.get("decision"),
            },
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        unique.append(record)
    return unique, duplicates


def _graph_payload(
    incidents: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    event_by_id = {
        (str(event.get("source_context", "")), str(event.get("source_event_id", ""))): event
        for event in events
        if event.get("source_event_id") not in (None, "")
    }
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    contexts: set[str] = set()
    schemas: set[str] = set()
    windows: list[dict[str, Any]] = []

    def add_node(node_id: str | None, node_type: str, label: str, **data: Any) -> None:
        if not node_id:
            return
        nodes.setdefault(
            node_id,
            {"id": node_id, "type": node_type, "label": label, "data": data},
        )

    def entity_id(kind: str, context: str, value: Any) -> str | None:
        if value in (None, ""):
            return None
        return f"{kind}:{context}:{value}"

    for incident in incidents:
        correlation = incident.get("correlation")
        if not isinstance(correlation, dict):
            continue
        context = str(
            correlation.get("capture_context")
            or incident.get("triggering_source_context")
            or ""
        )
        if context:
            contexts.add(context)
        if correlation.get("schema_id"):
            schemas.add(str(correlation["schema_id"]))
        windows.append(
            {
                "start": correlation.get("window_start"),
                "end": correlation.get("window_end"),
                "timestamp_source": correlation.get("timestamp_source"),
                "timestamp_unit": correlation.get("timestamp_unit"),
            }
        )
        for relation in correlation.get("relationships", []):
            if not isinstance(relation, dict):
                continue
            source_id = relation.get("source_entity_id")
            target_id = relation.get("target_entity_id")
            relation_type = str(relation.get("relationship_type", ""))
            details = relation.get("details")
            details = details if isinstance(details, dict) else {}
            source_event = event_by_id.get((context, str(relation.get("source_event_id", ""))))
            target_event = event_by_id.get((context, str(relation.get("target_event_id", ""))))

            # Older persisted records predate explicit entity endpoints. Project
            # only relationships whose stored type/details identify both ends.
            if not source_id or not target_id:
                if relation_type == "process_performed_file_operation":
                    source_id = entity_id("process", context, f"pid:{details.get('pid')}")
                    target_id = entity_id("file", context, f"path:{details.get('path')}")
                elif relation_type == "process_made_network_connection_attempt":
                    address = details.get("dst_ip") or details.get("dst_host")
                    port = details.get("dst_port") or "unknown"
                    source_id = entity_id("process", context, f"pid:{details.get('pid')}")
                    target_id = entity_id("network", context, f"{address or 'unknown'}:{port}")
                elif relation_type == "file_rename_observed":
                    source_id = entity_id("file", context, f"path:{details.get('old_path')}")
                    target_id = entity_id("file", context, f"path:{details.get('new_path')}")
                elif relation_type == "process_spawned_by":
                    source_id = entity_id("process", context, f"pid:{details.get('parent_pid')}")
                    target_id = entity_id("process", context, f"pid:{details.get('child_pid')}")
                elif relation_type == "event_order":
                    source_id = entity_id("event", context, relation.get("source_event_id"))
                    target_id = entity_id("event", context, relation.get("target_event_id"))
            if not source_id or not target_id or source_id == target_id:
                continue
            source_type = "process" if str(source_id).startswith("process:") else (
                "file" if str(source_id).startswith("file:") else
                "network" if str(source_id).startswith("network:") else "event"
            )
            target_type = "process" if str(target_id).startswith("process:") else (
                "file" if str(target_id).startswith("file:") else
                "network" if str(target_id).startswith("network:") else "event"
            )
            add_node(
                str(source_id),
                source_type,
                str((source_event or {}).get("process") or (source_event or {}).get("path") or source_id),
                pid=(source_event or {}).get("pid"),
                ppid=(source_event or {}).get("ppid"),
                path=(source_event or {}).get("path"),
                source_context=context,
            )
            add_node(
                str(target_id),
                target_type,
                str((target_event or {}).get("process") or (target_event or {}).get("path") or target_id),
                pid=(target_event or {}).get("pid"),
                ppid=(target_event or {}).get("ppid"),
                path=(target_event or {}).get("path"),
                dst_ip=(target_event or {}).get("dst_ip"),
                dst_port=(target_event or {}).get("dst_port"),
                source_context=context,
            )
            edges.append(
                {
                    "id": f"{context}:{relation.get('relationship_type')}:{relation.get('source_event_id')}:{relation.get('target_event_id')}",
                    "source": str(source_id),
                    "target": str(target_id),
                    "type": relation.get("relationship_type"),
                    "source_event_id": relation.get("source_event_id"),
                    "target_event_id": relation.get("target_event_id"),
                    "evidence": relation.get("evidence"),
                    "inferred": bool(relation.get("inferred", False)),
                    "details": details,
                    "source_context": context,
                }
            )
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "capture_contexts": sorted(contexts),
        "schema_ids": sorted(schemas),
        "windows": windows,
        "limitations": (
            ["legacy relationships without entity endpoints could not be projected"]
            if any(
                isinstance(record.get("correlation"), dict)
                and any(
                    (
                        not relation.get("source_entity_id")
                        or not relation.get("target_entity_id")
                    )
                    and not (
                        relation.get("relationship_type")
                        in {
                            "process_performed_file_operation",
                            "process_made_network_connection_attempt",
                            "file_rename_observed",
                            "process_spawned_by",
                            "event_order",
                        }
                        and isinstance(relation.get("details"), dict)
                    )
                    for relation in record["correlation"].get("relationships", [])
                    if isinstance(relation, dict)
                )
                for record in incidents
            )
            else []
        ),
    }


class DashboardRepository:
    def __init__(self, sources: dict[str, DashboardSource], *, max_records: int = 100_000):
        if not sources:
            raise ValueError("at least one dashboard source is required")
        if max_records <= 0:
            raise ValueError("max_records must be greater than zero")
        self.sources = dict(sources)
        self.max_records = max_records

    def source(self, name: str) -> DashboardSource:
        try:
            return self.sources[name]
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=f"Unknown dashboard source: {name}") from exc

    def incidents(self, source: DashboardSource) -> tuple[list[dict[str, Any]], int, list[str]]:
        records, malformed, errors = _record_lines(
            source.incidents_path, limit=self.max_records
        )
        unique, duplicates = _deduplicate_incidents(records)
        if duplicates:
            errors = [*errors, f"collapsed {duplicates} exact duplicate incident records"]
        return unique, malformed, errors

    def events(self, source: DashboardSource) -> tuple[list[dict[str, Any]], int, list[str]]:
        if source.events_path is not None:
            return _record_lines(source.events_path, limit=self.max_records)
        incidents, malformed, errors = self.incidents(source)
        events: list[dict[str, Any]] = []
        for incident in incidents:
            event = incident.get("event")
            if isinstance(event, dict):
                events.append(event)
            for supporting in incident.get("supporting_events", []):
                if isinstance(supporting, dict):
                    events.append(supporting)
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for event in events:
            event_id = str(event.get("source_event_id", ""))
            context = str(event.get("source_context", ""))
            unique.setdefault((context, event_id), event)
        return list(unique.values())[: self.max_records], malformed, errors


def _configured_sources() -> dict[str, DashboardSource]:
    raw = os.environ.get("RSHIELD_DASHBOARD_SOURCES", "")
    sources: dict[str, DashboardSource] = {}
    for item in raw.split(";"):
        if not item.strip():
            continue
        parts = item.split("|")
        if len(parts) < 3 or parts[1] not in {"replay", "simulation", "live"}:
            raise ValueError(
                "RSHIELD_DASHBOARD_SOURCES entries must be name|kind|incidents_path[|events_path]"
            )
        sources[parts[0]] = DashboardSource(
            name=parts[0],
            kind=parts[1],
            incidents_path=Path(parts[2]).resolve(),
            events_path=Path(parts[3]).resolve() if len(parts) > 3 and parts[3] else None,
        )
    if not sources:
        raise ValueError("RSHIELD_DASHBOARD_SOURCES is not configured")
    return sources


def create_app(
    sources: dict[str, DashboardSource] | None = None,
    *,
    max_records: int = 100_000,
) -> FastAPI:
    repository = DashboardRepository(sources or _configured_sources(), max_records=max_records)
    app = FastAPI(title="RansomShield Evidence Dashboard", version="1.0")
    @app.exception_handler(DashboardDataError)
    async def dashboard_data_error(_, exc: DashboardDataError):
        return JSONResponse(status_code=503, content={"detail": str(exc)})
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    def get_source(name: str) -> DashboardSource:
        return repository.source(name)

    @app.get("/api/sources")
    def sources_status() -> dict[str, Any]:
        result = []
        for source in repository.sources.values():
            exists = source.incidents_path.is_file()
            result.append(
                {
                    **_source_payload(source),
                    "available": exists,
                    "freshness": (
                        source.incidents_path.stat().st_mtime if exists else None
                    ),
                }
            )
        return {"sources": result}

    @app.get("/api/summary")
    def summary(source: str = Query(...)) -> dict[str, Any]:
        selected = get_source(source)
        incidents, malformed_i, errors_i = repository.incidents(selected)
        events, malformed_e, errors_e = repository.events(selected)
        event_types = Counter(str(event.get("event_type", "OTHER")) for event in events)
        decisions = Counter(
            str(incident.get("decision", {}).get("action", "UNKNOWN"))
            for incident in incidents
        )
        timestamps = [_event_timestamp(event) for event in events]
        bases = Counter(item[0] for item in timestamps if item is not None)
        return {
            "source": _source_payload(
                selected,
                malformed=malformed_i + malformed_e,
                errors=errors_i + errors_e,
            ),
            "total_events": len(events),
            "incidents_recorded": len(incidents),
            "event_types": dict(event_types),
            "decisions": dict(decisions),
            "detector_status": Counter(
                str(incident.get("evidence", {}).get("detector_status", "unknown"))
                for incident in incidents
            ),
            "timestamp_bases": dict(bases),
            "abstain_count": decisions.get("ABSTAIN", 0),
            "malformed_records": malformed_i + malformed_e,
        }

    @app.get("/api/incidents")
    def incidents(
        source: str = Query(...),
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
        decision: str | None = None,
        event_type: str | None = None,
        process: str | None = None,
        source_context: str | None = None,
    ) -> dict[str, Any]:
        selected = get_source(source)
        records, malformed, errors = repository.incidents(selected)
        filtered = []
        for index, record in enumerate(records):
            event = record.get("event", {})
            if decision and record.get("decision", {}).get("action") != decision:
                continue
            if event_type and event.get("event_type") != event_type:
                continue
            if process and process.lower() not in str(event.get("process", "")).lower():
                continue
            context = record.get("triggering_source_context") or event.get("source_context")
            if source_context and source_context not in str(context):
                continue
            filtered.append({"index": index, **record})
        return {
            "items": filtered[offset : offset + limit],
            "total": len(filtered),
            "offset": offset,
            "limit": limit,
            "source": _source_payload(selected, malformed=malformed, errors=errors),
        }

    @app.get("/api/incidents/{incident_index}")
    def incident_detail(incident_index: int, source: str = Query(...)) -> dict[str, Any]:
        selected = get_source(source)
        records, _, _ = repository.incidents(selected)
        if incident_index < 0 or incident_index >= len(records):
            raise HTTPException(status_code=404, detail="Incident not found")
        return {"source": _source_payload(selected), "incident": records[incident_index]}

    @app.get("/api/incidents/{incident_index}/correlation")
    def incident_correlation(incident_index: int, source: str = Query(...)) -> dict[str, Any]:
        detail = incident_detail(incident_index, source)
        incident = detail["incident"]
        correlation = incident.get("correlation", {})
        return {
            "source": detail["source"],
            "correlation": correlation,
            "relationships": correlation.get("relationships", []),
            "supporting_events": incident.get("supporting_events", []),
        }

    @app.get("/api/graph")
    def graph(source: str = Query(...)) -> dict[str, Any]:
        selected = get_source(source)
        incidents, _, _ = repository.incidents(selected)
        events, _, _ = repository.events(selected)
        return {
            "source": _source_payload(selected),
            "graph": _graph_payload(incidents, events),
        }

    @app.get("/api/events")
    def events(
        source: str = Query(...),
        offset: int = Query(0, ge=0),
        limit: int = Query(50, ge=1, le=200),
        event_type: str | None = None,
        pid: int | None = Query(None, ge=1),
        path: str | None = None,
        source_event_id: str | None = None,
        source_context: str | None = None,
    ) -> dict[str, Any]:
        selected = get_source(source)
        records, malformed, errors = repository.events(selected)
        filtered = [
            event
            for event in records
            if not event_type or event.get("event_type") == event_type
        ]
        if pid is not None:
            filtered = [event for event in filtered if event.get("pid") == pid]
        if path:
            filtered = [event for event in filtered if path.lower() in str(event.get("path", "")).lower()]
        if source_event_id:
            filtered = [event for event in filtered if event.get("source_event_id") == source_event_id]
        if source_context:
            filtered = [event for event in filtered if source_context in str(event.get("source_context", ""))]
        return {
            "items": filtered[offset : offset + limit],
            "total": len(filtered),
            "offset": offset,
            "limit": limit,
            "source": _source_payload(selected, malformed=malformed, errors=errors),
        }

    @app.get("/api/events/{event_id}")
    def event_detail(event_id: str, source: str = Query(...)) -> dict[str, Any]:
        selected = get_source(source)
        records, _, _ = repository.events(selected)
        matches = [event for event in records if event.get("source_event_id") == event_id]
        if not matches:
            raise HTTPException(status_code=404, detail="Event not found")
        return {"source": _source_payload(selected), "event": matches[0]}

    @app.get("/api/timeline")
    def timeline(source: str = Query(...)) -> dict[str, Any]:
        selected = get_source(source)
        records, _, _ = repository.events(selected)
        points_by_basis: dict[str, Counter[str]] = {}
        for event in records:
            timestamp = _event_timestamp(event)
            if timestamp is None:
                continue
            basis, value = timestamp
            points = points_by_basis.setdefault(basis, Counter())
            bucket = int(value // (1_000_000_000 if basis == "kernel_monotonic" else 1))
            points[str(bucket)] += 1
        series = [
            {
                "timestamp_source": basis,
                "points": [
                    {"timestamp": key, "count": value}
                    for key, value in sorted(points.items())
                ],
            }
            for basis, points in sorted(points_by_basis.items())
        ]
        first = series[0] if len(series) == 1 else None
        return {
            "source": _source_payload(selected),
            "timestamp_source": first["timestamp_source"] if first else None,
            "points": first["points"] if first else [],
            "series": series,
            "limitations": (
                ["multiple timestamp bases; series are intentionally not combined"]
                if len(series) > 1
                else []
            ),
        }

    @app.post("/api/test-simulation")
    def test_simulation() -> dict[str, Any]:
        """Run the existing harmless in-memory scenario without OS side effects."""
        from collector.normalizer import EventNormalizer
        from ransomshield.integration import LiveDecisionPipeline
        from scripts.run_safe_simulation import scenario_events

        scenario_name, raw_events = scenario_events("benign_file_operations")
        normalizer = EventNormalizer(compute_entropy=False)
        pipeline = LiveDecisionPipeline(
            source_context=f"simulation:test:{scenario_name}"
        )
        records: list[dict[str, Any]] = []
        for index, raw_event in enumerate(raw_events, 1):
            event = normalizer.normalize(
                raw_event,
                source_context=f"simulation:test:{scenario_name}",
                occurrence_index=index,
            )
            pipeline.process_event(event)
            records.append(
                {
                    "event": event,
                    "decision": pipeline.last_record["decision"],
                    "correlation": pipeline.last_record["correlation"],
                    "supporting_events": pipeline.last_record["supporting_events"],
                }
            )
        return {
            "source": {
                "name": "simulation-test",
                "kind": "simulation",
                "label": "Safe in-memory test run",
            },
            "scenario": scenario_name,
            "records": records,
            "total_events": len(records),
            "decision_counts": {"ABSTAIN": len(records)},
            "detector_status": "unavailable",
            "side_effects": "none; existing harmless in-memory pipeline only",
        }

    return app


try:
    app = create_app()
except ValueError:
    app = FastAPI(title="RansomShield Evidence Dashboard", version="1.0")

    @app.get("/api/sources")
    def unconfigured_sources() -> dict[str, str]:
        raise HTTPException(
            status_code=503,
            detail="RSHIELD_DASHBOARD_SOURCES is not configured",
        )
