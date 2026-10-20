from __future__ import annotations

import json

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient

from dashboard.api import DashboardSource, create_app


def _app(tmp_path):
    incidents = tmp_path / "incidents.jsonl"
    events = tmp_path / "events.jsonl"
    event = {
        "timestamp": 100.0,
        "timestamp_ns": None,
        "pid": 42,
        "ppid": 1,
        "process": "fixture",
        "event_type": "FILE_RENAME",
        "path": "/tmp/new",
        "source_event_id": "event-1",
        "source_context": "replay:fixture",
        "success": None,
        "extra": {"old_path": "/tmp/old"},
    }
    incident = {
        "event": event,
        "supporting_events": [event],
        "supporting_event_ids": ["event-1"],
        "decision": {"action": "ABSTAIN"},
        "prediction": {"malicious_probability": None},
        "evidence": {
            "detector_status": "unavailable",
            "feature_schema_id": "schema-event-window-v1",
            "decision_basis": "ABSTAIN: no validated detector probability available",
        },
        "correlation": {
            "schema_id": "schema-behavior-correlation-v1",
            "supporting_event_ids": ["event-1"],
            "relationships": [],
        },
    }
    events.write_text(json.dumps(event) + "\nmalformed\n", encoding="utf-8")
    incidents.write_text(json.dumps(incident) + "\n", encoding="utf-8")
    app = create_app(
        {
            "fixture": DashboardSource(
                "fixture", "replay", incidents, events, "Fixture replay"
            )
        }
    )
    return TestClient(app)


def test_summary_preserves_source_counts_and_abstain(tmp_path):
    client = _app(tmp_path)
    response = client.get("/api/summary", params={"source": "fixture"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_events"] == 1
    assert payload["incidents_recorded"] == 1
    assert payload["abstain_count"] == 1
    assert payload["source"]["kind"] == "replay"
    assert payload["malformed_records"] == 1


def test_pagination_filters_and_traceability(tmp_path):
    client = _app(tmp_path)
    response = client.get(
        "/api/incidents",
        params={"source": "fixture", "decision": "ABSTAIN", "limit": 1},
    )
    assert response.status_code == 200
    assert response.json()["items"][0]["event"]["source_event_id"] == "event-1"
    event = client.get(
        "/api/events/event-1", params={"source": "fixture"}
    )
    assert event.status_code == 200
    assert event.json()["event"]["success"] is None
    correlation = client.get(
        "/api/incidents/0/correlation", params={"source": "fixture"}
    )
    assert correlation.status_code == 200
    assert correlation.json()["correlation"]["schema_id"] == "schema-behavior-correlation-v1"


def test_missing_store_is_clear_error(tmp_path):
    app = create_app(
        {
            "missing": DashboardSource(
                "missing", "simulation", tmp_path / "missing.jsonl"
            )
        }
    )
    response = TestClient(app).get("/api/summary", params={"source": "missing"})
    assert response.status_code == 503
    assert "Configured store is missing" in response.json()["detail"]


def test_safe_dashboard_test_uses_real_pipeline_and_abstains(tmp_path):
    client = _app(tmp_path)
    response = client.post("/api/test-simulation")
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_events"] == 4
    assert payload["decision_counts"] == {"ABSTAIN": 4}
    assert payload["detector_status"] == "unavailable"
    assert payload["records"][-1]["event"]["source_context"].startswith(
        "simulation:test:"
    )
    assert payload["records"][-1]["correlation"]["schema_id"] == (
        "schema-behavior-correlation-v1"
    )
