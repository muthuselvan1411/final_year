from __future__ import annotations

import json

from collector.dashboard import TelemetryDashboard
from collector.normalizer import EventNormalizer
from ransomshield.integration import LiveDecisionPipeline
from ransomshield.storage import IncidentStore
from scripts.inspect_incident import find_incident


def _raw(timestamp: float, path: str, event_type: str = "FILE_WRITE") -> dict:
    return {
        "timestamp": timestamp,
        "pid": 44,
        "ppid": 1,
        "process": "fixture",
        "exe": "/usr/bin/fixture",
        "event_type": event_type,
        "path": path,
        "success": None,
        "extra": {"success_evidence": "unavailable"},
    }


def test_normalizer_assigns_scoped_ids_and_preserves_supplied_id() -> None:
    normalizer = EventNormalizer(compute_entropy=False)
    first = normalizer.normalize(
        _raw(1.0, "/tmp/a"),
        source_context="replay:/tmp/capture.jsonl",
        occurrence_index=1,
    )
    duplicate = normalizer.normalize(
        _raw(1.0, "/tmp/a"),
        source_context="replay:/tmp/capture.jsonl",
        occurrence_index=2,
    )
    supplied = normalizer.normalize(
        {**_raw(2.0, "/tmp/b"), "source_event_id": "sensor-17"},
        source_context="live:/tmp/events.jsonl",
        occurrence_index=1,
    )

    assert first["source_event_id"] != duplicate["source_event_id"]
    assert first["source_context"].startswith("replay:")
    assert supplied["source_event_id"] == "sensor-17"


def test_incident_persists_exact_causal_supporting_events(tmp_path) -> None:
    normalizer = EventNormalizer(compute_entropy=False)
    events = [
        normalizer.normalize(
            _raw(10.0, "/tmp/a"),
            source_context="simulation:fixture",
            occurrence_index=1,
        ),
        normalizer.normalize(
            _raw(10.5, "/tmp/b", "FILE_RENAME"),
            source_context="simulation:fixture",
            occurrence_index=2,
        ),
        normalizer.normalize(
            _raw(11.0, "/tmp/future"),
            source_context="simulation:fixture",
            occurrence_index=3,
        ),
    ]
    output = tmp_path / "incidents.jsonl"
    pipeline = LiveDecisionPipeline(store=IncidentStore(output))
    pipeline.process_event(events[0])
    pipeline.process_event(events[1])
    pipeline.process_event(events[2])

    record = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
    ids = [item["source_event_id"] for item in record["supporting_events"]]
    assert ids == [
        events[0]["source_event_id"],
        events[1]["source_event_id"],
        events[2]["source_event_id"],
    ]
    assert record["evidence"]["supporting_event_ids"] == ids
    assert record["evidence"]["supporting_event_count"] == 3
    assert record["evidence"]["feature_schema_id"] == "schema-event-window-v1"
    assert record["triggering_event_id"] == events[2]["source_event_id"]
    assert record["triggering_source_context"] == "simulation:fixture"
    assert record["provenance"]["supporting_event_ids"] == ids
    assert record["provenance"]["supporting_event_count"] == 3
    assert record["provenance"]["window_start"] is not None
    assert record["provenance"]["window_end"] is not None
    assert record["provenance"]["timestamp_source"] == "event_timestamp"
    assert record["prediction"]["malicious_probability"] is None
    assert record["decision"]["action"] == "ABSTAIN"


def test_open_close_rename_delete_window_matches_feature_contributors(tmp_path) -> None:
    normalizer = EventNormalizer(compute_entropy=False)
    raw_events = [
        _raw(20.0, "/tmp/file.txt", "FILE_OPEN"),
        _raw(20.1, "/tmp/file.txt", "FILE_CLOSE"),
        {
            **_raw(20.2, "/tmp/renamed.txt", "FILE_RENAME"),
            "extra": {
                "old_path": "/tmp/file.txt",
                "success_evidence": "unavailable",
            },
        },
        _raw(20.3, "/tmp/renamed.txt", "FILE_DELETE"),
    ]
    events = [
        normalizer.normalize(
            event,
            source_context="replay:fixture",
            occurrence_index=index,
        )
        for index, event in enumerate(raw_events, 1)
    ]
    output = tmp_path / "incidents.jsonl"
    pipeline = LiveDecisionPipeline(store=IncidentStore(output))
    for event in events:
        pipeline.process_event(event)

    record = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
    ids = [event["source_event_id"] for event in record["supporting_events"]]
    assert ids == [event["source_event_id"] for event in events]
    assert record["evidence"]["supporting_event_ids"] == ids
    assert record["features"]["values"]["observation_count"] == 4.0
    assert record["features"]["values"]["rename_count"] == 1.0
    assert record["features"]["values"]["delete_count"] == 1.0
    rename_support = next(
        event
        for event in record["supporting_events"]
        if event["event_type"] == "FILE_RENAME"
    )
    assert rename_support["extra"]["old_path"] == "/tmp/file.txt"


def test_future_and_invalid_timestamp_events_are_not_supporting_evidence(tmp_path) -> None:
    normalizer = EventNormalizer(compute_entropy=False)
    current = normalizer.normalize(
        _raw(30.0, "/tmp/current"),
        source_context="replay:fixture",
        occurrence_index=1,
    )
    future = normalizer.normalize(
        _raw(31.0, "/tmp/future"),
        source_context="replay:fixture",
        occurrence_index=2,
    )
    invalid = {
        **_raw("not-a-time", "/tmp/invalid"),
        "source_event_id": "invalid-event",
        "source_context": "replay:fixture",
    }
    output = tmp_path / "incidents.jsonl"
    pipeline = LiveDecisionPipeline(store=IncidentStore(output))
    pipeline.process_event(current)
    pipeline.process_event(future)
    pipeline.process_event(invalid)

    records = [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    future_ids = records[1]["evidence"]["supporting_event_ids"]
    assert future_ids == [current["source_event_id"], future["source_event_id"]]
    assert invalid["source_event_id"] not in future_ids
    invalid_record = records[2]
    assert invalid_record["evidence"]["supporting_event_ids"] == []
    assert invalid_record["features"]["values"]["observation_count"] == 0.0
    assert invalid_record["prediction"]["malicious_probability"] is None
    assert invalid_record["decision"]["action"] == "ABSTAIN"


def test_single_event_rate_and_burst_ratio_follow_feature_definitions() -> None:
    normalizer = EventNormalizer(compute_entropy=False)
    event = normalizer.normalize(
        _raw(40.0, "/tmp/one", "FILE_RENAME"),
        source_context="replay:fixture",
        occurrence_index=1,
    )
    pipeline = LiveDecisionPipeline()
    pipeline.process_event(event)

    values = pipeline.last_record["features"]["values"]
    assert values["event_rate"] == 0.0
    assert values["burst_ratio"] == 1.0


def test_dashboard_can_show_persisted_incident_and_malformed_lines(tmp_path) -> None:
    path = tmp_path / "incidents.jsonl"
    path.write_text(
        "not-json\n"
        + json.dumps(
            {
                "event": {"source_event_id": "event-1"},
                "evidence": {
                    "supporting_event_count": 1,
                    "feature_schema_id": "schema-event-window-v1",
                    "source_context": "simulation:fixture",
                },
                "decision": {"action": "ABSTAIN"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    dashboard = TelemetryDashboard(incident_path=path)
    assert len(dashboard.recent_incidents) == 1
    dashboard.render()


def test_incident_detail_lookup_skips_malformed_lines(tmp_path) -> None:
    path = tmp_path / "incidents.jsonl"
    path.write_text(
        "bad\n"
        + json.dumps(
            {"event": {"source_event_id": "event-2"}, "decision": {"action": "ABSTAIN"}}
        )
        + "\n",
        encoding="utf-8",
    )
    assert find_incident(path, "event-2")["decision"]["action"] == "ABSTAIN"
