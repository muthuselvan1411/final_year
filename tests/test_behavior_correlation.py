from __future__ import annotations

import json

from collector.collector import build_live_source_context
from ransomshield.integration import LiveDecisionPipeline
from ransomshield.storage import IncidentStore
from ransomshield.telemetry.behavior_correlation import (
    CORRELATION_SCHEMA_ID,
    BehaviorCorrelationEngine,
)


def _event(
    timestamp: float,
    event_type: str,
    *,
    event_id: str,
    context: str = "capture:one",
    pid: int | None = 10,
    ppid: int | None = 1,
    path: str | None = None,
    timestamp_ns: int | None = None,
    dst_ip: str | None = None,
) -> dict:
    return {
        "timestamp": timestamp,
        "timestamp_ns": timestamp_ns,
        "pid": pid,
        "ppid": ppid,
        "process": f"proc-{pid}",
        "exe": f"/bin/proc-{pid}",
        "event_type": event_type,
        "path": path,
        "dst_ip": dst_ip,
        "dst_port": 443 if dst_ip else None,
        "success": None,
        "source_event_id": event_id,
        "source_context": context,
        "extra": (
            {"old_path": "/tmp/old.txt"}
            if event_type == "FILE_RENAME"
            else {}
        ),
    }


def test_parent_child_file_network_correlation_has_exact_provenance() -> None:
    engine = BehaviorCorrelationEngine(window_seconds=10.0)
    parent = _event(
        100.0,
        "NET_CONNECT",
        event_id="parent-net",
        pid=10,
        ppid=1,
        dst_ip="192.0.2.10",
    )
    child = _event(
        101.0,
        "FILE_RENAME",
        event_id="child-rename",
        pid=20,
        ppid=10,
        path="/tmp/new.txt",
    )

    engine.observe(parent)
    result = engine.observe(child)

    assert result.schema_id == CORRELATION_SCHEMA_ID
    assert result.supporting_event_ids == ("parent-net", "child-rename")
    assert result.feature_values["related_process_count"] == 2.0
    assert result.feature_values["parent_child_relationship_count"] == 1.0
    assert result.feature_values["network_activity_count"] == 1.0
    assert result.feature_values["rename_count"] == 1.0
    assert result.feature_values["file_network_temporal_relation"] == 1.0
    assert {item.relationship_type for item in result.relationships} >= {
        "process_spawned_by",
        "process_made_network_connection_attempt",
        "file_rename_observed",
    }
    assert all(item.details.get("success") is None for item in result.relationships
               if item.relationship_type == "process_made_network_connection_attempt")
    for relationship in result.relationships:
        if relationship.relationship_type != "event_order":
            assert relationship.source_entity_id
            assert relationship.target_entity_id
            assert relationship.source_entity_id != relationship.target_entity_id


def test_unrelated_processes_and_contexts_are_not_correlated() -> None:
    engine = BehaviorCorrelationEngine(window_seconds=10.0)
    engine.observe(_event(100.0, "FILE_OPEN", event_id="parent", pid=10, ppid=1))
    unrelated = engine.observe(
        _event(101.0, "FILE_DELETE", event_id="unrelated", pid=30, ppid=999)
    )
    other_context = engine.observe(
        _event(
            102.0,
            "FILE_WRITE",
            event_id="other-context",
            pid=20,
            ppid=10,
            context="capture:two",
        )
    )

    assert unrelated.supporting_event_ids == ("unrelated",)
    assert unrelated.feature_values["related_process_count"] == 1.0
    assert other_context.supporting_event_ids == ("other-context",)
    assert other_context.capture_context == "capture:two"


def test_kernel_ordering_excludes_future_invalid_and_preserves_duplicates() -> None:
    engine = BehaviorCorrelationEngine(window_seconds=2.0)
    engine.observe(
        _event(
            100.0,
            "FILE_OPEN",
            event_id="duplicate",
            pid=10,
            timestamp_ns=1_000_000_000,
        )
    )
    engine.observe(
        _event(
            99.0,
            "FILE_CLOSE",
            event_id="duplicate",
            pid=10,
            timestamp_ns=1_500_000_000,
        )
    )
    engine.observe(
        _event(
            98.0,
            "FILE_DELETE",
            event_id="invalid",
            pid=10,
            timestamp_ns=None,
        )
    )
    result = engine.observe(
        _event(
            97.0,
            "FILE_RENAME",
            event_id="current",
            pid=10,
            timestamp_ns=2_000_000_000,
        )
    )

    assert result.timestamp_source == "kernel_monotonic"
    assert result.supporting_event_ids == ("duplicate", "current")
    assert "invalid" not in result.supporting_event_ids
    assert result.window_start == 1_000_000_000
    assert result.window_end == 2_000_000_000
    assert any("without kernel monotonic" in item for item in result.limitations)


def test_timestamp_basis_never_mixes_kernel_and_wall_clock_events() -> None:
    engine = BehaviorCorrelationEngine(window_seconds=10.0)
    engine.observe(
        _event(
            100.0,
            "FILE_OPEN",
            event_id="kernel",
            timestamp_ns=1_000_000_000,
        )
    )
    wall_clock = engine.observe(
        _event(
            101.0,
            "FILE_CLOSE",
            event_id="wall",
            timestamp_ns=None,
        )
    )

    assert wall_clock.timestamp_source == "event_timestamp"
    assert wall_clock.timestamp_unit == "seconds"
    assert wall_clock.supporting_event_ids == ("wall",)
    assert any("kernel monotonic timestamps excluded" in item for item in wall_clock.limitations)


def test_live_source_context_is_stable_per_session_and_unique_between_sessions(
    tmp_path,
) -> None:
    output = tmp_path / "events.jsonl"
    first_session = build_live_source_context(output, "session-one")
    same_session = build_live_source_context(output, "session-one")
    second_session = build_live_source_context(output, "session-two")

    assert first_session == same_session
    assert first_session.startswith("live:")
    assert first_session != second_session

    engine = BehaviorCorrelationEngine()
    first = engine.observe(
        _event(100.0, "FILE_OPEN", event_id="first", context=first_session)
    )
    second = engine.observe(
        _event(101.0, "FILE_CLOSE", event_id="second", context=second_session)
    )
    assert first.capture_context == first_session
    assert second.capture_context == second_session
    assert second.supporting_event_ids == ("second",)


def test_missing_identity_or_timestamp_is_explicit_and_isolated() -> None:
    engine = BehaviorCorrelationEngine()
    missing_pid = engine.observe(
        _event(
            100.0,
            "FILE_DELETE",
            event_id="missing-pid",
            pid=None,
            ppid=None,
        )
    )
    invalid_time = engine.observe(
        _event(
            float("nan"),
            "FILE_OPEN",
            event_id="invalid-time",
            pid=10,
        )
    )

    assert missing_pid.supporting_event_ids == ("missing-pid",)
    assert "missing or invalid triggering pid" in " ".join(missing_pid.limitations)
    assert missing_pid.capture_context == "capture:one"
    assert invalid_time.supporting_event_ids == ()
    assert "no valid causal timestamp" in " ".join(invalid_time.limitations)


def test_duplicate_delivery_is_ignored_but_distinct_occurrences_are_counted() -> None:
    engine = BehaviorCorrelationEngine()
    original = _event(100.0, "FILE_WRITE", event_id="same", path="/tmp/a")
    duplicate = dict(original)
    distinct = _event(101.0, "FILE_WRITE", event_id="different", path="/tmp/a")

    engine.observe(original)
    duplicate_result = engine.observe(duplicate)
    distinct_result = engine.observe(distinct)

    assert duplicate_result.feature_values["observation_count"] == 1.0
    assert duplicate_result.duplicate_event_ids == ("same",)
    assert "duplicate delivery ignored" in " ".join(duplicate_result.limitations)
    assert distinct_result.feature_values["observation_count"] == 2.0
    assert distinct_result.feature_values["repeated_file_paths"] == 1.0


def test_conflicting_payload_for_same_id_is_excluded_and_audited() -> None:
    engine = BehaviorCorrelationEngine()
    engine.observe(_event(100.0, "FILE_WRITE", event_id="same", path="/tmp/a"))
    result = engine.observe(
        _event(101.0, "FILE_DELETE", event_id="same", path="/tmp/b")
    )

    assert result.feature_values["observation_count"] == 1.0
    assert result.conflicting_event_ids == ("same",)
    assert result.conflicting_event_details[0]["conflicting_event"]["path"] == "/tmp/b"
    assert "conflicting payload excluded" in " ".join(result.limitations)


def test_state_is_bounded_and_pipeline_persists_correlation_without_changing_abstain(
    tmp_path,
) -> None:
    output = tmp_path / "incidents.jsonl"
    pipeline = LiveDecisionPipeline(store=IncidentStore(output), window_seconds=1.0)
    pipeline.process_event(
        _event(100.0, "FILE_OPEN", event_id="old", pid=10, ppid=1)
    )
    pipeline.process_event(
        _event(102.0, "FILE_DELETE", event_id="current", pid=10, ppid=1)
    )

    assert pipeline.last_record["correlation"]["supporting_event_ids"] == ("current",)
    assert pipeline.last_record["correlation"]["schema_id"] == CORRELATION_SCHEMA_ID
    assert pipeline.last_record["prediction"]["malicious_probability"] is None
    assert pipeline.last_record["decision"]["action"] == "ABSTAIN"
    persisted = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
    assert persisted["evidence"]["correlation_schema_id"] == CORRELATION_SCHEMA_ID
    assert persisted["evidence"]["correlation_supporting_event_ids"] == ["current"]


def test_replay_is_deterministic_for_same_capture_and_configuration() -> None:
    events = [
        _event(100.0, "NET_CONNECT", event_id="net", pid=10, dst_ip="192.0.2.1"),
        _event(
            100.5,
            "FILE_RENAME",
            event_id="rename",
            pid=20,
            ppid=10,
            path="/tmp/new",
        ),
    ]

    def run() -> dict:
        engine = BehaviorCorrelationEngine(window_seconds=2.0)
        engine.observe(events[0])
        return engine.observe(events[1]).to_dict()

    assert run() == run()


def test_max_event_and_context_limits_expire_state() -> None:
    engine = BehaviorCorrelationEngine(
        window_seconds=10.0,
        max_events=1,
        max_contexts=1,
    )
    engine.observe(_event(100.0, "FILE_OPEN", event_id="old"))
    engine.observe(
        _event(
            101.0,
            "FILE_DELETE",
            event_id="other-context",
            context="capture:two",
        )
    )
    current = engine.observe(
        _event(102.0, "FILE_CLOSE", event_id="current", context="capture:one")
    )

    assert current.supporting_event_ids == ("current",)

    bounded_audit = BehaviorCorrelationEngine(max_events=1)
    bounded_audit.observe(_event(100.0, "FILE_OPEN", event_id="same"))
    bounded_audit.observe(_event(101.0, "FILE_DELETE", event_id="same", path="/tmp/1"))
    bounded_audit.observe(_event(102.0, "FILE_DELETE", event_id="same", path="/tmp/2"))
    result = bounded_audit.observe(
        _event(103.0, "FILE_DELETE", event_id="same", path="/tmp/3")
    )
    assert len(result.conflicting_event_details) <= 1
