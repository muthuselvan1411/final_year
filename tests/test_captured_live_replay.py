from __future__ import annotations

import json

import pytest

from collector.normalizer import EventNormalizer
from ransomshield.integration import LiveDecisionPipeline
from ransomshield.storage import IncidentStore, StorageError
from schema.event_schema import NormalizedEvent


CAPTURED_EVENTS = (
    {
        "timestamp": 1792481020.200291,
        "timestamp_ns": 2333862114214,
        "receive_timestamp": 1792481020.200291,
        "pid": 5827,
        "ppid": 5825,
        "process": "bash",
        "exe": "bash",
        "event_type": "FILE_OPEN",
        "path": "/tmp/ransomshield-live-test/files/test.txt",
        "bytes": 0,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "success": None,
        "extra": {
            "success_evidence": "unavailable",
            "timestamp_source": "userspace_receive",
        },
    },
    {
        "timestamp": 1792481020.200307,
        "timestamp_ns": 2333862138772,
        "receive_timestamp": 1792481020.200307,
        "pid": 5827,
        "ppid": 5825,
        "process": "bash",
        "exe": "bash",
        "event_type": "FILE_CLOSE",
        "path": "/tmp/ransomshield-live-test/files/test.txt",
        "bytes": 0,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "success": None,
        "extra": {
            "success_evidence": "unavailable",
            "timestamp_source": "userspace_receive",
        },
    },
    {
        "timestamp": 1792481020.240609,
        "timestamp_ns": 2333902453707,
        "receive_timestamp": 1792481020.240609,
        "pid": 5956,
        "ppid": 5827,
        "process": "mv",
        "exe": "mv",
        "event_type": "FILE_RENAME",
        "path": "/tmp/ransomshield-live-test/files/renamed.txt",
        "bytes": 0,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "success": None,
        "extra": {
            "old_path": "/tmp/ransomshield-live-test/files/test.txt",
            "success_evidence": "unavailable",
            "timestamp_source": "userspace_receive",
        },
    },
    {
        "timestamp": 1792481020.247274,
        "timestamp_ns": 2333909112797,
        "receive_timestamp": 1792481020.247274,
        "pid": 5962,
        "ppid": 5827,
        "process": "rm",
        "exe": "rm",
        "event_type": "FILE_DELETE",
        "path": "/tmp/ransomshield-live-test/files/renamed.txt",
        "bytes": 0,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "success": None,
        "extra": {
            "success_evidence": "unavailable",
            "timestamp_source": "userspace_receive",
        },
    },
)


def test_captured_event_shapes_survive_normalization_and_schema_round_trip():
    normalizer = EventNormalizer(compute_entropy=False)

    normalized = [normalizer.normalize(event) for event in CAPTURED_EVENTS]
    rename = normalized[2]
    restored = NormalizedEvent.from_dict(rename).to_dict()

    assert {event["event_type"] for event in normalized} == {
        "FILE_OPEN",
        "FILE_CLOSE",
        "FILE_RENAME",
        "FILE_DELETE",
    }
    assert rename["timestamp_ns"] == 2333902453707
    assert rename["receive_timestamp"] == 1792481020.240609
    assert rename["success"] is None
    assert rename["path"].endswith("/renamed.txt")
    assert rename["process"] == "mv"
    assert rename["pid"] == 5956
    assert restored["extra"]["old_path"].endswith("/test.txt")
    assert restored["success"] is None
    assert restored["timestamp_ns"] == 2333902453707


def test_captured_replay_abstains_and_persists_each_incident(tmp_path):
    output = tmp_path / "captured-incidents.jsonl"
    pipeline = LiveDecisionPipeline(store=IncidentStore(output))
    normalizer = EventNormalizer(compute_entropy=False)

    decisions = [
        pipeline.process_event(normalizer.normalize(event))
        for event in CAPTURED_EVENTS
    ]

    assert [decision.action for decision in decisions] == ["ABSTAIN"] * 4
    records = [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    assert len(records) == 4
    assert all(record["prediction"]["malicious_probability"] is None for record in records)
    assert all(record["decision"]["action"] == "ABSTAIN" for record in records)
    rename_record = records[2]
    assert rename_record["event"]["extra"]["old_path"].endswith("/test.txt")
    assert rename_record["event"]["success"] is None


@pytest.mark.parametrize("pid", [None, "not-a-pid", 0, -1])
def test_invalid_process_identifiers_are_isolated_without_benign_inference(
    pid, tmp_path
):
    output = tmp_path / "invalid-process-incidents.jsonl"
    pipeline = LiveDecisionPipeline(store=IncidentStore(output))
    event = dict(CAPTURED_EVENTS[0], pid=pid)

    decision = pipeline.process_event(event)

    assert decision.action == "ABSTAIN"
    record = json.loads(output.read_text(encoding="utf-8"))
    assert record["prediction"]["malicious_probability"] is None
    assert record["decision"]["action"] == "ABSTAIN"
    assert any(
        "pid" in limitation for limitation in record["evidence"]["limitations"]
    )


def test_incident_store_reports_persistence_errors(tmp_path):
    destination = tmp_path / "not-a-file"
    destination.mkdir()

    with pytest.raises(StorageError):
        IncidentStore(destination).append({"record_type": "test"})
