from __future__ import annotations

import json

import pytest

from scripts.replay_live_jsonl import replay_jsonl


def _captured_event(event_type: str = "FILE_OPEN") -> dict:
    return {
        "timestamp": 100.0,
        "timestamp_ns": 123456789,
        "receive_timestamp": 100.001,
        "pid": 42,
        "ppid": 7,
        "process": "bash",
        "exe": "bash",
        "event_type": event_type,
        "path": "/tmp/replay/test.txt",
        "bytes": 0,
        "dst_ip": None,
        "dst_port": None,
        "protocol": None,
        "success": None,
        "extra": {
            "success_evidence": "unavailable",
            "timestamp_source": "userspace_receive",
            **(
                {"old_path": "/tmp/replay/old.txt"}
                if event_type == "FILE_RENAME"
                else {}
            ),
        },
    }


def test_replay_reports_partial_failures_and_persists_abstentions(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text(
        "\n".join(
            [
                json.dumps(_captured_event()),
                "{not-json}",
                json.dumps(_captured_event("FILE_RENAME")),
                json.dumps({"timestamp": 101.0, "pid": None, "ppid": None}),
                json.dumps(["not", "an", "event"]),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    summary = replay_jsonl(source, tmp_path / "output")

    assert summary["input_lines"] == 5
    assert summary["valid_json_records"] == 4
    assert summary["malformed_json_records"] == 1
    assert summary["non_object_records"] == 1
    assert summary["processed_events"] == 3
    assert summary["normalization_failures"] == 0
    assert summary["decision_counts"] == {"ABSTAIN": 3}
    assert summary["abstentions"] == 3
    assert summary["missing_or_invalid_pid"] == 1
    assert summary["missing_or_invalid_ppid"] == 1
    assert summary["incident_records_written"] == 3

    records = [
        json.loads(line)
        for line in (tmp_path / "output" / "incidents.jsonl").read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    assert records[0]["prediction"]["malicious_probability"] is None
    assert records[1]["event"]["extra"]["old_path"].endswith("/old.txt")
    assert records[0]["event"]["success"] is None


def test_replay_refuses_stale_output(tmp_path):
    source = tmp_path / "events.jsonl"
    source.write_text(json.dumps(_captured_event()) + "\n", encoding="utf-8")
    output = tmp_path / "output"
    output.mkdir()
    (output / "replay_summary.json").write_text("existing\n", encoding="utf-8")

    with pytest.raises(FileExistsError):
        replay_jsonl(source, output)
