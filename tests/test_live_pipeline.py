from __future__ import annotations

import json

from ransomshield.decision.contract import PredictionRecord
from ransomshield.integration import LiveDecisionPipeline
from ransomshield.storage import IncidentStore


class StaticDetector:
    model_id = "test-detector"
    model_version = "test-v1"
    feature_schema_id = "schema-event-window-v1"

    def __init__(self, probability: float | None):
        self.probability = probability
        self.received = []

    def predict(self, features, events):
        self.received.append((features, list(events)))
        return PredictionRecord(
            sample_id="ignored-by-pipeline",
            baseline_label=1 if self.probability is not None else "unavailable",
            raw_score=self.probability,
            malicious_probability=self.probability,
            model_id=self.model_id,
            model_version=self.model_version,
            feature_schema_id=features.schema_id,
            inference_ms=0.1,
        )


def _event(
    timestamp: float,
    event_type: str = "FILE_WRITE",
    *,
    pid: int | None = 42,
    ppid: int | None = 7,
    process: str = "safe-test",
    path: str = "/tmp/sandbox/file.txt",
) -> dict:
    return {
        "timestamp": timestamp,
        "pid": pid,
        "ppid": ppid,
        "process": process,
        "exe": "/usr/bin/python",
        "event_type": event_type,
        "path": path,
        "bytes": 12,
        "success": True,
        "extra": {"entropy": 7.0},
    }


def test_unavailable_detector_reaches_policy_as_abstain(tmp_path):
    output = tmp_path / "incidents.jsonl"
    pipeline = LiveDecisionPipeline(store=IncidentStore(output))

    decision = pipeline.process_event(_event(100.0))

    assert decision.action == "ABSTAIN"
    record = json.loads(output.read_text(encoding="utf-8"))
    assert record["prediction"]["malicious_probability"] is None
    assert record["decision"]["action"] == "ABSTAIN"


def test_detector_receives_event_features_and_benign_policy_result(tmp_path):
    detector = StaticDetector(0.1)
    pipeline = LiveDecisionPipeline(detector=detector)

    decision = pipeline.process_event(_event(100.0))

    assert decision.action == "NO_ALERT"
    assert len(detector.received) == 1
    features, events = detector.received[0]
    assert features.schema_id == "schema-event-window-v1"
    assert features.values["file_modifications"] == 1.0
    assert events[0]["pid"] == 42


def test_suspicious_policy_is_advisory_without_containment(tmp_path):
    detector = StaticDetector(0.95)
    pipeline = LiveDecisionPipeline(detector=detector)

    decision = pipeline.process_event(_event(100.0))

    assert decision.action == "CONTAINMENT_RECOMMENDED"
    assert "Advisory recommendation only" in decision.explanation


def test_events_from_two_pids_are_isolated(tmp_path):
    detector = StaticDetector(0.1)
    pipeline = LiveDecisionPipeline(detector=detector, store=IncidentStore(tmp_path / "incidents.jsonl"))

    pipeline.process_event(_event(100.0, pid=101, path="/tmp/a"))
    pipeline.process_event(_event(101.0, pid=202, path="/tmp/b"))

    first_features, _ = detector.received[0]
    second_features, second_events = detector.received[1]
    assert first_features.values["observation_count"] == 1.0
    assert second_features.values["observation_count"] == 1.0
    assert {event["pid"] for event in second_events} == {202}


def test_process_a_features_do_not_change_when_process_b_arrives():
    detector = StaticDetector(0.1)
    pipeline = LiveDecisionPipeline(detector=detector)

    pipeline.process_event(_event(100.0, pid=101, path="/tmp/a"))
    pipeline.process_event(_event(101.0, pid=202, path="/tmp/b"))
    pipeline.process_event(_event(102.0, pid=101, path="/tmp/a"))

    first_features = detector.received[0][0]
    third_features = detector.received[2][0]
    assert third_features.values["observation_count"] == 2.0
    assert third_features.values["distinct_pids"] == 1.0
    assert third_features.values["distinct_files"] == 1.0
    assert first_features.values["distinct_pids"] == 1.0


def test_out_of_order_and_invalid_timestamps_remain_causal(tmp_path):
    detector = StaticDetector(0.1)
    output = tmp_path / "incidents.jsonl"
    pipeline = LiveDecisionPipeline(detector=detector, store=IncidentStore(output))

    pipeline.process_event(_event(102.0, pid=101, path="/tmp/current"))
    pipeline.process_event(_event(101.0, pid=101, path="/tmp/older"))
    pipeline.process_event(_event("not-a-time", pid=101, path="/tmp/invalid"))

    features, events = detector.received[1]
    assert features.values["observation_count"] == 1.0
    assert [event["path"] for event in events] == ["/tmp/older"]
    invalid_record = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
    assert invalid_record["evidence"]["observation_count"] == 0
    assert "no valid event timestamps" in invalid_record["evidence"]["limitations"]


def test_missing_pid_is_isolated_and_explicitly_limited(tmp_path):
    detector = StaticDetector(0.1)
    output = tmp_path / "incidents.jsonl"
    pipeline = LiveDecisionPipeline(detector=detector, store=IncidentStore(output))

    pipeline.process_event(_event(100.0, pid=101, path="/tmp/a"))
    pipeline.process_event(_event(101.0, pid=None, ppid=None, path="/tmp/missing"))

    _, events = detector.received[1]
    assert len(events) == 1
    assert events[0]["pid"] is None
    record = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
    assert "missing pid; event isolated without process association" in record["evidence"]["limitations"]


def test_possible_pid_reuse_starts_a_conservative_generation(tmp_path):
    detector = StaticDetector(0.1)
    output = tmp_path / "incidents.jsonl"
    pipeline = LiveDecisionPipeline(detector=detector, store=IncidentStore(output))

    pipeline.process_event(_event(100.0, pid=101, process="first", path="/tmp/first"))
    pipeline.process_event(_event(101.0, pid=101, process="second", path="/tmp/second"))

    _, events = detector.received[1]
    assert [event["path"] for event in events] == ["/tmp/second"]
    record = json.loads(output.read_text(encoding="utf-8").splitlines()[-1])
    assert "possible PID reuse or identity change; isolated into a new PID generation" in (
        record["evidence"]["limitations"]
    )
