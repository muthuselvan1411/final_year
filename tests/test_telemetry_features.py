import pytest

from ransomshield.telemetry.event_features import extract_event_window_features
from ransomshield.telemetry.process import build_process_context
from ransomshield.telemetry.temporal import extract_temporal_features


def test_temporal_features_are_sorted_and_causal() -> None:
    features = extract_temporal_features(
        [
            {"timestamp": 3.0, "event_type": "FILE_DELETE", "path": "b"},
            {"timestamp": 1.0, "event_type": "FILE_WRITE", "path": "a", "score": 0.9},
            {"timestamp": 2.0, "event_type": "FILE_WRITE", "path": "a", "score": 0.8},
        ],
        window_seconds=5.0,
        score_threshold=0.5,
    )
    assert features.observation_count == 3
    assert features.file_modifications == 2
    assert features.delete_count == 1
    assert features.distinct_files == 2
    assert features.repeated_files == 1
    assert features.temporal_consistency == 1.0


def test_temporal_features_report_missing_timestamps() -> None:
    features = extract_temporal_features([{"event_type": "FILE_WRITE"}])
    assert features.observation_count == 0
    assert features.temporal_consistency is None
    assert features.unavailable_reason == "no valid event timestamps"


def test_temporal_features_ignore_events_after_decision_time() -> None:
    features = extract_temporal_features(
        [
            {"timestamp": 1.0, "event_type": "FILE_WRITE", "path": "a"},
            {"timestamp": 9.0, "event_type": "FILE_DELETE", "path": "a"},
        ],
        window_seconds=10.0,
        decision_time=2.0,
    )
    assert features.observation_count == 1
    assert features.delete_count == 0


def test_two_event_rate_uses_elapsed_seconds_and_repeated_path_counts() -> None:
    features = extract_temporal_features(
        [
            {"timestamp": 1792481020.211776, "event_type": "FILE_OPEN", "path": "/tmp/file"},
            {"timestamp": 1792481020.211935, "event_type": "FILE_CLOSE", "path": "/tmp/file"},
        ],
        window_seconds=10.0,
    )
    assert features.observation_count == 2
    expected_rate = 2 / (1792481020.211935 - 1792481020.211776)
    assert features.event_rate == pytest.approx(expected_rate)
    assert features.distinct_files == 1
    assert features.repeated_files == 1
    assert features.burst_ratio == 1.0


def test_zero_duration_rate_is_unavailable_but_burst_ratio_is_defined() -> None:
    features = extract_event_window_features(
        [{"timestamp": 5.0, "event_type": "FILE_RENAME", "path": "/tmp/file"}]
    )
    assert features.values["observation_count"] == 1.0
    assert features.values["event_rate"] == 0.0
    assert features.available["event_rate"] is False
    assert features.values["burst_ratio"] == 1.0
    assert features.available["burst_ratio"] is True


def test_very_short_duration_rate_remains_finite_and_order_independent() -> None:
    events = [
        {"timestamp": 2.000001, "event_type": "FILE_WRITE", "path": "b"},
        {"timestamp": 2.0, "event_type": "FILE_WRITE", "path": "a"},
    ]
    features = extract_temporal_features(events, window_seconds=1.0)
    assert features.window_start == 2.0
    assert features.window_end == 2.000001
    assert features.event_rate == pytest.approx(2 / 0.000001)
    assert features.distinct_files == 2
    assert features.repeated_files == 0


def test_invalid_and_future_timestamps_do_not_enter_window() -> None:
    features = extract_temporal_features(
        [
            {"timestamp": "invalid", "event_type": "FILE_WRITE", "path": "bad"},
            {"timestamp": 1.0, "event_type": "FILE_WRITE", "path": "current"},
            {"timestamp": 2.0, "event_type": "FILE_DELETE", "path": "future"},
        ],
        decision_time=1.5,
    )
    assert features.observation_count == 1
    assert features.delete_count == 0
    assert features.distinct_files == 1


def test_captured_open_close_rates_match_their_recorded_timestamps() -> None:
    first = extract_temporal_features(
        [
            {"timestamp": 1792481020.200291, "event_type": "FILE_OPEN", "path": "x"},
            {"timestamp": 1792481020.200307, "event_type": "FILE_CLOSE", "path": "x"},
        ]
    )
    second = extract_temporal_features(
        [
            {"timestamp": 1792481020.211776, "event_type": "FILE_OPEN", "path": "x"},
            {"timestamp": 1792481020.211935, "event_type": "FILE_CLOSE", "path": "x"},
        ]
    )
    assert first.event_rate == pytest.approx(
        2 / (1792481020.200307 - 1792481020.200291)
    )
    assert second.event_rate == pytest.approx(
        2 / (1792481020.211935 - 1792481020.211776)
    )


def test_process_context_does_not_invent_single_process() -> None:
    context = build_process_context(
        [
            {"timestamp": 2.0, "pid": 10, "ppid": 1, "process": "a"},
            {"timestamp": 1.0, "pid": 11, "ppid": 1, "process": "b"},
        ]
    )
    assert context.process_id is None
    assert context.parent_process_id == 1
    assert context.ordered is False
    assert "multiple process identifiers in event window" in context.limitations


def test_mixed_process_window_is_not_single_process_evidence() -> None:
    context = build_process_context(
        [
            {"timestamp": 1.0, "pid": 10, "ppid": 1, "process": "a"},
            {"timestamp": 2.0, "pid": 11, "ppid": 1, "process": "b"},
        ]
    )
    assert context.process_id is None
    assert "multiple process identifiers in event window" in context.limitations
