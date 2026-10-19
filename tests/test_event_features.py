from ransomshield.telemetry.event_features import (
    EVENT_FEATURE_NAMES,
    EVENT_FEATURE_SCHEMA_ID,
    extract_event_window_features,
)


def test_event_feature_schema_is_versioned_and_stable() -> None:
    features = extract_event_window_features([])
    assert features.schema_id == EVENT_FEATURE_SCHEMA_ID
    assert list(features.values) == list(EVENT_FEATURE_NAMES)
    assert len(features.vector()) == len(EVENT_FEATURE_NAMES)


def test_event_features_exclude_future_events() -> None:
    features = extract_event_window_features(
        [
            {"timestamp": 1.0, "pid": 10, "ppid": 1, "event_type": "FILE_WRITE", "path": "a"},
            {"timestamp": 3.0, "pid": 10, "ppid": 1, "event_type": "FILE_DELETE", "path": "a"},
        ],
        decision_time=2.0,
    )
    assert features.values["observation_count"] == 1.0
    assert features.values["delete_count"] == 0.0
    assert features.values["process_event_count"] == 1.0
    assert features.values["distinct_pids"] == 1.0


def test_string_timestamp_after_cutoff_is_not_used() -> None:
    features = extract_event_window_features(
        [{"timestamp": "9.0", "pid": 99, "ppid": 1, "event_type": "FILE_DELETE"}],
        decision_time=2.0,
    )
    assert features.values["observation_count"] == 0.0
    assert features.values["distinct_pids"] == 0.0


def test_missing_evidence_is_explicit() -> None:
    features = extract_event_window_features([{"event_type": "FILE_WRITE"}])
    assert features.available["observation_count"] is False
    assert features.available["has_pid"] is False
    assert features.available["has_ppid"] is False
    assert "no valid event timestamps" in features.limitations
