from ransomshield.telemetry.temporal import extract_temporal_features


def test_temporal_extractor_never_uses_future_events() -> None:
    events = [
        {"timestamp": 1.0, "event_type": "FILE_WRITE", "path": "a"},
        {"timestamp": 2.0, "event_type": "FILE_DELETE", "path": "a"},
        {"timestamp": 3.0, "event_type": "FILE_RENAME", "path": "a"},
    ]
    before_delete = extract_temporal_features(
        events, window_seconds=5.0, decision_time=1.5
    )
    assert before_delete.observation_count == 1
    assert before_delete.delete_count == 0
    assert before_delete.rename_count == 0


def test_temporal_extractor_does_not_accept_label_as_evidence() -> None:
    events = [
        {"timestamp": 1.0, "event_type": "FILE_WRITE", "path": "a", "label": 1},
        {"timestamp": 2.0, "event_type": "FILE_WRITE", "path": "b", "label": 0},
    ]
    features = extract_temporal_features(events, window_seconds=5.0)
    assert features.observation_count == 2
    assert features.file_modifications == 2
    assert not hasattr(features, "label")
