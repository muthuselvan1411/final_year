from ransomshield.evaluation.trace_audit import audit_events, verify_group_disjointness


def test_trace_audit_reports_coverage_and_group() -> None:
    audit = audit_events(
        [
            {"timestamp": 1.0, "pid": 10, "ppid": 1, "event_type": "FILE_WRITE", "path": "a"},
            {"timestamp": 2.0, "pid": 10, "ppid": 1, "event_type": "FILE_DELETE", "path": "a"},
        ],
        trace_group="trace-a",
    )
    assert audit.trace_group == "trace-a"
    assert audit.event_count == 2
    assert audit.valid_timestamp_count == 2
    assert audit.distinct_pids == 1
    assert audit.events_with_path == 2


def test_trace_audit_detects_invalid_and_duplicate_events() -> None:
    event = {"timestamp": "bad", "pid": 1, "ppid": 0, "event_type": "OTHER"}
    audit = audit_events([event, event], trace_group="trace-b")
    assert audit.invalid_timestamp_count == 2
    assert audit.duplicate_event_count == 1


def test_trace_group_leakage_is_rejected() -> None:
    try:
        verify_group_disjointness(
            {"train": ["trace-a"], "test": ["trace-a"]}
        )
    except ValueError as exc:
        assert "trace-a" in str(exc)
    else:
        raise AssertionError("Expected overlapping trace groups to be rejected")
