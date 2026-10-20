from collector.normalizer import EventNormalizer
from schema.event_schema import NormalizedEvent


def test_loader_timestamp_and_unknown_success_are_preserved() -> None:
    normalized = EventNormalizer(compute_entropy=False).normalize(
        {
            "timestamp": 100.5,
            "timestamp_ns": 123456789,
            "receive_timestamp": 100.6,
            "pid": 10,
            "ppid": 1,
            "process": "test",
            "event_type": "FILE_WRITE",
            "success": None,
            "extra": {
                "success_evidence": "unavailable",
                "timestamp_source": "userspace_receive",
            },
        }
    )

    assert normalized["timestamp_ns"] == 123456789
    assert normalized["receive_timestamp"] == 100.6
    assert normalized["timestamp"] == 100.5
    assert normalized["success"] is None
    assert normalized["extra"]["success_evidence"] == "unavailable"


def test_normalized_event_preserves_legacy_positional_extra_argument() -> None:
    event = NormalizedEvent(
        100.0,
        10,
        1,
        "test",
        "/usr/bin/test",
        "FILE_WRITE",
        "/tmp/file",
        4,
        None,
        None,
        None,
        None,
        {"success_evidence": "unavailable"},
    )

    assert event.extra["success_evidence"] == "unavailable"
    assert event.timestamp_ns is None
    assert event.receive_timestamp is None


def test_normalizer_maps_invalid_process_identifiers_to_explicit_sentinels() -> None:
    normalized = EventNormalizer(compute_entropy=False).normalize(
        {"timestamp": 1.0, "pid": None, "ppid": "not-a-pid"}
    )

    assert normalized["pid"] == 0
    assert normalized["ppid"] == 0
