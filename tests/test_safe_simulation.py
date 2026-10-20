from __future__ import annotations

import json

from scripts.run_safe_simulation import run_scenario


def test_benign_simulation_uses_pipeline_without_filesystem_side_effects(tmp_path):
    result = run_scenario("benign_file_operations", tmp_path / "benign")

    assert result["source"] == "synthetic_simulation"
    assert result["expected_event_count"] == 4
    assert result["observed_event_count"] == 4
    assert result["processing_failures"] == []
    assert result["decision_counts"] == {"ABSTAIN": 4}
    assert json.loads(
        (tmp_path / "benign" / "simulation_summary.json").read_text(
            encoding="utf-8"
        )
    )["detector_status"] == "unavailable"


def test_synthetic_burst_is_not_reported_as_detection(tmp_path):
    result = run_scenario("synthetic_rapid_file_burst", tmp_path / "burst")

    assert result["observed_event_count"] == 12
    assert result["observed_event_types"] == {"FILE_RENAME": 12}
    assert result["decision_counts"] == {"ABSTAIN": 12}
    assert "not ransomware execution" in result["interpretation"]
