"""
Unit tests for scripts/inspect_dataset.py using the synthetic test fixture.
"""

from __future__ import annotations

from pathlib import Path

from scripts.inspect_dataset import profile_dataset


def test_profile_synthetic_fixture() -> None:
    fixture_path = Path("tests/fixtures/synthetic_fixture.json")
    assert fixture_path.is_file()

    profile = profile_dataset(fixture_path, sample_id_col="sample_id", label_col="label")
    assert profile["row_count"] == 10
    assert profile["unique_sample_ids"] == 10
    assert profile["duplicate_sample_ids"] == 0
    assert profile["missing_sample_ids"] == 0
    assert "0" in profile["label_distribution"] or 0 in profile["label_distribution"]
    assert len(profile["sha256"]) == 64
