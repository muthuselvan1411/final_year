"""
Unit tests for split generation and leakage verification.
"""

from __future__ import annotations

import pandas as pd
from ransomshield.data.splits import verify_partition_disjointness, LeakageError
from tests.compat import assert_raises


def test_verify_partition_disjointness_passes() -> None:
    parts = {
        "train": [1, 2, 3],
        "val": [4, 5],
        "test": [6, 7],
    }
    verify_partition_disjointness(parts)


def test_verify_partition_disjointness_detects_leakage() -> None:
    parts = {
        "train": [1, 2, 3],
        "val": [3, 4],  # Sample 3 overlaps with train!
        "test": [5, 6],
    }
    with assert_raises(LeakageError, match="Data leakage detected"):
        verify_partition_disjointness(parts)


def test_verify_partition_disjointness_rejects_empty_partition() -> None:
    parts = {
        "train": [1, 2],
        "val": [],
        "test": [3, 4],
    }
    with assert_raises(LeakageError, match="is empty"):
        verify_partition_disjointness(parts)
