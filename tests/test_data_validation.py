"""
Unit tests for MLRan data validation and schema rules.
"""

from __future__ import annotations

import pandas as pd

from ransomshield.data.validation import validate_mlran_dataframe, ValidationError
from tests.compat import assert_raises


def test_validate_mlran_dataframe_rejects_missing_sample_id_col() -> None:
    df = pd.DataFrame({"feat_1": [1, 2], "sample_type": [0, 1]})
    with assert_raises(ValidationError, match="Missing required sample ID column"):
        validate_mlran_dataframe(df, sample_id_col="sample_id", label_col="sample_type", expected_feature_count=1)


def test_validate_mlran_dataframe_rejects_duplicate_sample_ids() -> None:
    df = pd.DataFrame({
        "sample_id": [101, 101],
        "sample_type": [0, 1],
        "feat_1": [1.0, 2.0],
    })
    with assert_raises(ValidationError, match="contains 1 duplicate sample IDs"):
        validate_mlran_dataframe(df, sample_id_col="sample_id", label_col="sample_type", expected_feature_count=1)


def test_validate_mlran_dataframe_rejects_non_binary_labels() -> None:
    df = pd.DataFrame({
        "sample_id": [101, 102],
        "sample_type": [0, 5],
        "feat_1": [1.0, 2.0],
    })
    with assert_raises(ValidationError, match="Labels must be strictly binary"):
        validate_mlran_dataframe(df, sample_id_col="sample_id", label_col="sample_type", expected_feature_count=1)


def test_validate_mlran_dataframe_rejects_wrong_feature_count() -> None:
    df = pd.DataFrame({
        "sample_id": [101, 102],
        "sample_type": [0, 1],
        "feat_1": [1.0, 2.0],
    })
    with assert_raises(ValidationError, match="Expected 483 feature columns, but found 1"):
        validate_mlran_dataframe(df, sample_id_col="sample_id", label_col="sample_type", expected_feature_count=483)
