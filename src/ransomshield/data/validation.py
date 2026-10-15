"""
Schema and Data Quality Validation for MLRan Dataset.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


class ValidationError(ValueError):
    """Raised when dataset fails schema or data quality constraints."""
    pass


def validate_mlran_dataframe(
    df: pd.DataFrame,
    sample_id_col: str = "sample_id",
    label_col: str = "sample_type",
    expected_feature_count: int = 483,
) -> None:
    """
    Validates MLRan dataframe against strict research integrity rules:
    - Verifies presence of sample_id and label columns.
    - Rejects missing, null, or duplicate sample IDs.
    - Enforces binary labels (0 = benign, 1 = ransomware).
    - Checks that all feature columns are finite numeric values.
    """
    if df.empty:
        raise ValidationError("Dataset DataFrame is empty.")

    if sample_id_col not in df.columns:
        raise ValidationError(f"Missing required sample ID column '{sample_id_col}'.")

    if label_col not in df.columns:
        raise ValidationError(f"Missing required label column '{label_col}'.")

    # 1. Sample ID checks
    sample_ids = df[sample_id_col]
    if sample_ids.isnull().any():
        null_count = int(sample_ids.isnull().sum())
        raise ValidationError(f"Dataset contains {null_count} null sample IDs.")

    if sample_ids.duplicated().any():
        dup_count = int(sample_ids.duplicated().sum())
        raise ValidationError(f"Dataset contains {dup_count} duplicate sample IDs.")

    # 2. Label checks
    labels = df[label_col]
    if labels.isnull().any():
        raise ValidationError(f"Label column '{label_col}' contains null values.")

    unique_labels = set(labels.unique())
    if not unique_labels.issubset({0, 1}):
        raise ValidationError(
            f"Labels must be strictly binary {{0, 1}}, got: {sorted(unique_labels)}"
        )

    # 3. Feature count and numeric validity checks
    exclude_cols = {
        sample_id_col,
        label_col,
        "family_label",
        "type_label",
        "ransomware_family",
        "sha256",
        "year",
        "first_submission_date_year",
    }
    feature_cols = [c for c in df.columns if c not in exclude_cols]

    if len(feature_cols) != expected_feature_count:
        raise ValidationError(
            f"Expected {expected_feature_count} feature columns, but found {len(feature_cols)}."
        )

    features_array = df[feature_cols].to_numpy()
    if not np.issubdtype(features_array.dtype, np.number):
        raise ValidationError("Feature matrix contains non-numeric data types.")

    if not np.isfinite(features_array).all():
        raise ValidationError("Feature matrix contains NaN or Infinite values.")
