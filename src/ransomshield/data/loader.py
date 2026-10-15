"""
Dataset Loader for MLRan Feature-Selected Dataset.
Loads raw feature tables, merges metadata, and enforces canonical representation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from ransomshield.data.validation import validate_mlran_dataframe


@dataclass
class MLRanDataset:
    df: pd.DataFrame
    feature_cols: List[str]
    train_ids_official: List[int | str]
    test_ids_official: List[int | str]
    feature_names_dic: Dict[str, str]
    metadata_summary: Dict[str, Any]


def load_mlran_dataset(raw_dir: str | Path = "data/raw/mlran") -> MLRanDataset:
    """
    Loads official MLRan dataset files and canonicalizes them.
    Merges X_train, X_test, labels, and sample metadata.
    """
    raw_p = Path(raw_dir)
    if not raw_p.is_dir():
        raise FileNotFoundError(f"MLRan directory does not exist: {raw_p}")

    train_path = raw_p / "MLRan_X_train_RFE.csv"
    test_path = raw_p / "MLRan_X_test_RFE.csv"
    metadata_path = raw_p / "mlran_dataset_metadata.csv"
    dict_path = raw_p / "RFE_selected_feature_names_dic.json"

    for req_file in [train_path, test_path, metadata_path]:
        if not req_file.is_file():
            raise FileNotFoundError(f"Required MLRan file missing: {req_file}")

    # 1. Load train and test feature splits
    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    train_ids = df_train["sample_id"].tolist()
    test_ids = df_test["sample_id"].tolist()

    df_combined = pd.concat([df_train, df_test], axis=0, ignore_index=True)

    # 2. Load feature names dictionary if available
    feature_names_dic: Dict[str, str] = {}
    if dict_path.is_file():
        with open(dict_path, "r", encoding="utf-8") as f:
            feature_names_dic = json.load(f)

    # 3. Load metadata and attach key metadata columns
    meta_df = pd.read_csv(metadata_path)
    meta_cols_to_merge = ["sample_id", "sha256", "ransomware_family", "first_submission_date_year"]
    available_meta_cols = [c for c in meta_cols_to_merge if c in meta_df.columns]
    df_meta_subset = meta_df[available_meta_cols].drop_duplicates(subset=["sample_id"])

    # Merge on sample_id
    df_merged = pd.merge(df_combined, df_meta_subset, on="sample_id", how="left")

    # 4. Identify 483 feature columns
    non_feature_cols = {
        "sample_id",
        "sample_type",
        "family_label",
        "type_label",
        "sha256",
        "ransomware_family",
        "first_submission_date_year",
    }
    feature_cols = [c for c in df_combined.columns if c not in non_feature_cols]

    # 5. Validate canonical dataframe
    validate_mlran_dataframe(
        df_merged,
        sample_id_col="sample_id",
        label_col="sample_type",
        expected_feature_count=len(feature_cols),
    )

    metadata_summary = {
        "total_samples": len(df_merged),
        "feature_count": len(feature_cols),
        "goodware_count": int((df_merged["sample_type"] == 0).sum()),
        "ransomware_count": int((df_merged["sample_type"] == 1).sum()),
        "unique_families": int(df_merged["family_label"].nunique()),
        "official_train_count": len(train_ids),
        "official_test_count": len(test_ids),
    }

    return MLRanDataset(
        df=df_merged,
        feature_cols=feature_cols,
        train_ids_official=train_ids,
        test_ids_official=test_ids,
        feature_names_dic=feature_names_dic,
        metadata_summary=metadata_summary,
    )
