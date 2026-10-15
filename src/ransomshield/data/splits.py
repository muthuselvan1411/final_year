"""
Split Management and Leakage Protection for RansomShield Experiments.

Implements:
- SOURCE_PROTOCOL: Official MLRan train/test split with validation fold carved strictly from training data.
- RANSHIELDSPLIT_v1: Family-held-out generalization split preventing family leakage into train/calib folds.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set

import numpy as np
import pandas as pd


@dataclass
class SplitResult:
    split_name: str
    seed: int
    train_ids: List[int | str]
    val_ids: List[int | str]
    test_ids: List[int | str]
    challenge_ids: List[int | str] | None = None


class LeakageError(AssertionError):
    """Raised when partition overlap or data leakage is detected."""
    pass


def verify_partition_disjointness(
    partitions: Dict[str, List[int | str]],
    allow_empty: bool = False,
) -> None:
    """Verifies that sample IDs across all partitions are mutually exclusive."""
    seen_ids: Set[int | str] = set()
    for part_name, ids in partitions.items():
        if not allow_empty and len(ids) == 0:
            raise LeakageError(f"Partition '{part_name}' is empty.")
        part_set = set(ids)
        overlap = seen_ids.intersection(part_set)
        if overlap:
            sample_overlap = list(overlap)[:5]
            raise LeakageError(
                f"Data leakage detected! Partition '{part_name}' shares {len(overlap)} IDs with other partitions. Samples: {sample_overlap}"
            )
        seen_ids.update(part_set)


def create_source_protocol_split(
    df: pd.DataFrame,
    official_train_ids: List[int | str],
    official_test_ids: List[int | str],
    val_ratio: float = 0.20,
    seed: int = 42,
    output_dir: str | Path = "data/splits",
) -> SplitResult:
    """
    Creates the official reproduction split.
    Carves validation fold strictly from official_train_ids so test_ids remain untouched.
    """
    train_df = df[df["sample_id"].isin(official_train_ids)].copy()
    rng = np.random.RandomState(seed)

    # Stratified split on label (sample_type) to preserve balance
    train_labels = train_df["sample_type"].to_numpy()
    unique_labels = np.unique(train_labels)

    train_ids: List[int | str] = []
    val_ids: List[int | str] = []

    for lbl in unique_labels:
        lbl_indices = train_df[train_df["sample_type"] == lbl]["sample_id"].to_numpy()
        rng.shuffle(lbl_indices)
        n_val = int(len(lbl_indices) * val_ratio)
        val_ids.extend(lbl_indices[:n_val].tolist())
        train_ids.extend(lbl_indices[n_val:].tolist())

    verify_partition_disjointness({
        "train": train_ids,
        "val": val_ids,
        "test": official_test_ids,
    })

    result = SplitResult(
        split_name="SOURCE_PROTOCOL",
        seed=seed,
        train_ids=train_ids,
        val_ids=val_ids,
        test_ids=official_test_ids,
    )

    out_p = Path(output_dir)
    out_p.mkdir(parents=True, exist_ok=True)
    with open(out_p / "SOURCE_PROTOCOL.json", "w", encoding="utf-8") as f:
        json.dump({
            "split_name": result.split_name,
            "seed": result.seed,
            "counts": {
                "train": len(result.train_ids),
                "val": len(result.val_ids),
                "test": len(result.test_ids),
            },
            "train_ids": result.train_ids,
            "val_ids": result.val_ids,
            "test_ids": result.test_ids,
        }, f, indent=2)

    return result


def create_ranshield_family_split(
    df: pd.DataFrame,
    held_out_families: List[str | int] | None = None,
    val_ratio: float = 0.20,
    seed: int = 42,
    output_dir: str | Path = "data/splits",
) -> SplitResult:
    """
    Creates RANSHIELDSPLIT_v1: Family-held-out generalization split.
    Ransomware samples from held_out_families are strictly excluded from train and val.
    """
    if held_out_families is None:
        # Select top families to hold out as a generalization stress test
        # e.g., families with substantial representation
        family_counts = df[df["sample_type"] == 1]["family_label"].value_counts()
        # Pick 5 distinct families for held-out evaluation
        held_out_families = family_counts.index[:5].tolist()

    is_held_out = df["family_label"].isin(held_out_families) & (df["sample_type"] == 1)
    df_challenge = df[is_held_out]
    df_remaining = df[~is_held_out]

    challenge_ids = df_challenge["sample_id"].tolist()

    # Split remaining into train (64%), val (16%), test_standard (20%)
    rng = np.random.RandomState(seed)
    train_ids: List[int | str] = []
    val_ids: List[int | str] = []
    test_ids: List[int | str] = []

    for lbl in [0, 1]:
        subset = df_remaining[df_remaining["sample_type"] == lbl]["sample_id"].to_numpy()
        rng.shuffle(subset)
        n_test = int(len(subset) * 0.20)
        n_val = int(len(subset) * 0.16)

        test_ids.extend(subset[:n_test].tolist())
        val_ids.extend(subset[n_test : n_test + n_val].tolist())
        train_ids.extend(subset[n_test + n_val :].tolist())

    verify_partition_disjointness({
        "train": train_ids,
        "val": val_ids,
        "test": test_ids,
        "challenge_family": challenge_ids,
    })

    # Verify no held-out family leaked into train or val
    train_families = set(df[df["sample_id"].isin(train_ids)]["family_label"].unique())
    val_families = set(df[df["sample_id"].isin(val_ids)]["family_label"].unique())
    for hof in held_out_families:
        if hof in train_families:
            raise LeakageError(f"Held out family '{hof}' leaked into training set!")
        if hof in val_families:
            raise LeakageError(f"Held out family '{hof}' leaked into validation set!")

    result = SplitResult(
        split_name="RANSHIELDSPLIT_v1",
        seed=seed,
        train_ids=train_ids,
        val_ids=val_ids,
        test_ids=test_ids,
        challenge_ids=challenge_ids,
    )

    out_p = Path(output_dir)
    out_p.mkdir(parents=True, exist_ok=True)
    with open(out_p / "RANSHIELDSPLIT_v1.json", "w", encoding="utf-8") as f:
        json.dump({
            "split_name": result.split_name,
            "seed": result.seed,
            "held_out_families": [str(f) for f in held_out_families],
            "counts": {
                "train": len(result.train_ids),
                "val": len(result.val_ids),
                "test": len(result.test_ids),
                "challenge_family": len(result.challenge_ids or []),
            },
            "train_ids": result.train_ids,
            "val_ids": result.val_ids,
            "test_ids": result.test_ids,
            "challenge_ids": result.challenge_ids,
        }, f, indent=2)

    return result
