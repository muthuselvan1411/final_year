#!/usr/bin/env python3
"""
Pipeline script to ingest MLRan dataset, validate schema, build splits, and generate data card.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from ransomshield.data.loader import load_mlran_dataset
from ransomshield.data.splits import (
    create_ranshield_family_split,
    create_source_protocol_split,
)
from ransomshield.data.provenance import generate_data_card


def main() -> None:
    print("=" * 60)
    print("RansomShield Phase 2: Ingesting and Validating MLRan Dataset")
    print("=" * 60)

    try:
        dataset = load_mlran_dataset("data/raw/mlran")
    except Exception as e:
        print(f"[FAIL] Data loading failed: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[PASS] Successfully loaded {len(dataset.df)} samples with {len(dataset.feature_cols)} features.")
    print(f"       Goodware: {dataset.metadata_summary['goodware_count']}, Ransomware: {dataset.metadata_summary['ransomware_count']}")

    # 1. Create SOURCE_PROTOCOL split
    print("\nCreating SOURCE_PROTOCOL split...")
    split_src = create_source_protocol_split(
        df=dataset.df,
        official_train_ids=dataset.train_ids_official,
        official_test_ids=dataset.test_ids_official,
        val_ratio=0.20,
        seed=42,
    )
    print(f"[PASS] SOURCE_PROTOCOL created: Train={len(split_src.train_ids)}, Val={len(split_src.val_ids)}, Test={len(split_src.test_ids)}")

    # 2. Create RANSHIELDSPLIT_v1 (family holdout)
    print("\nCreating RANSHIELDSPLIT_v1 (Family Holdout) split...")
    split_family = create_ranshield_family_split(
        df=dataset.df,
        val_ratio=0.16,
        seed=42,
    )
    print(f"[PASS] RANSHIELDSPLIT_v1 created: Train={len(split_family.train_ids)}, Val={len(split_family.val_ids)}, Test={len(split_family.test_ids)}, Challenge={len(split_family.challenge_ids or [])}")

    # 3. Generate DATA_CARD_MLRAN.md
    generate_data_card(dataset, "reports/DATA_CARD_MLRAN.md")
    print("\n[PASS] DATA_CARD_MLRAN.md successfully generated in reports/.")
    print("=" * 60)


if __name__ == "__main__":
    main()
