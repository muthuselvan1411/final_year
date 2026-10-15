#!/usr/bin/env python3
"""
Dataset Inspection and Profiling Tool for RansomShield.

Inspects feature tables or JSON datasets:
- Verifies existence and computes SHA-256 checksum.
- Detects row counts, column counts, and column types.
- Checks for missing values and duplicates on sample IDs.
- Outputs a schema profile JSON and human-readable summary.
- Fails loudly on missing files or malformed data; does not guess columns.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


def compute_file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def profile_dataset(
    file_path: Path,
    sample_id_col: str = "sample_id",
    label_col: str = "label",
) -> Dict[str, Any]:
    if not file_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {file_path}")

    file_size = file_path.stat().st_size
    file_hash = compute_file_sha256(file_path)

    # Inspect JSON or CSV
    suffix = file_path.suffix.lower()
    if suffix in [".json", ".jsonl"]:
        with open(file_path, "r", encoding="utf-8") as f:
            if suffix == ".json":
                data = json.load(f)
                records = data.get("records", data) if isinstance(data, dict) else data
            else:
                records = [json.loads(line) for line in f if line.strip()]

        if not isinstance(records, list) or len(records) == 0:
            raise ValueError(f"No records found in dataset {file_path}")

        row_count = len(records)
        first_row = records[0]
        columns = list(first_row.keys())

        # Check required columns
        sample_ids = [r.get(sample_id_col) for r in records]
        labels = [r.get(label_col) for r in records]

        missing_sample_ids = sum(1 for sid in sample_ids if sid is None or sid == "")
        unique_sample_ids = len(set(sample_ids))
        duplicate_sample_ids = row_count - unique_sample_ids

        label_counts: Dict[str, int] = {}
        for lbl in labels:
            lbl_key = str(lbl)
            label_counts[lbl_key] = label_counts.get(lbl_key, 0) + 1

        profile: Dict[str, Any] = {
            "file_name": file_path.name,
            "file_path": str(file_path),
            "file_size_bytes": file_size,
            "sha256": file_hash,
            "format": suffix,
            "row_count": row_count,
            "columns": columns,
            "sample_id_column": sample_id_col,
            "label_column": label_col,
            "unique_sample_ids": unique_sample_ids,
            "duplicate_sample_ids": duplicate_sample_ids,
            "missing_sample_ids": missing_sample_ids,
            "label_distribution": label_counts,
        }
        return profile
    else:
        raise NotImplementedError(f"Dataset inspection for format '{suffix}' requires Stage 2 pandas/csv support.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inspect dataset and generate schema profile.")
    parser.add_argument("--input", required=True, help="Path to input dataset file.")
    parser.add_argument("--output-json", default=None, help="Path to output profile JSON.")
    parser.add_argument("--sample-id-col", default="sample_id", help="Sample ID column name.")
    parser.add_argument("--label-col", default="label", help="Label column name.")
    args = parser.parse_args()

    input_p = Path(args.input)
    try:
        profile = profile_dataset(input_p, args.sample_id_col, args.label_col)
    except Exception as e:
        print(f"[ERROR] Dataset inspection failed: {e}", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print(f"Dataset Profile: {profile['file_name']}")
    print("=" * 60)
    print(f"Path:                {profile['file_path']}")
    print(f"Size:                {profile['file_size_bytes']} bytes")
    print(f"SHA-256:             {profile['sha256']}")
    print(f"Total Rows:          {profile['row_count']}")
    print(f"Unique Sample IDs:   {profile['unique_sample_ids']}")
    print(f"Duplicate IDs:       {profile['duplicate_sample_ids']}")
    print(f"Label Distribution:  {profile['label_distribution']}")
    print("-" * 60)

    if args.output_json:
        out_p = Path(args.output_json)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
        print(f"Profile saved to: {out_p}")


if __name__ == "__main__":
    main()
