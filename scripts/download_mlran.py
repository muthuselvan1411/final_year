#!/usr/bin/env python3
"""
Download and verify MLRan Feature-Selected Dataset from the official GitHub repository.
Saves raw files into data/raw/mlran/ and writes an immutable SHA-256 manifest to data/manifests/.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

BASE_URL = "https://raw.githubusercontent.com/faithfulco/mlran/main/6_experiments/FS_MLRan_Datasets"

FILES_TO_DOWNLOAD = [
    "MLRan_X_train_RFE.csv",
    "MLRan_X_test_RFE.csv",
    "MLRan_labels.csv",
    "mlran_dataset_metadata.csv",
    "RFE_selected_feature_names_dic.json",
    "type_train_sampleids.csv",
    "type_test_sampleids.csv",
]


def compute_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def download_mlran() -> Dict[str, Any]:
    repo_root = Path(__file__).resolve().parent.parent
    target_dir = repo_root / "data" / "raw" / "mlran"
    manifests_dir = repo_root / "data" / "manifests"

    target_dir.mkdir(parents=True, exist_ok=True)
    manifests_dir.mkdir(parents=True, exist_ok=True)

    manifest_entries: Dict[str, Any] = {}

    print(f"Downloading MLRan dataset from: {BASE_URL}")
    for fname in FILES_TO_DOWNLOAD:
        file_url = f"{BASE_URL}/{fname}"
        out_path = target_dir / fname

        print(f"  Fetching {fname}...", end="", flush=True)
        urllib.request.urlretrieve(file_url, out_path)
        size_bytes = out_path.stat().st_size
        sha256_hash = compute_sha256(out_path)
        print(f" Done ({size_bytes:,} bytes, sha256={sha256_hash[:8]}...)")

        manifest_entries[fname] = {
            "source_url": file_url,
            "local_path": str(out_path.relative_to(repo_root)),
            "size_bytes": size_bytes,
            "sha256": sha256_hash,
            "download_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }

    manifest = {
        "dataset_name": "mlran",
        "provenance": {
            "repository": "https://github.com/faithfulco/mlran",
            "paper_arxiv": "https://arxiv.org/abs/2505.18613",
            "journal_doi": "https://doi.org/10.1016/j.jnca.2026.104475",
            "license": "MIT License",
        },
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "files": manifest_entries,
    }

    manifest_path = manifests_dir / "mlran_raw_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\nManifest successfully written to: {manifest_path}")
    return manifest


if __name__ == "__main__":
    download_mlran()
