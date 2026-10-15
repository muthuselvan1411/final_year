"""
Reproducibility Manifest Tooling for RansomShield Experiments.

Generates immutable execution records containing:
- Run ID and execution timestamp (UTC)
- Git commit hash
- Host environment specifications (OS, CPU, RAM, Python version)
- Installed package versions
- Resolved configuration checksum (SHA-256)
- Dataset input checksums (SHA-256)
- Random seed
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def compute_sha256(file_path: str | Path) -> str:
    """Computes SHA-256 checksum of a file."""
    p = Path(file_path)
    if not p.is_file():
        raise FileNotFoundError(f"File not found for checksum computation: {p}")
    hasher = hashlib.sha256()
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_dict_sha256(data: Dict[str, Any]) -> str:
    """Computes SHA-256 checksum of a canonical JSON serialization of a dict."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get_git_commit(repo_root: Optional[Path] = None) -> str:
    """Retrieves current git commit hash."""
    if repo_root is None:
        repo_root = Path(__file__).resolve().parent.parent.parent
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return commit
    except Exception:
        return "UNKNOWN_OR_NOT_A_GIT_REPO"


def create_manifest(
    run_id: str,
    purpose: str,
    seed: int,
    config_dict: Dict[str, Any],
    dataset_file: Optional[str | Path] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Generates an immutable manifest dictionary for an experiment run."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    dataset_checksum = None
    if dataset_file is not None and Path(dataset_file).is_file():
        dataset_checksum = compute_sha256(dataset_file)

    manifest: Dict[str, Any] = {
        "manifest_version": "1.0",
        "run_id": run_id,
        "purpose": purpose,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed,
        "git_commit": get_git_commit(repo_root),
        "config_sha256": compute_dict_sha256(config_dict),
        "dataset_file": str(dataset_file) if dataset_file else None,
        "dataset_sha256": dataset_checksum,
        "environment": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "machine": platform.machine(),
            "cpu_count": os.cpu_count(),
        },
        "metadata": extra_metadata or {},
    }
    return manifest


def save_manifest(manifest: Dict[str, Any], output_path: str | Path) -> None:
    """Saves manifest to a JSON file."""
    p = Path(output_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
