"""
Unit tests for reproducibility manifest generation and hashing.
"""

from __future__ import annotations

import json
from pathlib import Path

from ransomshield.manifest import (
    compute_dict_sha256,
    compute_sha256,
    create_manifest,
    save_manifest,
)


def test_compute_sha256(tmp_path: Path) -> None:
    test_file = tmp_path / "hello.txt"
    test_file.write_text("RansomShield Reproducibility Test\n", encoding="utf-8")
    h1 = compute_sha256(test_file)
    assert isinstance(h1, str)
    assert len(h1) == 64

    # Idempotent
    h2 = compute_sha256(test_file)
    assert h1 == h2


def test_compute_dict_sha256() -> None:
    d1 = {"a": 1, "b": 2, "c": [1, 2, 3]}
    d2 = {"c": [1, 2, 3], "b": 2, "a": 1}  # Key order difference
    assert compute_dict_sha256(d1) == compute_dict_sha256(d2)


def test_create_and_save_manifest(tmp_path: Path) -> None:
    cfg = {"seed": 42, "model": "b1"}
    manifest = create_manifest(
        run_id="SMOKE-01",
        purpose="Manifest unit test",
        seed=42,
        config_dict=cfg,
        dataset_file=None,
    )
    assert manifest["run_id"] == "SMOKE-01"
    assert manifest["random_seed"] == 42
    assert "git_commit" in manifest
    assert "environment" in manifest
    assert "config_sha256" in manifest

    out_file = tmp_path / "manifest.json"
    save_manifest(manifest, out_file)
    assert out_file.is_file()

    with open(out_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["run_id"] == "SMOKE-01"
