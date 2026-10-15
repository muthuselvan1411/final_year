"""
Unit tests for configuration loading and validation.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from ransomshield.config import (
    ConfigValidationError,
    load_config,
    validate_config_dict,
)
from tests.compat import assert_raises


def get_valid_config_dict() -> dict:
    return {
        "run_id": "TEST-01",
        "purpose": "Unit testing valid configuration",
        "seed": 42,
        "output_dir": "results/test_run",
        "dataset": {
            "name": "synthetic_test",
            "data_path": "tests/fixtures/synthetic_fixture.json",
            "feature_schema_id": "schema-v1",
            "sample_id_col": "sample_id",
            "label_col": "label",
        },
        "split": {
            "strategy": "synthetic_dev",
            "train_ratio": 0.6,
            "val_ratio": 0.2,
            "test_ratio": 0.2,
            "seed": 42,
        },
        "model": {
            "model_id": "b1-logistic-regression",
            "model_family": "logistic_regression",
            "seed": 42,
        },
        "policy": {
            "policy_version": "v1",
            "thresholds": {
                "tau_alert": 0.40,
                "tau_contain": 0.80,
                "min_confidence": 0.50,
                "temporal_consistency_threshold": 0.70,
            },
        },
    }


def test_valid_config_passes() -> None:
    cfg = get_valid_config_dict()
    validate_config_dict(cfg)


def test_missing_seed_raises() -> None:
    cfg = get_valid_config_dict()
    del cfg["seed"]
    with assert_raises(ConfigValidationError, match="missing required top-level 'seed'"):
        validate_config_dict(cfg)


def test_prohibited_output_dir_raises() -> None:
    cfg = get_valid_config_dict()
    cfg["output_dir"] = "data/raw/results"
    with assert_raises(ConfigValidationError, match="Prohibited output_dir"):
        validate_config_dict(cfg)


def test_unknown_dataset_raises() -> None:
    cfg = get_valid_config_dict()
    cfg["dataset"]["name"] = "invented_ransomware_dataset"
    with assert_raises(ConfigValidationError, match="Unknown dataset"):
        validate_config_dict(cfg)


def test_split_ratios_must_sum_to_one() -> None:
    cfg = get_valid_config_dict()
    cfg["split"]["train_ratio"] = 0.5
    cfg["split"]["val_ratio"] = 0.2
    cfg["split"]["test_ratio"] = 0.1
    with assert_raises(ConfigValidationError, match="Split ratios must sum to 1.0"):
        validate_config_dict(cfg)


def test_threshold_out_of_bounds_raises() -> None:
    cfg = get_valid_config_dict()
    cfg["policy"]["thresholds"]["tau_alert"] = 1.25
    with assert_raises(ConfigValidationError, match="must be within"):
        validate_config_dict(cfg)


def test_tau_alert_greater_than_tau_contain_raises() -> None:
    cfg = get_valid_config_dict()
    cfg["policy"]["thresholds"]["tau_alert"] = 0.90
    cfg["policy"]["thresholds"]["tau_contain"] = 0.70
    with assert_raises(ConfigValidationError, match="cannot exceed tau_contain"):
        validate_config_dict(cfg)


def test_load_config_from_file() -> None:
    cfg = get_valid_config_dict()
    import yaml
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
        yaml.dump(cfg, f)
        temp_path = Path(f.name)

    try:
        loaded = load_config(temp_path)
        assert loaded["run_id"] == "TEST-01"
        assert loaded["seed"] == 42
    finally:
        if temp_path.exists():
            temp_path.unlink()
