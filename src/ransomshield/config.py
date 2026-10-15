"""
Configuration Schema and Validation for RansomShield.

Enforces reproducibility rules:
- Rejects unknown datasets.
- Rejects missing random seeds.
- Rejects decision thresholds outside [0.0, 1.0].
- Rejects output paths that write inside raw data directories (e.g. data/raw/).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

import yaml

ALLOWED_DATASETS = {"mlran", "nbaiot", "synthetic_test"}
PROHIBITED_OUTPUT_DIRS = {"data/raw", "data\\raw"}


class ConfigValidationError(ValueError):
    """Raised when configuration violates reproducibility or safety constraints."""
    pass


@dataclass
class DatasetConfig:
    name: str
    data_path: str
    feature_schema_id: str
    sample_id_col: str
    label_col: str
    family_col: Optional[str] = None
    trace_col: Optional[str] = None
    timestamp_col: Optional[str] = None
    group_col: Optional[str] = None


@dataclass
class SplitConfig:
    strategy: Literal["iid", "grouped", "family_holdout", "temporal", "lodo", "synthetic_dev"]
    train_ratio: float = 0.6
    val_ratio: float = 0.2
    test_ratio: float = 0.2
    group_key: Optional[str] = None
    seed: int = 42


@dataclass
class ModelConfig:
    model_id: str
    model_family: str
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    seed: int = 42


@dataclass
class PolicyThresholds:
    tau_alert: float = 0.50
    tau_contain: float = 0.85
    min_confidence: float = 0.50
    temporal_consistency_threshold: float = 0.70
    min_temporal_observations: int = 3


@dataclass
class PolicyConfig:
    policy_version: str
    thresholds: PolicyThresholds
    enable_calibration: bool = False
    enable_temporal: bool = False
    action_hierarchy: List[str] = field(
        default_factory=lambda: ["NO_ALERT", "MONITOR", "ALERT", "CONTAINMENT_RECOMMENDED"]
    )


@dataclass
class ExperimentConfig:
    run_id: str
    purpose: str
    seed: int
    output_dir: str
    dataset: DatasetConfig
    split: SplitConfig
    model: ModelConfig
    policy: PolicyConfig


def validate_config_dict(cfg: Dict[str, Any]) -> None:
    """Validates raw configuration dictionary against strict safety rules."""
    # 1. Seed validation
    if "seed" not in cfg:
        raise ConfigValidationError("Configuration missing required top-level 'seed'.")
    if not isinstance(cfg["seed"], int):
        raise ConfigValidationError(f"'seed' must be an integer, got: {type(cfg['seed'])}")

    # 2. Output directory validation (must not write into data/raw)
    out_dir = str(cfg.get("output_dir", "")).strip().replace("\\", "/")
    if not out_dir:
        raise ConfigValidationError("Configuration missing required 'output_dir'.")
    for prohibited in ["data/raw", "./data/raw"]:
        if out_dir == prohibited or out_dir.startswith(prohibited + "/"):
            raise ConfigValidationError(
                f"Prohibited output_dir: '{out_dir}'. Outputs must NEVER write inside raw data directories."
            )

    # 3. Dataset validation
    if "dataset" not in cfg or not isinstance(cfg["dataset"], dict):
        raise ConfigValidationError("Configuration missing required 'dataset' section.")
    ds_name = cfg["dataset"].get("name")
    if not ds_name or ds_name not in ALLOWED_DATASETS:
        raise ConfigValidationError(
            f"Unknown dataset '{ds_name}'. Must be one of: {sorted(ALLOWED_DATASETS)}"
        )

    # 4. Split validation
    if "split" not in cfg or not isinstance(cfg["split"], dict):
        raise ConfigValidationError("Configuration missing required 'split' section.")
    split = cfg["split"]
    if "seed" not in split:
        raise ConfigValidationError("Split section missing required 'seed'.")
    ratios = [split.get("train_ratio", 0.0), split.get("val_ratio", 0.0), split.get("test_ratio", 0.0)]
    if any(r < 0.0 or r > 1.0 for r in ratios):
        raise ConfigValidationError(f"Split ratios must be between 0.0 and 1.0, got: {ratios}")
    if abs(sum(ratios) - 1.0) > 1e-4:
        raise ConfigValidationError(f"Split ratios must sum to 1.0, got sum: {sum(ratios)}")

    # 5. Policy threshold validation
    if "policy" not in cfg or not isinstance(cfg["policy"], dict):
        raise ConfigValidationError("Configuration missing required 'policy' section.")
    thresholds = cfg["policy"].get("thresholds", {})
    for thresh_key in ["tau_alert", "tau_contain", "min_confidence", "temporal_consistency_threshold"]:
        val = thresholds.get(thresh_key)
        if val is None:
            raise ConfigValidationError(f"Policy thresholds missing required key '{thresh_key}'.")
        if not (0.0 <= float(val) <= 1.0):
            raise ConfigValidationError(
                f"Policy threshold '{thresh_key}' must be within [0.0, 1.0], got: {val}"
            )
    if float(thresholds["tau_alert"]) > float(thresholds["tau_contain"]):
        raise ConfigValidationError(
            f"tau_alert ({thresholds['tau_alert']}) cannot exceed tau_contain ({thresholds['tau_contain']})."
        )


def load_config(path_or_str: str | Path) -> Dict[str, Any]:
    """Loads and validates configuration from a YAML file."""
    p = Path(path_or_str)
    if not p.is_file():
        raise FileNotFoundError(f"Configuration file not found: {p}")
    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ConfigValidationError(f"Configuration file {p} does not contain a top-level mapping.")
    validate_config_dict(data)
    return data
