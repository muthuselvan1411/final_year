#!/usr/bin/env python3
"""
Executes the B0 - B4 Baseline Model Ladder on MLRan under SOURCE_PROTOCOL.
Saves reproducible predictions, manifests, and metrics.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Add src to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import numpy as np
import pandas as pd

from ransomshield.baseline.adapter import BaselineAdapter
from ransomshield.baseline.train import train_baseline_model
from ransomshield.data.loader import load_mlran_dataset
from ransomshield.evaluation.metrics import compute_detector_metrics
from ransomshield.manifest import create_manifest, save_manifest


def run_baseline_ladder() -> None:
    print("=" * 65)
    print("RansomShield Phase 3: B0 - B4 Baseline Model Ladder Execution")
    print("=" * 65)

    # 1. Load dataset & splits
    dataset = load_mlran_dataset("data/raw/mlran")
    df = dataset.df
    feature_cols = dataset.feature_cols

    split_file = Path("data/splits/SOURCE_PROTOCOL.json")
    if not split_file.is_file():
        raise FileNotFoundError("SOURCE_PROTOCOL.json not found. Run scripts/prepare_mlran_data.py first.")

    with open(split_file, "r", encoding="utf-8") as f:
        split_data = json.load(f)

    train_ids = split_data["train_ids"]
    val_ids = split_data["val_ids"]
    test_ids = split_data["test_ids"]

    # Slice train and test data
    train_mask = df["sample_id"].isin(train_ids)
    test_mask = df["sample_id"].isin(test_ids)

    X_train = df.loc[train_mask, feature_cols].to_numpy()
    y_train = df.loc[train_mask, "sample_type"].to_numpy().astype(int)

    X_test = df.loc[test_mask, feature_cols].to_numpy()
    y_test = df.loc[test_mask, "sample_type"].to_numpy().astype(int)
    test_sample_ids = df.loc[test_mask, "sample_id"].tolist()

    print(f"Data Partitions: Train={len(X_train)} (Prev={np.mean(y_train):.3f}), Test={len(X_test)} (Prev={np.mean(y_test):.3f})")
    print(f"Features: {len(feature_cols)} behavioral RFE features\n")

    models_to_run = [
        ("b0_prevalence", "B0: Majority Class Floor"),
        ("b1_logistic", "B1: L2 Regularized Logistic Regression"),
        ("b2_random_forest", "B2: Random Forest (100 trees)"),
        ("b3_gradient_boosting", "B3: HistGradientBoosting"),
        ("b4_mlran_paper", "B4: Source MLRan Comparator (Random Forest)"),
    ]

    out_dir = Path("results/P3_baseline_reproduction")
    out_dir.mkdir(parents=True, exist_ok=True)

    results_table = []
    all_metrics: dict = {}
    saved_predictions = None

    for m_id, m_label in models_to_run:
        print(f"Training {m_label}...", end="", flush=True)
        bundle = train_baseline_model(model_id=m_id, X_train=X_train, y_train=y_train, seed=42)
        print(f" Done ({bundle.fit_time_seconds:.2f}s). Evaluating on locked test set...", end="", flush=True)

        adapter = BaselineAdapter(
            model=bundle.model,
            model_id=m_id,
            model_version="1.0.0",
            feature_schema_id=bundle.feature_schema_id,
        )

        records = adapter.predict_records(X_test, test_sample_ids)
        y_pred = np.array([r.baseline_label for r in records])
        y_prob = np.array([r.malicious_probability if r.malicious_probability is not None else 0.5 for r in records])

        metrics = compute_detector_metrics(
            y_true=y_test,
            y_pred=y_pred,
            y_prob=y_prob,
            compute_ci=True,
            n_bootstrap=1000,
            seed=42,
        )
        print(" Complete.")

        ci_f1 = metrics.ci_95.get("f1", (0.0, 0.0)) if metrics.ci_95 else (0.0, 0.0)

        results_table.append({
            "model_id": m_id,
            "label": m_label,
            "recall": metrics.recall,
            "precision": metrics.precision,
            "f1": metrics.f1,
            "fpr": metrics.false_positive_rate,
            "roc_auc": metrics.roc_auc,
            "pr_auc": metrics.pr_auc,
            "brier": metrics.brier_score,
            "f1_ci95": f"[{ci_f1[0]:.4f}, {ci_f1[1]:.4f}]",
            "fit_time_s": bundle.fit_time_seconds,
            "latency_ms": records[0].inference_ms,
        })
        all_metrics[m_id] = metrics.to_dict()

        if m_id == "b4_mlran_paper":
            pred_df = pd.DataFrame([
                {
                    "sample_id": r.sample_id,
                    "true_label": int(y_test[i]),
                    "baseline_label": r.baseline_label,
                    "raw_score": r.raw_score,
                    "malicious_probability": r.malicious_probability,
                    "inference_ms": r.inference_ms,
                }
                for i, r in enumerate(records)
            ])
            pred_df.to_csv(out_dir / "predictions_b4.csv", index=False)

    # Save metrics JSON
    with open(out_dir / "metrics_ladder.json", "w", encoding="utf-8") as f:
        json.dump(all_metrics, f, indent=2)

    # Save Manifest
    manifest = create_manifest(
        run_id="P3-MLRAN-LADDER-01",
        purpose="Reproduction of B0-B4 baseline models under official SOURCE_PROTOCOL split",
        seed=42,
        config_dict={"models": [m[0] for m in models_to_run], "split": "SOURCE_PROTOCOL"},
        dataset_file="data/raw/mlran/MLRan_X_train_RFE.csv",
    )
    save_manifest(manifest, out_dir / "manifest.json")

    # Print summary markdown table
    print("\n" + "=" * 80)
    print("Baseline Ladder Results on Locked Test Set (N=975)")
    print("=" * 80)
    print(f"{'Model':<30} | {'Recall':<7} | {'Precision':<9} | {'F1':<7} | {'FPR':<7} | {'ROC-AUC':<8} | {'95% CI (F1)':<18}")
    print("-" * 80)
    for r in results_table:
        roc_str = f"{r['roc_auc']:.4f}" if r['roc_auc'] is not None else "N/A"
        print(f"{r['label']:<30} | {r['recall']:.4f}  | {r['precision']:.4f}    | {r['f1']:.4f} | {r['fpr']:.4f}  | {roc_str:<8} | {r['f1_ci95']:<18}")
    print("=" * 80)
    print(f"Artifacts saved in: {out_dir}")


if __name__ == "__main__":
    run_baseline_ladder()
