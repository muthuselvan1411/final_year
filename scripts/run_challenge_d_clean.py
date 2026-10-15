#!/usr/bin/env python3
"""
Challenge D Clean Re-Run: Legitimate Out-of-Distribution Family Generalization.

FIX for audit finding A4:
  The original run_paired_evaluation.py trained B4 on SOURCE_PROTOCOL and evaluated
  on RANSHIELDSPLIT_v1 challenge IDs, causing 340/495 training leakage.

  This script trains B4 EXCLUSIVELY on RANSHIELDSPLIT_v1 train set (N=2807),
  using RANSHIELDSPLIT_v1 val set for calibration (N=701),
  and evaluates on the 495 family-held-out challenge samples.
  The held families (cryptolocker, locker, pajetbin, reveton, virlock) are
  completely absent from the V1 training partition.

Outputs:
  results/P4_challenge_d_clean/challenge_predictions.csv
  results/P4_challenge_d_clean/challenge_metrics.json
  results/P4_challenge_d_clean/manifest.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "src"))

import numpy as np
import pandas as pd

from ransomshield.baseline.adapter import BaselineAdapter
from ransomshield.baseline.train import train_baseline_model
from ransomshield.data.loader import load_mlran_dataset
from ransomshield.decision.calibration import ProbabilityCalibrator
from ransomshield.decision.evidence import build_evidence_record
from ransomshield.decision.policy import OperationalDecisionPolicy
from ransomshield.evaluation.metrics import compute_detector_metrics
from ransomshield.manifest import create_manifest, save_manifest


def run_challenge_d_clean() -> None:
    print("=" * 70)
    print("RansomShield Challenge D (Clean): Family Holdout OOD Evaluation")
    print("=" * 70)
    print("Using RANSHIELDSPLIT_v1 exclusively (train/val/challenge).")
    print("This eliminates the training leakage found in audit A4.")
    print()

    # 1. Load dataset
    dataset = load_mlran_dataset(root / "data" / "raw" / "mlran")
    df = dataset.df
    feature_cols = dataset.feature_cols

    with open(root / "data" / "splits" / "RANSHIELDSPLIT_v1.json", "r", encoding="utf-8") as f:
        v1 = json.load(f)

    train_ids     = set(v1["train_ids"])
    val_ids       = set(v1.get("val_ids", []))
    challenge_ids = set(v1["challenge_ids"])

    # Verify no overlap between sets
    assert len(train_ids & challenge_ids) == 0, "LEAK: challenge IDs in V1 train"
    assert len(val_ids & challenge_ids) == 0,   "LEAK: challenge IDs in V1 val"
    print(f"  V1 train: {len(train_ids)}, val: {len(val_ids)}, challenge: {len(challenge_ids)}")
    print("  Disjointness verified: no leakage within RANSHIELDSPLIT_v1.")

    # 2. Extract partitions
    df_train    = df[df["sample_id"].isin(train_ids)]
    df_val      = df[df["sample_id"].isin(val_ids)]
    df_challenge = df[df["sample_id"].isin(challenge_ids)]

    X_train = df_train[feature_cols].to_numpy()
    y_train = df_train["sample_type"].to_numpy().astype(int)
    X_val   = df_val[feature_cols].to_numpy()
    y_val   = df_val["sample_type"].to_numpy().astype(int)
    X_chall = df_challenge[feature_cols].to_numpy()
    y_chall = df_challenge["sample_type"].to_numpy().astype(int)
    chall_ids = df_challenge["sample_id"].tolist()

    print(f"\n  Training partition: N={len(X_train)}, malicious={y_train.sum()}, benign={(y_train==0).sum()}")
    print(f"  Validation:         N={len(X_val)}, malicious={y_val.sum()}, benign={(y_val==0).sum()}")
    print(f"  Challenge (OOD):    N={len(X_chall)}, malicious={y_chall.sum()}, benign={(y_chall==0).sum()}")

    # Verify challenge set is all malicious
    assert (y_chall == 1).all(), "Challenge set contains benign samples!"
    print("  All 495 challenge samples are malicious (label=1). Verified.")

    # Verify family isolation if family metadata available
    if "ransomware_family" in df.columns:
        train_families = set(df_train["ransomware_family"].dropna().unique())
        chall_families = set(df_challenge["ransomware_family"].dropna().unique())
        overlap = train_families & chall_families
        if len(overlap) == 0:
            print(f"  Family isolation VERIFIED: challenge families {sorted(chall_families)} absent from training.")
        else:
            print(f"  WARNING: Family overlap detected: {overlap}")

    # 3. Train B4 (Random Forest) on V1 train partition
    print(f"\n1. Fitting B4 Random Forest on V1 train set (N={len(X_train)})...", end="", flush=True)
    bundle = train_baseline_model("b4_mlran_paper", X_train, y_train, seed=42)
    base_model = bundle.model
    print(" Done.")

    # 4. Calibrate on V1 val partition
    print(f"2. Fitting Platt calibration on V1 val set (N={len(X_val)})...", end="", flush=True)
    calibrator = ProbabilityCalibrator(method="sigmoid").fit(base_model, X_val, y_val)
    print(f" Done (Val Brier: {calibrator.val_brier_before:.4f} -> {calibrator.val_brier_after:.4f}).")

    # 5. Evaluate on challenge set (family OOD)
    print(f"3. Evaluating on held-out family challenge set (N={len(X_chall)})...", end="", flush=True)
    tau_alert   = 0.50
    tau_contain = 0.85
    policy = OperationalDecisionPolicy(
        policy_version="eadl-v1.0",
        tau_alert=tau_alert,
        tau_contain=tau_contain,
    )
    adapter = BaselineAdapter(base_model, model_id="b4_v1_train", feature_schema_id=bundle.feature_schema_id)
    chall_records = adapter.predict_records(X_chall, chall_ids)
    chall_preds = np.array([r.baseline_label for r in chall_records])
    chall_probs = np.array([r.malicious_probability for r in chall_records])
    chall_cal   = calibrator.predict_proba(X_chall)[:, 1]

    # Detector-level metrics
    chall_metrics = compute_detector_metrics(y_chall, chall_preds, chall_probs, compute_ci=True, seed=42)

    # EADL actions on challenge
    chall_decisions = []
    for i, r in enumerate(chall_records):
        ev = build_evidence_record(r, calibrated_prob=float(chall_cal[i]), calibrator_id="platt_sigmoid_v1_ood")
        dec = policy.evaluate_decision(r, ev)
        chall_decisions.append(dec)
    chall_actions = [d.action for d in chall_decisions]

    action_counts = pd.Series(chall_actions).value_counts().to_dict()
    contain_count = action_counts.get("CONTAINMENT_RECOMMENDED", 0)
    alert_count   = action_counts.get("ALERT", 0)
    monitor_count = action_counts.get("MONITOR", 0)
    missed_count  = action_counts.get("NO_ALERT", 0)

    eadl_contain_recall = contain_count / len(y_chall)
    eadl_alert_recall   = (contain_count + alert_count) / len(y_chall)

    print(" Done.")

    # 6. Save artifacts
    out_dir = root / "results" / "P4_challenge_d_clean"
    out_dir.mkdir(parents=True, exist_ok=True)

    chall_df = pd.DataFrame({
        "sample_id": chall_ids,
        "true_label": y_chall,
        "baseline_label": chall_preds,
        "raw_score": chall_probs,
        "calibrated_prob": chall_cal,
        "eadl_action": chall_actions,
        "eadl_severity": [d.severity for d in chall_decisions],
    })
    chall_df.to_csv(out_dir / "challenge_predictions.csv", index=False)

    metrics_out = {
        "run_description": "Challenge D Clean OOD - B4 trained on RANSHIELDSPLIT_v1 train only",
        "split": "RANSHIELDSPLIT_v1",
        "n_challenge": len(y_chall),
        "n_challenge_malicious": int(y_chall.sum()),
        "n_challenge_benign": int((y_chall == 0).sum()),
        "held_out_families": v1.get("held_out_families", []),
        "v1_train_size": len(train_ids),
        "v1_val_size": len(val_ids),
        "detector_level": {
            "recall": chall_metrics.recall,
            "precision": chall_metrics.precision,
            "f1": chall_metrics.f1,
            "fpr": chall_metrics.false_positive_rate,
            "roc_auc": chall_metrics.roc_auc,
        },
        "eadl_actions": action_counts,
        "eadl_contain_recall": eadl_contain_recall,
        "eadl_alert_or_higher_recall": eadl_alert_recall,
        "eadl_missed": missed_count,
        "calibration": {
            "val_brier_before": calibrator.val_brier_before,
            "val_brier_after": calibrator.val_brier_after,
        },
        "audit_note": (
            "This is the corrected Challenge D experiment. "
            "The original run_paired_evaluation.py had training leakage: "
            "340 of 495 challenge samples appeared in SOURCE_PROTOCOL training set. "
            "This run trains exclusively on RANSHIELDSPLIT_v1 train partition, "
            "ensuring complete family isolation."
        ),
    }
    with open(out_dir / "challenge_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_out, f, indent=2)

    manifest = create_manifest(
        run_id="P4-CHALLENGE-D-CLEAN-01",
        purpose="Clean family-holdout OOD evaluation using RANSHIELDSPLIT_v1 (fixes audit A4 leakage)",
        seed=42,
        config_dict={
            "split": "RANSHIELDSPLIT_v1",
            "model": "b4_mlran_paper",
            "tau_alert": tau_alert,
            "tau_contain": tau_contain,
            "audit_fix": "training_leakage_A4",
        },
        dataset_file="data/raw/mlran/MLRan_X_train_RFE.csv",
    )
    save_manifest(manifest, out_dir / "manifest.json")

    # Print results
    print()
    print("=" * 72)
    print("CHALLENGE D CLEAN OOD RESULTS (B4 trained on V1 train only)")
    print("=" * 72)
    print(f"  Held-out families: {v1.get('held_out_families', [])}")
    print(f"  Challenge samples: N={len(y_chall)} (all malicious)")
    print(f"  V1 Train size:     N={len(train_ids)} (family-isolated)")
    print()
    print(f"  Detector Recall:          {chall_metrics.recall*100:.2f}%")
    print(f"  Detector Precision:       {chall_metrics.precision*100:.2f}%")
    print(f"  Detector F1:              {chall_metrics.f1*100:.2f}%")
    print(f"  Detector FPR:             {chall_metrics.false_positive_rate*100:.2f}%")
    print(f"  ROC-AUC:                  {chall_metrics.roc_auc:.4f}")
    print()
    print(f"  EADL CONTAINMENT:         {contain_count} ({eadl_contain_recall*100:.2f}% of malicious)")
    print(f"  EADL ALERT:               {alert_count} ({alert_count/len(y_chall)*100:.2f}%)")
    print(f"  EADL MONITOR:             {monitor_count} ({monitor_count/len(y_chall)*100:.2f}%)")
    print(f"  EADL NO_ALERT (missed):   {missed_count} ({missed_count/len(y_chall)*100:.2f}%)")
    print(f"  ALERT-or-higher recall:   {eadl_alert_recall*100:.2f}%")
    print()
    print(f"  Saved to: {out_dir}")
    print("=" * 72)


if __name__ == "__main__":
    run_challenge_d_clean()
