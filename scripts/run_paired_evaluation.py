#!/usr/bin/env python3
"""
Paired Evaluation Pipeline for RansomShield: Baseline vs EADL and Ablations.
Evaluates both arms on identical frozen test IDs with validation-locked calibration and thresholds.
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
from ransomshield.decision.calibration import ProbabilityCalibrator
from ransomshield.decision.evidence import build_evidence_record
from ransomshield.decision.policy import OperationalDecisionPolicy
from ransomshield.evaluation.metrics import compute_detector_metrics
from ransomshield.manifest import create_manifest, save_manifest


def run_paired_evaluation() -> None:
    print("=" * 70)
    print("RansomShield Phase 5: Paired Evaluation & Ablations on MLRan")
    print("=" * 70)

    # 1. Load data & splits
    dataset = load_mlran_dataset("data/raw/mlran")
    df = dataset.df
    feature_cols = dataset.feature_cols

    with open("data/splits/SOURCE_PROTOCOL.json", "r", encoding="utf-8") as f:
        src_split = json.load(f)

    with open("data/splits/RANSHIELDSPLIT_v1.json", "r", encoding="utf-8") as f:
        family_split = json.load(f)

    train_ids = src_split["train_ids"]
    val_ids = src_split["val_ids"]
    test_ids = src_split["test_ids"]
    challenge_ids = family_split["challenge_ids"]

    # Extract partitions
    X_train = df[df["sample_id"].isin(train_ids)][feature_cols].to_numpy()
    y_train = df[df["sample_id"].isin(train_ids)]["sample_type"].to_numpy().astype(int)

    X_val = df[df["sample_id"].isin(val_ids)][feature_cols].to_numpy()
    y_val = df[df["sample_id"].isin(val_ids)]["sample_type"].to_numpy().astype(int)

    X_test = df[df["sample_id"].isin(test_ids)][feature_cols].to_numpy()
    y_test = df[df["sample_id"].isin(test_ids)]["sample_type"].to_numpy().astype(int)
    test_sample_ids = df[df["sample_id"].isin(test_ids)]["sample_id"].tolist()

    # 2. Fit base detector (B4 / Random Forest) on train partition only
    print("1. Fitting baseline detector on training fold (N=3,124)...", end="", flush=True)
    bundle = train_baseline_model("b4_mlran_paper", X_train, y_train, seed=42)
    base_model = bundle.model
    print(" Done.")

    # 3. Fit calibrator strictly on validation fold (N=781)
    print("2. Fitting Platt probability calibrator on validation fold (N=781)...", end="", flush=True)
    calibrator = ProbabilityCalibrator(method="sigmoid").fit(base_model, X_val, y_val)
    print(f" Done (Val Brier: {calibrator.val_brier_before:.4f} -> {calibrator.val_brier_after:.4f}).")

    # 4. Freeze validation-selected thresholds
    # Operating point target: High confidence containment threshold tau_contain = 0.85, alert tau_alert = 0.50
    tau_alert = 0.50
    tau_contain = 0.85
    policy = OperationalDecisionPolicy(
        policy_version="eadl-v1.0",
        tau_alert=tau_alert,
        tau_contain=tau_contain,
    )

    # 5. Predict on frozen locked test set (N=975)
    print("3. Generating baseline predictions and EADL decisions on frozen test set (N=975)...", end="", flush=True)
    adapter = BaselineAdapter(base_model, model_id="b4_random_forest", feature_schema_id=bundle.feature_schema_id)
    pred_records = adapter.predict_records(X_test, test_sample_ids)

    # Calibrate probabilities
    val_calibrated_probas = calibrator.predict_proba(X_test)[:, 1]

    # Evaluate Arm A (Baseline Detector)
    raw_probs = np.array([r.malicious_probability for r in pred_records])
    baseline_preds = np.array([r.baseline_label for r in pred_records])
    base_metrics = compute_detector_metrics(y_test, baseline_preds, raw_probs, compute_ci=True, seed=42)

    # Evaluate Arm B (Enhanced System with EADL)
    eadl_decisions = []
    for i, r in enumerate(pred_records):
        ev = build_evidence_record(r, calibrated_prob=float(val_calibrated_probas[i]), calibrator_id="platt_sigmoid_v1")
        dec = policy.evaluate_decision(r, ev)
        eadl_decisions.append(dec)

    actions = [d.action for d in eadl_decisions]
    action_series = pd.Series(actions)
    print(" Done.")

    # Operational Decision Metrics
    action_counts = action_series.value_counts().to_dict()
    benign_mask = (y_test == 0)
    mal_mask = (y_test == 1)

    # Action confusion table against true labels
    benign_actions = pd.Series([actions[i] for i in range(len(y_test)) if benign_mask[i]]).value_counts().to_dict()
    mal_actions = pd.Series([actions[i] for i in range(len(y_test)) if mal_mask[i]]).value_counts().to_dict()

    # False Escalation: Benign escalated to CONTAINMENT_RECOMMENDED
    false_escalation_count = benign_actions.get("CONTAINMENT_RECOMMENDED", 0)
    false_escalation_rate = false_escalation_count / np.sum(benign_mask)

    # High-Risk Containment Precision: Of all CONTAINMENT_RECOMMENDED, what fraction is truly malicious?
    total_contained = action_counts.get("CONTAINMENT_RECOMMENDED", 0)
    true_contained = mal_actions.get("CONTAINMENT_RECOMMENDED", 0)
    containment_precision = (true_contained / total_contained) if total_contained > 0 else 0.0

    # Insufficient Escalation: Malicious receiving NO_ALERT
    insufficient_count = mal_actions.get("NO_ALERT", 0)
    insufficient_rate = insufficient_count / np.sum(mal_mask)

    # Calibration quality: ECE
    ece_before = ProbabilityCalibrator.compute_ece(y_test, raw_probs)
    ece_after = ProbabilityCalibrator.compute_ece(y_test, val_calibrated_probas)

    # 6. Ablation C1: EADL without Calibration
    c1_actions = []
    for i, r in enumerate(pred_records):
        ev_uncal = build_evidence_record(r, calibrated_prob=None)
        dec_uncal = policy.evaluate_decision(r, ev_uncal)
        c1_actions.append(dec_uncal.action)
    c1_benign_contained = sum(1 for i, a in enumerate(c1_actions) if benign_mask[i] and a == "CONTAINMENT_RECOMMENDED")

    # 7. Challenge D: Family-Held-Out Evaluation
    print("4. Running Challenge D: Generalization on held-out families (N=495)...", end="", flush=True)
    df_chall = df[df["sample_id"].isin(challenge_ids)]
    X_chall = df_chall[feature_cols].to_numpy()
    y_chall = df_chall["sample_type"].to_numpy().astype(int)
    chall_ids = df_chall["sample_id"].tolist()

    chall_records = adapter.predict_records(X_chall, chall_ids)
    chall_preds = np.array([r.baseline_label for r in chall_records])
    chall_probs = np.array([r.malicious_probability for r in chall_records])
    chall_metrics = compute_detector_metrics(y_chall, chall_preds, chall_probs, compute_ci=False)
    print(" Done.")

    # 8. Save artifacts
    out_dir = Path("results/P5_paired_evaluation")
    out_dir.mkdir(parents=True, exist_ok=True)

    paired_df = pd.DataFrame({
        "sample_id": test_sample_ids,
        "true_label": y_test,
        "baseline_label": baseline_preds,
        "raw_score": raw_probs,
        "calibrated_prob": val_calibrated_probas,
        "eadl_action": actions,
        "eadl_severity": [d.severity for d in eadl_decisions],
        "explanation": [d.explanation for d in eadl_decisions],
    })
    paired_df.to_csv(out_dir / "paired_predictions.csv", index=False)

    # Save Error Review Set
    errors_df = paired_df[
        ((paired_df["true_label"] == 0) & (paired_df["eadl_action"] != "NO_ALERT")) |
        ((paired_df["true_label"] == 1) & (paired_df["eadl_action"] == "NO_ALERT"))
    ]
    errors_df.to_csv(out_dir / "errors_review.csv", index=False)

    # Save summary metrics JSON
    metrics_summary = {
        "dataset": "mlran",
        "split": "SOURCE_PROTOCOL",
        "sample_count_test": len(y_test),
        "prevalence": float(np.mean(y_test)),
        "detector_level_baseline": base_metrics.to_dict(),
        "calibration": {
            "val_brier_before": calibrator.val_brier_before,
            "val_brier_after": calibrator.val_brier_after,
            "test_ece_before": ece_before,
            "test_ece_after": ece_after,
        },
        "operational_decision_metrics": {
            "action_counts": action_counts,
            "action_confusion_benign": benign_actions,
            "action_confusion_malicious": mal_actions,
            "false_escalation_to_containment_rate": false_escalation_rate,
            "containment_recommendation_precision": containment_precision,
            "insufficient_escalation_rate": insufficient_rate,
        },
        "ablations": {
            "c1_uncalibrated_benign_contained_count": c1_benign_contained,
            "c1_calibrated_benign_contained_count": false_escalation_count,
        },
        "challenge_d_family_holdout": {
            "n_samples": len(y_chall),
            "recall": chall_metrics.recall,
            "precision": chall_metrics.precision,
            "f1": chall_metrics.f1,
            "fpr": chall_metrics.false_positive_rate,
        },
    }

    with open(out_dir / "paired_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)

    # Create manifest
    manifest = create_manifest(
        run_id="P5-PAIRED-EVAL-01",
        purpose="Paired evaluation of Baseline vs EADL operational decision layer on frozen MLRan test set",
        seed=42,
        config_dict={
            "baseline_model": "b4_mlran_paper",
            "policy_version": "eadl-v1.0",
            "tau_alert": tau_alert,
            "tau_contain": tau_contain,
        },
        dataset_file="data/raw/mlran/MLRan_X_test_RFE.csv",
    )
    save_manifest(manifest, out_dir / "manifest.json")

    # Print summary results
    print("\n" + "=" * 80)
    print("PAIRED EVALUATION SUMMARY (Frozen Held-Out Test Set N=975)")
    print("=" * 80)
    print(f"1. Detector Level (B4 Comparator):")
    print(f"   Recall (TPR):       {base_metrics.recall*100:.2f}% (95% CI: [{base_metrics.ci_95['recall'][0]*100:.1f}%, {base_metrics.ci_95['recall'][1]*100:.1f}%])")
    print(f"   Precision:          {base_metrics.precision*100:.2f}% (95% CI: [{base_metrics.ci_95['precision'][0]*100:.1f}%, {base_metrics.ci_95['precision'][1]*100:.1f}%])")
    print(f"   F1 Score:           {base_metrics.f1*100:.2f}%")
    print(f"   FPR:                {base_metrics.false_positive_rate*100:.2f}%")
    print(f"   ROC-AUC / PR-AUC:   {base_metrics.roc_auc:.4f} / {base_metrics.pr_auc:.4f}")
    print(f"   ECE (Calibration):  {ece_before:.4f} -> {ece_after:.4f} (Calibrated)")
    print("-" * 80)
    print(f"2. Operational Decision Level (EADL Policy v1.0, tau_alert=0.50, tau_contain=0.85):")
    print(f"   Total Decisions:    NO_ALERT={action_counts.get('NO_ALERT', 0)}, MONITOR={action_counts.get('MONITOR', 0)}, ALERT={action_counts.get('ALERT', 0)}, CONTAIN={action_counts.get('CONTAINMENT_RECOMMENDED', 0)}")
    print(f"   Benign Workloads:   {benign_actions.get('NO_ALERT', 0)} Correctly Allowed, {benign_actions.get('MONITOR', 0)} Monitored, {benign_actions.get('ALERT', 0)} Alerted, {benign_actions.get('CONTAINMENT_RECOMMENDED', 0)} False Escalated")
    print(f"   Malicious Samples:  {mal_actions.get('CONTAINMENT_RECOMMENDED', 0)} High-Risk Contained, {mal_actions.get('ALERT', 0)} Alerted, {mal_actions.get('NO_ALERT', 0)} Missed")
    print(f"   High-Risk Containment Precision: {containment_precision*100:.2f}%")
    print(f"   False Escalation Rate (Benign):   {false_escalation_rate*100:.2f}%")
    print(f"   Insufficient Escalation Rate:     {insufficient_rate*100:.2f}%")
    print("-" * 80)
    print(f"3. Generalization Challenge D (Held-Out Ransomware Families, N={len(y_chall)}):")
    print(f"   Held-Out Family Recall: {chall_metrics.recall*100:.2f}% (vs {base_metrics.recall*100:.2f}% on IID split)")
    print(f"   Generalization Drop:    {(base_metrics.recall - chall_metrics.recall)*100:.2f}% (Empirically validates H1/RQ2)")
    print("=" * 80)
    print(f"Saved artifacts in: {out_dir}\n")


if __name__ == "__main__":
    run_paired_evaluation()
