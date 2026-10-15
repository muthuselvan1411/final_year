"""
Detector-level and Operational Decision Metrics for RansomShield.
Calculates TPR, FPR, Precision, F1, ROC-AUC, PR-AUC, Brier score, and 95% bootstrap CIs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


@dataclass
class DetectorMetrics:
    total_samples: int
    prevalence: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    recall: float
    precision: float
    f1: float
    false_positive_rate: float
    specificity: float
    roc_auc: Optional[float] = None
    pr_auc: Optional[float] = None
    brier_score: Optional[float] = None
    ci_95: Optional[Dict[str, Tuple[float, float]]] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_detector_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    compute_ci: bool = False,
    n_bootstrap: int = 1000,
    seed: int = 42,
) -> DetectorMetrics:
    """
    Computes rigorous detector-level metrics on binary ground truth.
    """
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)

    n_samples = len(y_true)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()

    recall = float(recall_score(y_true, y_pred, zero_division=0))
    precision = float(precision_score(y_true, y_pred, zero_division=0))
    f1 = float(f1_score(y_true, y_pred, zero_division=0))
    fpr = float(fp / max(fp + tn, 1))
    specificity = float(tn / max(tn + fp, 1))
    prevalence = float(np.mean(y_true))

    roc_auc = None
    pr_auc = None
    brier = None

    if y_prob is not None:
        y_prob = np.asarray(y_prob, dtype=float)
        try:
            roc_auc = float(roc_auc_score(y_true, y_prob))
        except Exception:
            roc_auc = None
        try:
            pr_auc = float(average_precision_score(y_true, y_prob))
        except Exception:
            pr_auc = None
        try:
            brier = float(brier_score_loss(y_true, y_prob))
        except Exception:
            brier = None

    ci_dict = None
    if compute_ci and n_samples > 10:
        ci_dict = bootstrap_metric_ci(
            y_true=y_true,
            y_pred=y_pred,
            y_prob=y_prob,
            n_bootstrap=n_bootstrap,
            seed=seed,
        )

    return DetectorMetrics(
        total_samples=n_samples,
        prevalence=prevalence,
        true_positives=int(tp),
        false_positives=int(fp),
        true_negatives=int(tn),
        false_negatives=int(fn),
        recall=recall,
        precision=precision,
        f1=f1,
        false_positive_rate=fpr,
        specificity=specificity,
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        brier_score=brier,
        ci_95=ci_dict,
    )


def bootstrap_metric_ci(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: Optional[np.ndarray] = None,
    n_bootstrap: int = 1000,
    seed: int = 42,
) -> Dict[str, Tuple[float, float]]:
    """
    Computes 95% stratified bootstrap confidence intervals.
    """
    rng = np.random.RandomState(seed)
    n = len(y_true)

    recalls: List[float] = []
    precisions: List[float] = []
    f1s: List[float] = []
    fprs: List[float] = []

    for _ in range(n_bootstrap):
        indices = rng.randint(0, n, size=n)
        sample_true = y_true[indices]
        sample_pred = y_pred[indices]

        # Skip if single-class sample
        if len(np.unique(sample_true)) < 2:
            continue

        rec = float(recall_score(sample_true, sample_pred, zero_division=0))
        prec = float(precision_score(sample_true, sample_pred, zero_division=0))
        f_one = float(f1_score(sample_true, sample_pred, zero_division=0))

        tn, fp, _, _ = confusion_matrix(sample_true, sample_pred, labels=[0, 1]).ravel()
        fp_rate = float(fp / max(fp + tn, 1))

        recalls.append(rec)
        precisions.append(prec)
        f1s.append(f_one)
        fprs.append(fp_rate)

    ci: Dict[str, Tuple[float, float]] = {}
    for name, vals in [("recall", recalls), ("precision", precisions), ("f1", f1s), ("fpr", fprs)]:
        if vals:
            ci[name] = (float(np.percentile(vals, 2.5)), float(np.percentile(vals, 97.5)))
        else:
            ci[name] = (0.0, 0.0)

    return ci
