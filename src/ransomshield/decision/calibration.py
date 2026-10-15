"""
Probability Calibration for RansomShield EADL.
Fits calibration models strictly on validation data.
"""

from __future__ import annotations

import numpy as np
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import brier_score_loss


class ProbabilityCalibrator:
    """
    Validation-only probability calibrator using Platt scaling (sigmoid) or Isotonic regression.
    """

    def __init__(self, method: str = "sigmoid"):
        self.method = method
        self.calibrator = None
        self.is_fitted = False
        self.val_brier_before: float | None = None
        self.val_brier_after: float | None = None

    def fit(self, base_estimator: Any, X_val: np.ndarray, y_val: np.ndarray) -> ProbabilityCalibrator:
        """
        Fits calibration model strictly on the validation partition.
        """
        self.val_brier_before = float(brier_score_loss(y_val, base_estimator.predict_proba(X_val)[:, 1]))

        calibrated = CalibratedClassifierCV(
            estimator=base_estimator,
            method=self.method,
            cv="prefit",
        )
        calibrated.fit(X_val, y_val)
        self.calibrator = calibrated
        self.is_fitted = True

        self.val_brier_after = float(brier_score_loss(y_val, self.calibrator.predict_proba(X_val)[:, 1]))
        return self

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not self.is_fitted or self.calibrator is None:
            raise RuntimeError("ProbabilityCalibrator is not fitted yet.")
        return self.calibrator.predict_proba(X)

    @staticmethod
    def compute_ece(y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10) -> float:
        """Computes Expected Calibration Error (ECE)."""
        bin_limits = np.linspace(0.0, 1.0, n_bins + 1)
        ece = 0.0
        n = len(y_true)

        for i in range(n_bins):
            bin_mask = (y_prob >= bin_limits[i]) & (y_prob < bin_limits[i + 1])
            if i == n_bins - 1:  # include right edge on last bin
                bin_mask = (y_prob >= bin_limits[i]) & (y_prob <= bin_limits[i + 1])

            bin_count = np.sum(bin_mask)
            if bin_count > 0:
                bin_acc = np.mean(y_true[bin_mask])
                bin_conf = np.mean(y_prob[bin_mask])
                ece += (bin_count / n) * abs(bin_acc - bin_conf)

        return float(ece)
