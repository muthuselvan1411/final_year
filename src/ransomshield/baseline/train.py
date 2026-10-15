"""
Training Pipeline for RansomShield Baseline Models (B0 - B4 Ladder).
Ensures preprocessing is encapsulated and fitted strictly within training folds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

import numpy as np
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


@dataclass
class BaselineModelBundle:
    model_id: str
    model: Any
    hyperparameters: Dict[str, Any]
    feature_schema_id: str
    fit_time_seconds: float


def train_baseline_model(
    model_id: str,
    X_train: np.ndarray,
    y_train: np.ndarray,
    seed: int = 42,
    custom_params: Dict[str, Any] | None = None,
) -> BaselineModelBundle:
    """
    Trains one model from the B0 - B4 baseline ladder strictly on the provided training partition.
    """
    import time
    params = custom_params or {}
    t0 = time.perf_counter()

    if model_id == "b0_prevalence":
        clf = DummyClassifier(strategy="prior")
        hyperparams = {"strategy": "prior"}
    elif model_id == "b1_logistic":
        C = float(params.get("C", 1.0))
        max_iter = int(params.get("max_iter", 1000))
        clf = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", LogisticRegression(C=C, max_iter=max_iter, random_state=seed)),
        ])
        hyperparams = {"C": C, "max_iter": max_iter, "penalty": "l2"}
    elif model_id in ["b2_random_forest", "b4_mlran_paper"]:
        n_estimators = int(params.get("n_estimators", 100))
        max_depth = params.get("max_depth", None)
        clf = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=seed,
            n_jobs=-1,
        )
        hyperparams = {"n_estimators": n_estimators, "max_depth": max_depth, "random_state": seed}
    elif model_id == "b3_gradient_boosting":
        max_iter = int(params.get("max_iter", 100))
        clf = HistGradientBoostingClassifier(
            max_iter=max_iter,
            random_state=seed,
        )
        hyperparams = {"max_iter": max_iter, "random_state": seed}
    else:
        raise ValueError(f"Unknown baseline model_id: '{model_id}'. Choose from: b0_prevalence, b1_logistic, b2_random_forest, b3_gradient_boosting, b4_mlran_paper")

    clf.fit(X_train, y_train)
    fit_time = time.perf_counter() - t0

    return BaselineModelBundle(
        model_id=model_id,
        model=clf,
        hyperparameters=hyperparams,
        feature_schema_id="schema-mlran-rfe-483",
        fit_time_seconds=fit_time,
    )
