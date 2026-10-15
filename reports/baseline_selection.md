# RansomShield Baseline Selection Rubric & Ladder

**Status:** Proposed baseline ladder (Phase 1 Scaffold)  
**Date:** 2026-10-15  
**Governing Document:** `03-mlran-reproduction.md`

## 1. Candidate Baseline Ladder

| Model ID | Model Architecture | Role in Evaluation | Complexity / Interpretability | Output Contract Support |
|---|---|---|---|---|
| **B0** | Majority / Prevalence Dummy | Sanity floor | Trivial (no training) | Emits constant prior probability |
| **B1** | Regularized Logistic Regression (L2 / ElasticNet) | Linear baseline | High interpretability; linear feature weights | Well-calibrated logits / probabilities |
| **B2** | Random Forest Classifier | Non-linear ensemble | High robustness; tree feature importances | Voting probabilities |
| **B3** | LightGBM / XGBoost / Gradient-Boosted Trees | Competitive tabular baseline | State-of-the-art tabular accuracy | Score / sigmoid probabilities |
| **B4** | Source MLRan Paper Model(s) | Reproduction comparator | Exact parameters from MLRan repo | As specified in upstream repo |

## 2. Baseline Evaluation Criteria

1. **Continuous Output:** The model must emit continuous scores / probabilities to support calibration and EADL threshold analysis.
2. **Deterministic Reproduction:** Training must be fully seeded and parameter grids pre-declared.
3. **Training Boundary:** Preprocessing (imputer, scaler) must be encapsulated within a scikit-learn Pipeline fit strictly on training folds.
4. **Adapter Compatibility:** Model predictions must feed seamlessly into the `PredictionRecord` contract.

## 3. Approval Gate Requirement
Before running baseline training or parameter searches, the specific configurations in `configs/baseline.yaml` must be confirmed against the ingested dataset schema.
