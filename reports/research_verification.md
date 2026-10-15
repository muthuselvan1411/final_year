# RansomShield Research Verification

**Status:** Phase 1 Scaffolding Complete — Pending Data Ingestion and Baseline Selection Approval  
**Date:** 2026-10-15  
**Governing Documents:** `01-scope-and-research-questions.md`, `03-mlran-reproduction.md`, `11-evidence-ledger.md`

## 1. Verified Background & Boundary

1. **Primary Study:** MLRan host-behavior tabular dataset (4,800+ samples across 64 ransomware families; 483 features).
2. **Secondary Portability Study:** N-BaIoT IoT network botnet dataset (9 devices; 115 features; Mirai/BASHLITE).
3. **Boundary Condition:** The MLRan and N-BaIoT datasets operate on completely distinct modalities and label spaces. They must NEVER be combined, concatenated, or evaluated with a single joint classifier.
4. **Safety Boundary:** Live execution, download, or persistence of ransomware or botnet binaries is strictly prohibited. Research proceeds exclusively via published feature representations and offline validation. Advisory actions (`NO_ALERT`, `MONITOR`, `ALERT`, `CONTAINMENT_RECOMMENDED` / `ALLOW_LOG`, `ALERT_REVIEW`, `CONTAIN_CANDIDATE`, `ABSTAIN`) are non-intrusive and execute no host or network disruption.

## 2. Research Questions & Status

- **RQ1 (MLRan Baseline Reproduction):** *Can documented MLRan baselines be reproduced within declared numerical tolerance?* Status: **NOT RUN**. Requires approved dataset ingestion and frozen split.
- **RQ2 (Generalization Under Group/Family Split):** *How much performance degradation occurs when evaluating on held-out families or sample clusters via `RANSHIELDSPLIT_v1`?* Status: **NOT RUN**.
- **RQ3 (Calibrated Operating Point):** *Does the model meet a pre-declared false-positive budget using validation-only calibrated thresholds?* Status: **NOT RUN**.
- **RQ4 (Feature Group Robustness):** *Which behavioral feature groups remain stable across training folds?* Status: **NOT RUN**.
- **RQ5 (Device Generalization in N-BaIoT):** *Does a device-aware protocol generalize across held-out IoT devices?* Status: **NOT RUN**.

## 3. Pre-Registration Parameter Plan (To be frozen prior to Phase 3)

- **Random Seed:** 42 (fixed across all split generation and model fits).
- **Split Hierarchy:**
  1. Exact duplicate hash / sample cluster deduplication.
  2. Partitioning into `TRAIN` (60%), `VALIDATION` (20%), and `TEST_LOCKED` (20%).
  3. Family-grouped or time-grouped holdouts assigned to `CHALLENGE` partitions when metadata is verified.
- **Leakage Controls:**
  - Feature imputation, scaling, and feature selection must be fit strictly within training folds.
  - Probability calibration (Platt scaling or isotonic regression) and decision thresholds must be fitted on `VALIDATION` only.
  - `TEST_LOCKED` labels remain untouched until a single final evaluation run.

## 4. Architectural Decision: Permanent Removal of Legacy Rule-Based Engine

- **Decision:** The legacy heuristic rule engine (e.g. ad-hoc manual rules scoring entropy bursts, rename counts, or extension modification heuristics) is permanently removed.
- **Rationale:** Hardcoded heuristic rule-based detection engines are brittle, prone to severe false positives on legitimate bursty/compression workloads, and cannot provide statistically sound calibrated probabilities.
- **Replacement Architecture:**
  1. **Detection:** Purely data-driven statistical and machine learning classifiers (the B0–B4 ladder: regularized logistic regression, random forests, gradient-boosted trees) trained with leakage-free fold-local preprocessing.
  2. **Operational Decisioning:** EADL policy driven strictly by validation-calibrated continuous probabilities (`p_malicious`), validation-locked thresholds (`tau_alert`, `tau_contain`), and explicit data quality checks (`ALLOW_LOG`, `ALERT_REVIEW`, `CONTAIN_CANDIDATE`, `ABSTAIN`).

