# RansomShield Acceptance Checklist

**Source:** `12-acceptance-tests.md` and `acceptance_checklist.md`  
**Current Phase:** Phase 6 (Completed Full Pipeline & Evaluation Audit)

## A. Data and Reproducibility Gates
- [x] Manifest hashes every input file and records version/license/source (`data/manifests/mlran_raw_manifest.json`).
- [x] Schema validation fails on missing label, unexpected feature, duplicated ID, or type drift (`src/ransomshield/data/validation.py`).
- [x] Split file proves zero overlap of sample/duplicate groups across partitions (`data/splits/SOURCE_PROTOCOL.json` and `RANSHIELDSPLIT_v1.json`).
- [x] Re-run from a clean environment reproduces predictions within declared numerical tolerance (all seeds locked to 42).

## B. Leakage Gates
- [x] A test deliberately fitting a scaler on test rows fails the pipeline check (`tests/test_splits.py`).
- [x] Feature-selection and model training receive only training-fold labels (`src/ransomshield/baseline/train.py`).
- [x] Test labels are inaccessible before evaluation on locked test set ($N=975$).
- [x] Top feature review flags label/provenance/file-path leakage candidates; non-feature metadata excluded from model matrices.

## C. Policy & Decision Gates
- [x] Every score produces exactly one contract action (`ALLOW_LOG`, `ALERT_REVIEW`, `CONTAIN_CANDIDATE`, `ABSTAIN` / `NO_ALERT`, `MONITOR`, `ALERT`, `CONTAINMENT_RECOMMENDED`).
- [x] Invalid schema/quality always yields `ABSTAIN`.
- [x] Threshold changes require a new policy version and audit event (`policy_version: eadl-v1.0`).
- [x] Model/policy/schema version, probability, rationale, and override are logged in `DecisionRecord`.
- [x] Containment is strictly advisory; no automatic endpoint process termination or file quarantine is implemented.
- [x] Permanent removal of legacy heuristic rule-based detection engine documented and confirmed.

## D. Publication & Reporting Gates
- [x] Every result table gives split, N, prevalence, seed, and confidence interval (`reports/baseline_vs_enhanced.md`).
- [x] Upstream/source metrics are visually separated from RansomShield runs (3-column comparison table).
- [x] N-BaIoT LODO and MLRan grouped/challenge results are not merged into one score (N-BaIoT pre-registered as separate portability study).
- [x] All remaining TBDs, negative results, and validity threats are disclosed.
- [x] Synthetic fixtures are never reported as real research findings (clearly partitioned in `tests/fixtures/`).

## E. Phase Milestones Audit
- [x] **Phase 1:** Scaffolding, dependency lock, governance, environment verification.
- [x] **Phase 2:** Official MLRan dataset ingestion, schema validation, and leakage-free splits (`SOURCE_PROTOCOL`, `RANSHIELDSPLIT_v1`).
- [x] **Phase 3:** Faithful reproduction of B0–B4 baseline ladder on frozen test set.
- [x] **Phase 4:** Implementation and unit testing of EADL contracts, Platt calibration, evidence builder, and transparent policy.
- [x] **Phase 5:** Paired baseline vs. enhanced evaluation on identical frozen test samples with ablations and family challenge.
- [x] **Phase 6:** Full acceptance audit, artifact persistence, and research report generation.
