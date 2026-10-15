# Experiment plan

| Phase | Experiment | Pass criterion | Status |
|---|---|---|---|
| P0 | provenance/schema audit | manifest, hashes, counts, labels reconciled | NOT RUN |
| P1 | pipeline smoke test | no cross-split fit; deterministic rerun | NOT RUN |
| P2 | source-protocol baseline | configuration and difference from source documented | NOT RUN |
| P3 | grouped MLRan baselines | all metrics + CIs + leakage audit | NOT RUN |
| P4 | stronger MLRan split | family/time result or explicit metadata limitation | NOT RUN |
| P5 | calibration/policy simulation | locked threshold, action distribution | NOT RUN |
| P6 | N-BaIoT within-device diagnostic | clearly labeled diagnostic only | NOT RUN |
| P7 | N-BaIoT LODO | per-device/family metrics + CIs | NOT RUN |
| P8 | robustness/explainability | stable, fold-local analysis + limitations | NOT RUN |

## Pre-registration choices to freeze before P3

Positive label, split algorithm/seed, models and grids, selection metric, false-positive target, calibration method, confidence-interval method, missing-value strategy, duplicate rule, and exclusion criteria. Any change creates `v2` and is reported as an amendment.
