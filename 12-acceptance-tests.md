# Acceptance tests

## Data and reproducibility

- [ ] Manifest hashes every input and records version/license/source.
- [ ] Schema validation fails on missing label, unexpected feature, duplicated ID, or type drift.
- [ ] Split file proves zero overlap of sample/duplicate groups across partitions.
- [ ] Re-run from a clean environment reproduces predictions within declared numerical tolerance.

## Leakage gates

- [ ] A test deliberately fitting a scaler on test rows fails the pipeline check.
- [ ] Feature-selection code receives only training-fold labels.
- [ ] Test labels are inaccessible before `evaluate_locked`.
- [ ] Top feature review flags label/provenance/file-path leakage candidates.

## Policy gates

- [ ] Every score produces exactly one contract action.
- [ ] Invalid schema/quality always yields `ABSTAIN`.
- [ ] Threshold changes require a new policy version and audit event.
- [ ] Model/policy/schema version, probability, rationale, and override are logged.

## Publication gates

- [ ] Every result table gives split, N, prevalence, seed, and confidence interval.
- [ ] Upstream/source metrics are visually separated from RansomShield runs.
- [ ] N-BaIoT LODO and MLRan grouped/challenge results are not merged into one score.
- [ ] All remaining TBDs, negative results, and validity threats are disclosed.
