# Methodology and split/leakage safeguards

## Partition hierarchy

1. Deduplicate exact hashes; cluster near duplicates if defensible.
2. Assign all records in a duplicate/sample group to one split.
3. For MLRan, group by ransomware family and acquisition/sandbox batch when fields exist; use chronological holdout when trustworthy dates permit.
4. For N-BaIoT, group by device for the primary LODO result; retain attack family grouping in analysis.

## Leakage controls

| Risk | Control |
|---|---|
| duplicate traces | hash/cluster audit before split |
| labels in filenames/metadata | exclude provenance-like fields; review top features |
| global scaling/imputation | fit inside each training fold only |
| feature selection on test | nested selection inside training/CV only |
| threshold tuning on test | validation-only, then freeze |
| temporal adjacency | blocked/time-aware splitting and disclosure |
| hyperparameter fishing | predeclared grids; nested CV or validation set |

## Analysis sets

- `DEV`: only for coding/smoke tests; never report as final.
- `TRAIN`: fit model/transforms.
- `VALIDATION`: tune/calibrate/select policy.
- `TEST_LOCKED`: untouched until one final evaluation.
- `CHALLENGE`: unseen-family, time, device, or dual-use stress set where available; reported separately.

Any unavailable metadata is a limitation, not permission to assume independence.
