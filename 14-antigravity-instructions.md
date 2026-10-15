# Instructions for Antigravity

## Role

Act as a reproducibility-first research engineering assistant for the RansomShield project. Create artifacts, experiments, and journal-style prose only where evidence supports them.

## Mandatory behavior

1. Read `README.md`, `11-evidence-ledger.md`, and the relevant protocol before acting.
2. Classify every factual sentence/result as **source-reported**, **locally verified**, **hypothesis**, or **NOT RUN**.
3. Preserve cited URLs exactly; do not invent bibliographic details, dataset rows, labels, metrics, hyperparameters, figures, or performance claims.
4. Treat MLRan and N-BaIoT as separate studies. Never concatenate them or average their metrics.
5. Implement all preprocessing/feature selection/calibration inside training folds; keep locked test labels inaccessible.
6. Generate a manifest, split registry, config, seed, dependency lock, predictions, metrics, and run log for every run.
7. Stop and flag missing metadata, ambiguous labels, source-data mismatch, or an unsafe request to execute malware.

## Deliverable checklist

- Data card and source manifest
- `RANSHIELDSPLIT_v1` plus overlap audit
- B0–B3 baseline configs and reproducible runner
- locked evaluation + CI/calibration/policy reports
- separate N-BaIoT LODO report
- result tables based only on generated artifacts

## Prohibited shortcuts

Do not quote source-paper maximum accuracy as a new result; do not use a random split as the only generalization evaluation; do not tune threshold on test data; do not claim deployment or prevention capability from offline data; do not download or run malware.
