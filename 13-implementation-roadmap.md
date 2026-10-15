# Implementation roadmap

## Milestone 1 — Evidence and data contract

Build a data inventory, manifest generator, schema validator, label mapper, and split registry. Deliver: immutable manifests and a `DATA_CARD.md`. Exit only after P0 acceptance tests pass.

## Milestone 2 — Reproducible tabular pipeline

Implement training-fold preprocessing, baseline models, run configuration, artifact tracking, prediction export, and deterministic smoke tests. Deliver: B0–B3 on a development subset; no final results.

## Milestone 3 — Evaluation and policy

Implement grouped/LODO splitters, locked evaluation, bootstrap CIs, calibration, threshold selection, policy simulator, and audit records. Deliver: P3–P7 reports populated only by executed runs.

## Milestone 4 — Analysis and paper

Perform error analysis, fold-local feature attribution/stability checks, limitations review, and manuscript assembly. Deliver: evidence-linked tables/figures and reproducibility appendix.

## Suggested repository layout

```text
ransomshield/
  data/{raw,manifests,splits}/   # raw excluded from version control
  configs/  src/  tests/  notebooks/  reports/  runs/
  docs/     # this package
```

Use DVC/object storage or equivalent for data artifacts; never commit samples or credentials.
