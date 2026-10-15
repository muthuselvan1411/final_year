# Results Directory

This directory stores experiment outputs, manifests, serialized predictions, and metrics.

## Guidelines
- Generated run artifacts are placed in `results/<run_id>/`.
- Each run folder contains:
  - `manifest.json`: environment, git commit, seed, config checksum, dataset checksum.
  - `config.yaml`: frozen resolved run configuration.
  - `metrics.json`: detector-level and operational decision metrics.
  - `predictions.parquet` (or `.csv`): frozen sample IDs and outputs.
  - `errors.csv`: error analysis.
- Large run data files are excluded from Git via `.gitignore`.
