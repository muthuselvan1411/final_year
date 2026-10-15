# MLRan dataset and baseline reproduction

## Source and status

Use only the public [MLRan repository](https://github.com/faithfulco/mlran) and its licensed released feature data. The source repository describes collection, Cuckoo submission/parsing, dataset, and experiment directories. Its reported feature path is mutual-information filtering from 6.4M+ raw features to 24,162, then RFE to 483. **No local download, parsing, or baseline run is documented in this package.**

## Reproduction protocol

1. Record repository commit, file URLs, retrieval timestamp, license, file SHA-256, row count, columns, labels, sample hashes, family labels, and collection/year metadata availability.
2. Build a data dictionary: feature type, semantics, missingness, potential target/provenance leakage, and allowed preprocessing.
3. Recreate the upstream baseline only after identifying the exact supplied split/model configuration. Treat it as `SOURCE_PROTOCOL`.
4. Create a new locked `RANSHIELDSPLIT_v1`: groups must at minimum bind exact sample hash/duplicate cluster to one partition; bind family and collection batch when metadata allows.
5. Fit every transform only on training folds. Choose hyperparameters and action threshold on validation only. Open test labels once.

## Baseline ladder

| ID | Model | Purpose |
|---|---|---|
| B0 | prevalence / majority | sanity floor |
| B1 | regularized logistic regression | interpretable linear reference |
| B2 | random forest | non-linear tree baseline |
| B3 | gradient-boosted trees (specified implementation) | competitive tabular baseline |
| B4 | source-paper model(s), exact config if recoverable | reproduction comparator |

Record implementation/version, parameter grid, selected parameters, fit time, inference time, seed, and hardware. Avoid claiming an exact source-paper reproduction if its data revision or split is unavailable.

## Required artifacts

`manifest.csv`, `schema.md`, `splits/RANSHIELDSPLIT_v1.json`, `configs/*.yaml`, `runs/<id>/metrics.json`, `predictions.parquet`, `environment.lock`, and a model card.
