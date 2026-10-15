# N-BaIoT Mirai/BASHLITE extension (separate study)

## Why separate

N-BaIoT is a network-traffic dataset; MLRan is a ransomware behavioral dataset. Neither label space nor feature space permits a scientifically valid pooled model without a separately justified representation and deployment question. This extension is a parallel validation of the RansomShield evaluation and policy concepts.

## Source facts

The [UCI record](https://doi.org/10.24432/C5RC8J) describes traffic from nine commercial IoT devices authentically infected with Mirai and BASHLITE, with 115 continuous sequential features and benign plus 10 attack classes. The original [paper](https://arxiv.org/abs/1805.03409) evaluates network-based anomaly detection using deep autoencoders.

## Tasks

- E1: benign vs malicious.
- E2: benign vs Mirai vs BASHLITE (family-level aggregation; preserve mapping).
- E3: original fine-grained classes only if label mapping is verified from downloaded files.

## Protocol

Use a device identifier as a mandatory group. Primary generalization evaluation is leave-one-device-out (LODO); validation must come from training devices only. Also report within-device chronological/block splits if ordering metadata is reliable. Never randomly mix highly adjacent snapshots across train/test without labeling the result as an optimistic diagnostic.

## Baselines and caveats

Compare regularized logistic regression, random forest/boosted trees, and an autoencoder only when its training is benign-only as intended. Report per-device and per-family recall, benign false-positive rate, macro F1, PR-AUC, and calibration. N-BaIoT’s lab setting, device repertoire, and historical botnet behavior limit claims about unseen consumer devices or current botnets.
