# Metrics and statistical analysis

## Core measures

For the malicious class report: recall/TPR, precision/PPV, F1, specificity, false-positive rate, PR-AUC, ROC-AUC (secondary under imbalance), confusion matrix, and prevalence. Report sensitivity at a predeclared FPR and FPR at a predeclared TPR. For N-BaIoT add macro/weighted F1 and per-device/per-class results.

## Calibration and operations

Report Brier score, expected calibration error (with binning specified), reliability plot, threshold, alert rate, abstention/review rate, p50/p95 inference latency, and end-to-end measurement boundary. Do not infer real production latency from offline benchmark timing.

## Uncertainty and comparisons

- Use 1,000+ stratified/group-respecting bootstrap resamples for 95% confidence intervals; state resampling unit.
- Compare paired predictions on the same locked test set; use McNemar for paired error comparison when assumptions are suitable, and bootstrap the metric difference.
- Correct or explicitly label exploratory multiple comparisons. Publish seeds and intervals; avoid “best” claims on overlapping intervals without a planned comparison.

All metric values are TBD pending executed runs.
