# Experiment design (not executed)

## Data and models

Keep the frozen MLRan 483-feature benchmark separate. Build a new
event-window model only if an inspected Linux dataset and local collection
provide compatible fields. Use a simple file-operation threshold as a
transparent baseline, then compare a live-compatible classifier with and
without temporal/process features.

## Splitting

- Independent unit: execution/trace, never an individual row or adjacent
  window.
- Training, validation, and locked test partitions are execution-disjoint.
- A challenge partition is family-disjoint when at least two independent
  families remain for training.
- Deduplicate exact/near-identical traces before splitting.
- Fit preprocessing, calibration, and thresholds on training/validation only.

## Arms and metrics

1. File-operation threshold baseline.
2. Event-count features.
3. Causal temporal-window features.
4. Temporal plus process-context features.
5. Probability-only policy.
6. Evidence-aware policy with advisory tiers.

Report precision, recall, F1, PR-AUC, ROC-AUC, false-positive rate, alert-tier
recall, containment-tier precision, calibration error, confidence intervals,
detection delay, files modified before first actionable alert, CPU, memory,
throughput, stage latency, and dropped events.

## Artifact contract

Every run must retain a unique run manifest, commit, configuration, package
versions, source URL/license, input hashes, split membership, model/schema
versions, normalized events, evidence records, decisions, errors, latency,
and test results. Existing results must never be overwritten.

## Sufficiency

Current local traces and the Linux archive alone are insufficient for
benign-vs-ransomware efficacy: the local traces have only two controlled
executions and the archive is ransomware-only. The EMW-DS CSV is insufficient
for event-window or early-detection evaluation because it contains aggregated
run-level syscall counts. The design is therefore a plan only and has not been
executed.
