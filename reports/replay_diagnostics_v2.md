# Recorded replay diagnostics v2

## Root cause of identical actions

The four modes share the same probability-tier logic. Temporal and process
evidence are only consulted by `_containment_supported`, which can prevent the
`CONTAINMENT_RECOMMENDED` branch. They do not alter `NO_ALERT`, `MONITOR`, or
`ALERT`.

The recorded probabilities are:

- benign windows: `0.25`
- synthetic-ransomware window: `0.75`

Both values are below `tau_contain=0.85`, so every mode necessarily selects
the probability tier (`NO_ALERT` for 0.25 and `ALERT` for 0.75). Evidence
cannot change those actions under the configured policy.

The probabilities are copied from each companion result's
`max_threat_assessment.confidence`; they are not recalculated from the
individual replayed events. They are therefore not representative per-event
model probabilities.

## Evidence findings

- Temporal evidence is present and differs:
  - benign window 0: `0.5`
  - benign window 1: `0.25`
  - synthetic-ransomware window: `0.25`
- Temporal counts differ substantially, including file modifications, renames,
  distinct paths, and event rate.
- The benign trace has one PID and is eligible for measured process context.
- The synthetic-ransomware trace contains seven PIDs, so its process evidence
  is now classified as `insufficient`, not measured single-process evidence.

## Policy sensitivity

Unit tests demonstrate that a valid measured temporal or process signal changes
a decision when probability is `0.95` (above the containment threshold):
missing/insufficient evidence produces `ALERT`, while the required measured
signal produces `CONTAINMENT_RECOMMENDED`.

## Limitations

The replay contains only three controlled workload windows. It is a functional
pipeline test, not a detection benchmark. A meaningful evidence comparison
requires many independently labeled event traces, per-window detector
probabilities or scores, stable trace/process grouping, and a predeclared
train/calibration/test split. Live collector integration remains separate.
