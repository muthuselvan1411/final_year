# RansomShield implementation status

## Implemented and tested

- Frozen MLRan baseline and probability-only EADL evaluation.
- Validated evidence contract with explicit availability and limitations.
- Causal temporal feature extraction for normalized timestamped event streams.
- Process-context summaries using supplied PID/PPID/process fields.
- Selectable probability-only and enhanced-evidence policy modes.
- Action-tier metrics separated from detector-level metrics.
- Versioned event-level feature contract `schema-event-window-v1` with causal
  cutoff enforcement and explicit availability masks.
- Versioned source-hash data audit under
  `results/event_level_data_audit_v2/`.

## Not claimed

- The MLRan feature table does not provide verified event ordering, timestamps,
  or process traces, so temporal/process improvements are not reported as
  MLRan detection results.
- The eBPF collector is Linux/kernel/toolchain dependent. Its native binaries
  are not a Windows live integration, and automated response remains disabled.
- Synthetic telemetry fixtures validate code paths only and are not efficacy
  evidence.
- No event-level classifier was trained: the two local controlled traces do not
  provide independent groups for disjoint train/validation/test evaluation.
- Candidate external sources and their verification gates are documented in
  `reports/event_level_acquisition_plan_v1.md`; no external data was
  downloaded.

## Recorded replay verification

`scripts/run_recorded_event_replay.py` normalizes the recorded JSONL events,
extracts causal temporal/process evidence, and invokes the probability-only,
temporal-only, process-only, and temporal-plus-process policies on the same
three recorded windows. Its outputs are under
`results/recorded_event_replay/` and are labeled
`functional_recorded_replay_only`.

The source traces contain timestamps, file-operation events, PIDs, and PPIDs,
but their companion reports identify them as controlled benign and
synthetic-ransomware workloads. They are not an independent real-world
benchmark, so their action counts are not reported as detection performance.

## Entry-point status

- `scripts/run_paired_evaluation.py`: invokes `OperationalDecisionPolicy` in
  the default `probability_only` mode. MLRan rows do not contain verified
  event-level evidence, so it does not invoke the enhanced mode.
- `scripts/run_recorded_event_replay.py`: invokes all four policy modes and
  saves per-window decisions and evidence summaries.
- `collector/collector.py`: starts the native eBPF loader and normalizes/logs
  events, but does not import or invoke `OperationalDecisionPolicy`. Live
  collector-to-EADL integration remains unimplemented and is not claimed.
- `replay/replay.py`: re-emits JSONL events only; it does not invoke EADL.

## Current verified offline artifacts

- `results/P5_paired_evaluation/paired_metrics.json`
- `results/P5_paired_evaluation/paired_predictions.csv`
- `results/P5_paired_evaluation/errors_review.csv`
