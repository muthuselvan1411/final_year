# RansomShield evidence contract

`EvidenceRecord` separates measured evidence from unavailable or insufficient
evidence. Missing values are not converted to zero and no field is populated
from the ground-truth label.

## Sources

- `model_probability`: calibrated detector probability, when the detector
  exposes a continuous score.
- `temporal_consistency`: fraction of observed scores above a configured
  threshold in a causal timestamped window. It is unavailable for unordered
  MLRan rows.
- `process_context`: PID, PPID, and process name only when supplied by the
  telemetry source. A PID is not globally unique across process lifetimes.
- `event_window`: ordered start/end timestamps for the observations used.

`evidence_availability` uses `measured`, `unavailable`, `insufficient`, or
`not_applicable`. `limitations` and `missing_evidence` are included in
explanations and artifacts so an advisory decision cannot imply unsupported
context.

## Policy modes

`probability_only` preserves the existing threshold policy. The optional
`enhanced_evidence` mode can require measured temporal consistency before a
containment recommendation. It never treats unavailable evidence as a negative
signal and remains advisory-only.

The frozen MLRan evaluation has no verified event ordering, timestamps, or
process trace fields. Temporal/process experiments therefore remain
unavailable for that dataset; telemetry fixtures test software behavior only.
