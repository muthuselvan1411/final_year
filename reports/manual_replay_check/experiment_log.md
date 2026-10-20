# Recorded event replay diagnostics

- Result category: `functional_recorded_replay_only`
- Dataset: controlled benign and synthetic-ransomware JSONL traces
- Eligible windows: 3
- Policies: probability-only, temporal-only, process-only, temporal-plus-process
- Diagnostic fields: raw evidence features, availability, policy versions, rule IDs, and explanations
- Labels: used only for reporting metrics, never evidence construction
- Future-event leakage: prevented with decision-time cutoffs
- Automatic containment: disabled; all containment outputs are advisory
- Command: `python scripts/run_recorded_event_replay.py`

These outputs are functional pipeline checks, not independent real-world detection-performance results.
