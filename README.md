# RansomShield — Antigravity Research Package

## Demonstrable prototype workflow

The repository supports three explicitly different evidence sources:

- **Live sensor data:** Ubuntu WSL2/Linux eBPF events collected by
  `collector/collector.py`.
- **Recorded replay:** JSONL traces replayed through the normalizer, live
  feature pipeline, unavailable detector, advisory policy, and JSONL incident
  store.
- **Synthetic simulation:** deterministic in-memory event sequences used only
  for functional testing. They do not execute ransomware and are not efficacy
  evidence.

The current live detector is intentionally unavailable. Missing model output
produces `ABSTAIN` with a null malicious probability; it is not interpreted as
benign. The frozen MLRan 483-feature schema remains separate from live event
features.

### Replay a captured trace

```bash
PYTHONPATH=src python3 scripts/replay_live_jsonl.py \
  /tmp/ransomshield-live-test/events.jsonl \
  /tmp/ransomshield-live-test/replay-output
```

The replay refuses to overwrite existing output and writes
`incidents.jsonl` plus `replay_summary.json`.

### Run safe simulations

```bash
PYTHONPATH=src python3 scripts/run_safe_simulation.py \
  --scenario benign_file_operations \
  --output-dir /tmp/ransomshield-simulation-benign

PYTHONPATH=src python3 scripts/run_safe_simulation.py \
  --scenario synthetic_rapid_file_burst \
  --output-dir /tmp/ransomshield-simulation-burst
```

These scenarios use in-memory events only. They produce `ABSTAIN` while the
validated detector is unavailable.

### Dashboard and API status

The current dashboard is a local Rich terminal dashboard, not a web frontend.
It displays observed telemetry activity and explicitly labels its activity
heuristics as advisory; it does not display a validated ransomware probability.
No HTTP API or browser dashboard exists in the current repository, so API and
frontend requirements remain future work rather than an unvalidated second
service.

**Status:** design and reproducibility package; no RansomShield experiment has been run.  
**Purpose:** a journal-style, auditable research plan for behavioral ransomware detection (MLRan) with a *separate* IoT botnet extension (N-BaIoT: Mirai/BASHLITE). This is not a claim that the two datasets are interoperable or that any accuracy has been reproduced.

## Research claim to test

RansomShield will test whether a reproducible, leakage-controlled behavioral classifier can detect ransomware from MLRan while maintaining an explicit operating policy and a defensible false-positive analysis. A separate N-BaIoT study will test device-aware detection of Mirai and BASHLITE network behavior. The common contribution is an evaluation and decision-policy framework—not a single model trained across incompatible modalities.

## Reading order

1. [Scope and research questions](01-scope-and-research-questions.md)
2. [Evidence ledger](11-evidence-ledger.md) and [literature review](02-literature-review.md)
3. [MLRan reproduction](03-mlran-reproduction.md) and [N-BaIoT extension](04-nbaiot-extension.md)
4. [Methodology / safeguards](07-methodology-and-leakage-safeguards.md), then [metrics](08-metrics-and-statistical-analysis.md)
5. [experiment plan](09-experiment-plan.md), [result templates](10-result-templates.md), and [acceptance tests](12-acceptance-tests.md)

## Deliverables map

| File | Use |
|---|---|
| `05-system-architecture.md` | Buildable component and data-flow design |
| `06-decision-policy-contract.md` | Alert, review, block, and abstain behavior |
| `13-implementation-roadmap.md` | Staged engineering and research work |
| `14-antigravity-instructions.md` | Exact instructions for an Antigravity agent |

## Non-negotiable reporting rules

- Preserve source versions, hashes, manifests, split IDs, random seeds, package versions, and run logs.
- Do not report an MLRan-paper number as a RansomShield result.
- Never fit imputation, scaling, feature selection, calibration, or thresholds on the test partition.
- Report both a conventional grouped benchmark and at least one stronger generalization split; label them distinctly.
- Treat the MLRan host-behavior task and N-BaIoT network-traffic task as separate experiments.

## Safety

Use feature tables and published artifacts only unless an institutionally approved malware-lab procedure exists. Do not download, execute, distribute, or detonate malware as part of this package.
## Evidence traceability

Each normalized event now carries a `source_event_id` and `source_context`.
Existing sensor IDs are preserved. Otherwise the normalizer creates a
deterministic identity scoped to the capture or replay context and occurrence
index. These IDs are not globally unique across independent captures.

Persisted incident records include the triggering event, the exact causal
supporting events used by the event-window extractor, their IDs, feature
values,
window timestamps, detector status, decision basis, source context, and
limitations. The Rich dashboard's **Recent Evidence Decisions** panel displays
bounded summaries of these records. `ABSTAIN` with a null malicious probability
remains the expected result while no validated live detector is available.
For complete details from a persisted store, run:

```text
python scripts/inspect_incident.py path/to/incidents.jsonl
python scripts/inspect_incident.py path/to/incidents.jsonl --event-id rs-event-...
```

Replay and simulation records are explicitly labeled with `replay:` or
`simulation:` source contexts. Traceability demonstrates how observed events
support a decision record; it is not evidence of validated ransomware
detection performance.
