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
validated detector is unavailable. A simulation output directory must be new;
the script refuses to append to an existing `incidents.jsonl` or summary. This
prevents a repeated four-event run from appearing as eight incident rows while
preserving legitimate observations with distinct source IDs.

### Evidence web dashboard

The repository also includes a minimal, read-only browser dashboard. It reads
persisted JSONL records through FastAPI; it does not run detection or
reconstruct behavioral correlation in the browser.

Configure named sources with a semicolon-separated environment variable:

```powershell
$env:RSHIELD_DASHBOARD_SOURCES = "replay|replay|C:\data\replay\incidents.jsonl|C:\data\replay\events.jsonl;simulation|simulation|C:\data\simulation\incidents.jsonl"
python dashboard/run_api.py
```

The source format is:

```text
name|kind|incidents_jsonl[|normalized_events_jsonl]
```

`kind` must be `replay`, `simulation`, or `live`. The API never accepts an
arbitrary filesystem path from a request. It scans configured stores with a
bounded record limit and skips malformed JSONL lines while reporting the
malformed count.

API endpoints:

- `GET /api/sources`
- `GET /api/summary?source=<name>`
- `GET /api/incidents?source=<name>&offset=0&limit=50`
- `GET /api/incidents/{index}?source=<name>`
- `GET /api/incidents/{index}/correlation?source=<name>`
- `GET /api/events?source=<name>&offset=0&limit=50`
- `GET /api/events/{source_event_id}?source=<name>`
- `GET /api/timeline?source=<name>`
- `POST /api/test-simulation` (runs the existing harmless in-memory scenario;
  it does not write sensor, incident, or operating-system state)

Run the frontend:

```powershell
cd dashboard\web
npm install
npm run dev
```

The default frontend API target is `http://localhost:8000`; set
`VITE_API_URL` when the API is hosted elsewhere. The UI labels replay,
simulation, and live sources separately, shows explicit `ABSTAIN` and null
probability states, and links incident evidence to persisted event IDs. The
navigation is organized as **Live Monitoring**, **Behavioral Analysis**,
**Incident Investigation**, and **Event Explorer**. Behavioral Analysis renders
only persisted `schema-behavior-correlation-v1` relationships, features,
availability masks, timestamp basis, and supporting IDs. **Run safe test**
exercises the same normalizer/pipeline/correlation path in memory and reports
the resulting four events and four `ABSTAIN` decisions; it is not a detector
test or efficacy measurement.

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
