# RansomShield friend-project integration report

## Dashboard redesign and duplicate-row audit

The browser dashboard now has four evidence-first views: Live Monitoring,
Behavioral Analysis, Incident Investigation, and Event Explorer. The API remains
read-only over configured JSONL stores. Behavioral Analysis displays only
persisted `schema-behavior-correlation-v1` relationships and feature
availability masks; it does not reconstruct a graph or run a classifier in the
browser. The source kind (`live`, `replay`, or `simulation`), detector status,
null malicious probability, and `ABSTAIN` policy state remain visible.

The reported four-event/eight-incident symptom was traced to
`scripts/run_safe_simulation.py`: `IncidentStore` is append-only and the
simulation previously reused an existing output directory, so a second run
appended the same four source IDs. This was not React rendering or an API
pagination artifact. Simulation output now refuses to reuse an existing
`incidents.jsonl` or summary. For already-created stores, the API collapses only
exact duplicate rows using source context, source event ID, event payload, and
decision; distinct source IDs and conflicting payloads remain separate and an
integrity message reports the collapse.

`POST /api/test-simulation` runs the existing harmless four-event scenario
through `EventNormalizer`, `LiveDecisionPipeline`, and
`BehaviorCorrelationEngine` in memory. It creates no sensor output, incident
file, filesystem operation, containment action, or detector probability. The
verified result is four events, four `ABSTAIN` decisions, unavailable detector,
and persisted-style correlation records in the response.

Validation for this redesign:

- `PYTHONPATH=src python -m pytest -q`: 99 passed, one existing Starlette/httpx deprecation warning.
- `PYTHONPATH=src python -m pytest -q tests/test_dashboard_api.py tests/test_safe_simulation.py`: 7 passed.
- `python -m compileall -q collector dashboard schema src scripts tests`: passed.
- `git diff --check`: passed; Git reported only existing line-ending notices.
- `cd dashboard/web; npm test`: 1 passed.
- `cd dashboard/web; npm run build`: passed; no bundle-size warning after the redesign.

The live sensor-to-browser path remains configuration-dependent:
`ebpf/sensor_loader -> collector/collector.py -> normalizer -> live pipeline ->
incident JSONL -> dashboard/api.py -> React`. The live collector creates one
stable session context per process, but no new kernel live capture was claimed
in this validation. Recorded replay and harmless simulation are verified;
live-sensor freshness and browser delivery require a configured running
collector and decision output.

## Interactive behavioral graph

Correlation relationships now retain both source-event provenance and explicit
entity endpoints. Process/file/network relationships no longer use an event ID
as both edge endpoints. Entity IDs are capture-context scoped:

- `process:<context>:pid:<pid>`
- `file:<context>:path:<path>`
- `network:<context>:<address>:<port>`
- `event:<context>:<source-event-id>` for ordering evidence

The read-only `GET /api/graph?source=<name>` endpoint aggregates persisted
correlation records into typed nodes and edges. It preserves source contexts,
schemas, windows, relationship evidence, inference flags, details and source
event IDs. Old records without entity endpoints are not given fabricated edges;
they are omitted from the graph and returned as an explicit limitation.

The Behavioral Analysis page uses React Flow for node dragging, pan/zoom,
fit-to-view, controls, minimap, node/edge selection and an evidence inspector.
It also shows a chronological supporting-event timeline and a separate ATT&CK
panel that explicitly reports when no documented mapping has been established.
No ATT&CK technique, malicious label, threat score or detector probability is
derived from correlation features.

## Empty-graph investigation and verification

The empty graph was traced with a fresh documented
`benign_file_operations` simulation. Normalization produced four events under
`simulation:benign_file_operations`. `LiveDecisionPipeline.process_event()`
called `BehaviorCorrelationEngine.observe()` for every event, and the
append-only incident records persisted the full `correlation.relationships`
array. The final persisted correlation record contained process-to-file,
file-rename, and event-order relationships with source event IDs and entity
IDs.

The original graph endpoint correctly handled current records, but the
dashboard source being inspected contained older incident records written
before explicit `source_entity_id` and `target_entity_id` fields were added.
The API therefore skipped those legacy relationships because the previous
projection required entity endpoints. This presented as “no relationship
graph” even though the correlation evidence was present in incident records.
It was an API compatibility/projection defect, not a simulation or correlation
failure.

`GET /api/graph` now deterministically projects supported legacy relationship
types from their stored relationship details. It never turns a self-referential
event pair into an edge. Unsupported or insufficiently described relationships
remain omitted and are reported as limitations.

Fresh simulation verification produced:

- normalized events: 4
- capture contexts: 1 (`simulation:benign_file_operations`)
- graph nodes: 7
- graph edges: 18
- edges with resolvable source and target nodes: 18
- edges with source event provenance: 18
- graph schema: `schema-behavior-correlation-v1`
- source event types: `FILE_OPEN`, `FILE_CLOSE`, `FILE_RENAME`, `FILE_DELETE`
- decision output: 4 `ABSTAIN`, unavailable detector, null probability

The graph regression tests also verify legacy relationship projection,
capture-scoped graph output, non-self-referential edges, and node/edge
resolvability. The frontend now reports node/relationship counts, clears
selection and stale graph state on source changes, shows a loading state while
the graph request is pending, uses a deterministic process/file/network
layout, and distinguishes “no relationship evidence” from a graph API failure.

## Scope

Destination: `C:\Users\mu2ce\Documents\ACADEMICS\sem7\finaaal\Real_time_ransomware_detection`

Read-only source: `C:\Users\mu2ce\Documents\ACADEMICS\sem7\finaaal\another\Real_time_ransomware_detection`

The destination remained the primary project. No commit or push was performed.
No malware, ransomware binary, or destructive workload was executed.

## Components compared

The detailed comparison is in
[friend_project_comparison.md](friend_project_comparison.md). The source
decision engine was rejected because it defaults to active process isolation,
termination, and quarantine. The source validation script was rejected because
it uses Linux-only eBPF execution, network probes, destructive cleanup, and
claims efficacy from synthetic ransomware simulation. The referenced `rf_v0.2`
model was not present as a validated source artifact.

## Files created or modified

Created:

- `src/ransomshield/integration/__init__.py`
- `src/ransomshield/integration/live_pipeline.py`
- `src/ransomshield/storage/__init__.py`
- `src/ransomshield/storage/incident_store.py`
- `src/ransomshield/telemetry/guardfs_features.py`
- `tests/test_live_pipeline.py`
- `research/integration/friend_project_comparison.md`
- `research/integration/integration_report.md`

Modified:

- `collector/collector.py`: added opt-in `--decision-output`. Default
  collector logging/dashboard behavior is unchanged.

Not copied:

- Friend `engine/decision_engine.py`
- Friend databases, generated bytecode, datasets, and serialized artifacts
- Friend `rf_v0.2` claims or unsafe validation scripts

## Architecture

Before:

`eBPF sensor -> native loader -> collector -> normalizer -> JSONL/dashboard`

Offline destination path:

`recorded events -> temporal/process features -> evidence -> policy`

After this milestone, when explicitly enabled:

`eBPF sensor -> native loader -> collector -> normalizer -> live pipeline -> event features -> detector contract -> evidence -> advisory policy -> incident JSONL`

The pipeline retains the normalized event, temporal/process feature availability,
GuardFS-style derived metadata, prediction, evidence, and decision in one
common incident record.

## Model compatibility

The source project references a Random Forest `rf_v0.2`, but no corresponding
validated model and feature manifest were available in the source model tree.
The destination MLRan model expects its frozen 483-feature schema and remains
offline-only. It was not connected to live events.

The integrated `UnavailableDetector` receives the versioned event-window feature
object and returns a prediction with `malicious_probability=None`. The policy
therefore returns `ABSTAIN`. No feature values are fabricated.

The five GuardFS-style values (`entropy_min`, `entropy_mean`, `entropy_max`,
`sum_writes`, `sum_reads`) are derived only from measured normalized events.
They are recorded as evidence metadata, not used as a prediction score.

## Process-aware event isolation

The live pipeline now maintains bounded per-identity event buckets rather than
feeding one shared event deque to feature extraction. For each decision, only
events from the current identity and with finite timestamps at or before the
current event timestamp are passed to the detector, temporal features, process
context, GuardFS-style metadata, and evidence construction. An event with an
invalid timestamp receives no causal feature events.

The eBPF event structure currently provides `pid` and `ppid`, but no process
start time, cgroup identity, or stable process-instance identifier. The
identity strategy is therefore:

1. Use an explicit `process_instance_id`, `process_start_time`, or `start_time`
   field if a future telemetry source provides one.
2. Otherwise use a PID generation keyed by `(ppid, process, exe)`. A signature
   change for an existing PID starts a new generation and records a possible
   PID-reuse/identity-change limitation.
3. If PID is missing or invalid, isolate the event into a one-event anonymous
   bucket and record missing identity explicitly.

This prevents cross-process feature mixing but cannot prove that two events with
the same PID and unchanged signature are the same process. The fallback is
conservative and may split one process after metadata changes; it does not
merge potentially reused PIDs.

## Safety behavior

- No `SIGSTOP`, `SIGKILL`, process termination, quarantine, or file movement was
  integrated.
- Incident storage raises an explicit `StorageError` on persistence failure.
- Containment remains advisory through the existing policy contract.
- The collector hook is opt-in through `--decision-output`.

## eBPF loader hardening and output semantics

Before a WSL2 live test, `ebpf/sensor_loader.c` was hardened without running
or rebuilding the loader:

- Every successful `bpf_program__attach()` result is retained until shutdown.
- Any required attachment failure reports the program name and libbpf error,
  suppresses the successful-startup message, and cleans up earlier links.
- Ring-buffer and link cleanup now occurs on normal shutdown and startup
  failure paths before closing the BPF object.
- Both `config_map` updates are checked and reported.
- The loader no longer asserts `success: true`: the current kernel event has
  no syscall return/result field, so output uses `success: null` and
  `extra.success_evidence: "unavailable"`.
- Output retains the existing `timestamp` field for compatibility, but adds
  `timestamp_ns` for the kernel monotonic timestamp and
  `receive_timestamp` for the userspace `CLOCK_REALTIME` receive time.
  `extra.timestamp_source` identifies the legacy `timestamp` as
  `userspace_receive`; it must not be treated as the exact operation time.
- The Python schema and normalizer preserve nullable success and the timestamp
  fields instead of converting missing success evidence to `false` or dropping
  the kernel timestamp.

The sensor currently emits enter-side operation events and does not include
syscall return values in `struct event_t`. A future success/failure claim
requires adding and validating return-result capture in the kernel/user-space
contract; this change intentionally does not infer it from requested byte
counts or event types.

## Focused verification plan

The loader was not run and no BPF programs were attached. On a supported WSL2
Linux environment, compile to temporary paths and then verify:

1. Force an attachment failure with a deliberately incompatible test object
   or unavailable tracepoint; confirm the failing program name is printed,
   the startup success line is absent, and previously attached links are
   destroyed.
2. Force a `config_map` update failure or invalid map fixture; confirm startup
   stops with the map index and error.
3. Interrupt a successful run; confirm ring-buffer cleanup, explicit link
   destruction, and object close occur without a resource error.
4. Parse emitted JSONL and assert `timestamp_ns` is present, `receive_timestamp`
   is distinct, `extra.timestamp_source` is `userspace_receive`, and
   `success` is null unless a future event contract supplies measured results.

## Tests and verification

### Unit tests

Added `tests/test_live_pipeline.py` covering:

1. Missing detector probability produces `ABSTAIN`.
2. Detector receives event-window features and events.
3. A controlled low probability produces `NO_ALERT`.
4. A controlled high probability produces the existing advisory
   `CONTAINMENT_RECOMMENDED` action without endpoint disruption.
5. Incident JSONL includes prediction and decision records.

Additional process-isolation regression coverage verifies:

- Two PIDs produce separate event windows and process features.
- Later events from process B do not alter process A's feature values.
- Out-of-order events are sorted by the existing temporal extractor while
  future events remain excluded by the causal cutoff.
- Invalid timestamps produce unavailable/empty evidence rather than reusing
  earlier events.
- Missing PID is isolated and explicitly limited.
- A possible PID reuse or identity change creates a new conservative
  generation.

Targeted command:

```text
python -m pytest tests/test_live_pipeline.py tests/test_event_features.py tests/test_policy.py -q
11 passed in 0.12s
```

Full destination suite:

```text
python -m pytest -q
52 passed in 9.11s
```

Current full-suite result after process-aware isolation:

```text
python -m pytest -q
57 passed in 2.00s
```

These are simulation/unit and regression tests, not live eBPF tests.

### Offline replay

The existing recorded replay was not changed. It was not rerun as part of this
integration because the requested change is the opt-in live collector bridge;
existing replay tests remain the regression baseline.

### Simulated workloads

No ransomware simulator or destructive workload was run. The new tests use
in-memory normalized events and a test-only static detector.

### Live eBPF

Not run. The host is Windows, and native eBPF requires a suitable Linux
kernel/WSL2 environment, BTF support, compiled sensor object, and privileges.
Python tests do not establish live kernel functionality.

## Usage

Windows-safe pipeline/unit tests:

```powershell
cd C:\Users\mu2ce\Documents\ACADEMICS\sem7\finaaal\Real_time_ransomware_detection
$env:PYTHONPATH = "src"
python -m pytest tests\test_live_pipeline.py -q
python -m pytest -q
```

On a supported Linux host, after building and validating the existing sensor:

```bash
PYTHONPATH=src python -m collector.collector \
  --watch-dir /tmp/ransomshield_sandbox \
  --output datasets/events.jsonl \
  --decision-output datasets/incidents.jsonl \
  --no-dashboard
```

Until a validated event-window model is supplied, every pipeline prediction
with the default detector should remain `ABSTAIN`.

## Remaining blockers

1. No validated live-compatible behavioral model is available.
2. The source `rf_v0.2` model and feature metadata were not present.
3. MLRan cannot be mapped to normalized live events.
4. Native eBPF integration remains unverified on this Windows host.
5. The source validation scripts contain unsafe behavior and were intentionally
   not imported.
6. No live accuracy or performance claim is justified.

## Full captured-log replay

Added `scripts/replay_live_jsonl.py` for incremental replay through the actual
normalizer, live pipeline, unavailable detector, advisory policy, and
`IncidentStore`. It refuses to overwrite an existing `incidents.jsonl` or
`replay_summary.json` output.

The captured WSL2 log was replayed with:

```bash
PYTHONPATH=src python3 scripts/replay_live_jsonl.py \
  /tmp/ransomshield-live-test/events.jsonl \
  /tmp/ransomshield-live-test/replay_validation_20261020
```

Verified result:

```text
input_lines: 482
valid_json_records: 482
processed_events: 482
malformed_json_records: 0
normalization_failures: 0
pipeline_failures: 0
storage_failures: 0
incident_records_written: 482
decision_counts: {"ABSTAIN": 482}
```

Observed event counts were:

```text
PROCESS_EXIT: 366
PROCESS_EXEC: 104
NET_CONNECT: 6
FILE_OPEN: 2
FILE_CLOSE: 2
FILE_RENAME: 1
FILE_DELETE: 1
```

Replay output was written outside the repository to
`/tmp/ransomshield-live-test/replay_validation_20261020/`. This is functional
pipeline validation only. It does not validate kernel attachment, event-loss
rates, syscall-result accuracy, detection efficacy, or production readiness.

## Safe simulation lab

Added `scripts/run_safe_simulation.py` with two deterministic in-memory
scenarios:

- `benign_file_operations`: open, close, rename, and delete-shaped events.
- `synthetic_rapid_file_burst`: twelve rapid rename-shaped events across
  distinct paths.

No filesystem operations are performed by these scenarios. Both use the same
normalizer, live pipeline, unavailable detector, advisory policy, and optional
incident store as captured events.

Executed successfully:

```text
python scripts/run_safe_simulation.py --scenario benign_file_operations \
  --output-dir C:\Windows\Temp\ransomshield-simulation-benign
Events: 4/4
Decisions: {'ABSTAIN': 4}
Processing failures: 0

python scripts/run_safe_simulation.py --scenario synthetic_rapid_file_burst \
  --output-dir C:\Windows\Temp\ransomshield-simulation-burst
Events: 12/12
Decisions: {'ABSTAIN': 12}
Processing failures: 0
```

The Rich terminal dashboard remains the existing local dashboard. Its activity
labels now say `ADVISORY ONLY`, `BURST OBSERVED`, or `ELEVATED ACTIVITY
OBSERVED`; it no longer labels activity as a threat-level detection. There is
no HTTP API or browser frontend in this repository, so those requested surfaces
remain unimplemented rather than being represented by fabricated data.
## Evidence traceability milestone

The live pipeline now assigns every normalized event a scoped
`source_event_id`. A supplied sensor ID is retained. When no ID exists, the
normalizer hashes the canonical captured record together with a source context
and occurrence index. Live collection, replay, and simulation use distinct
contexts. The strategy distinguishes duplicate occurrences within a capture,
but does not claim global identity across independent captures.

Each incident persists the exact bounded causal event set used for feature
calculation, including supporting IDs, event types, source context, timestamp
source, feature schema and values, window boundaries, detector status, decision
basis, and limitations. Events excluded by invalid timestamps, causal cutoffs,
or process-identity isolation are not included in the supporting set.

The Rich dashboard now provides a bounded Recent Evidence Decisions panel. It
shows event IDs, decision state, feature schema, supporting-event count, and
source context while retaining the existing activity view. Malformed stored
JSONL lines are skipped rather than crashing the dashboard.
The read-only `scripts/inspect_incident.py` command provides complete incident
detail, including the triggering event, supporting events, ordered feature
values, window, decision basis, detector status, and limitations.

The previously inspected WSL replay file was generated before this provenance
change, so its absence of supporting IDs is expected for that historical
artifact. In the capture, PID 5956 had `PROCESS_EXEC` under `bash`, then
`FILE_RENAME` under `mv`, then `PROCESS_EXIT` under `mv`. Because no stable
process-instance ID or start time was available, the PID-generation fallback
isolated the rename after the process signature changed. Its one-event window
is therefore conservative and intentional. For a one-event window,
`event_rate` is `0.0` because elapsed duration is zero, while
`burst_ratio` is `1.0` because the single observed path occurs once out of one
event. Neither value is inferred as a detection.

The unavailable detector remains unchanged: it produces
`malicious_probability: null` and the advisory policy returns `ABSTAIN`.
Traceability and visualization explain observed evidence and pipeline behavior;
they do not establish live ransomware detection efficacy. The frozen MLRan
483-feature schema remains separate.

### Traceability verification

Commands executed:

```text
python -m pytest tests/test_evidence_traceability.py tests/test_event_features.py tests/test_live_pipeline.py tests/test_captured_live_replay.py -q
python -m pytest -q
python -m compileall -q collector schema src scripts tests
git diff --check
wsl.exe -d Ubuntu -- bash -lc "cd /mnt/c/Users/mu2ce/Documents/ACADEMICS/sem7/finaaal/Real_time_ransomware_detection && PYTHONPATH=src python3 scripts/replay_live_jsonl.py /tmp/ransomshield-live-test/events.jsonl /tmp/ransomshield-live-test/replay_validation_20261020_traceability"
```

Results:

- Focused provenance and replay tests: **26 passed**.
- Full Python suite: **78 passed**.
- Python syntax compilation: **passed**.
- `git diff --check`: **passed**.
- Captured replay: **482 input lines, 482 processed, 0 malformed,
  0 normalization failures, 0 pipeline failures, 0 storage failures,
  482 incidents, 482 ABSTAIN decisions**.
- The new replay output contains `triggering_event_id`,
  `triggering_source_context`, `supporting_event_ids`, `supporting_events`, and
  the dedicated `provenance` object.

## Temporal feature and process-window audit

`schema-event-window-v1` uses the following definitions over the sorted,
timestamp-valid, causal events selected by `select_causal_window_events`:

- `observation_count`: number of selected events, including non-file events;
  unit: events.
- `distinct_files`: number of distinct non-empty `path` values; unit: unique
  paths. Rename source paths in `extra.old_path` are not counted as separate
  paths because the feature operates on the normalized `path` field.
- `repeated_files`: number of distinct paths whose occurrence count is greater
  than one, not the number of repeated occurrences; unit: paths.
- `event_rate`: `observation_count / (window_end - window_start)`; unit:
  events per second. With zero elapsed duration the underlying temporal value
  is unavailable; the numeric feature vector retains `0.0` as a compatibility
  sentinel and its availability mask is now `false`.
- `burst_ratio`: `max(path occurrence count) / observation_count`; unit:
  dimensionless ratio. It is `1.0` for one event or when all events reference
  the same path. It is unavailable when there are no valid events.

The extractor sorts out-of-order valid timestamps before calculating these
values. Non-numeric and non-finite timestamps are excluded. Events later than
`decision_time` are excluded. The selected window begins at the earliest
eligible timestamp and ends at the last eligible timestamp, capped at
`window_start + window_seconds`.

The captured harmless WSL2 log contains two FILE_OPEN/FILE_CLOSE pairs:

- PID 5827: `1792481020.200291` to `1792481020.200307`, duration
  `0.000016` seconds, rate `2 / 0.000016 = 125000 events/second`.
- PID 5950: `1792481020.211776` to `1792481020.211935`, duration
  `0.000159` seconds, rate approximately `12578.616 events/second`.

Both pairs have `observation_count=2`, `distinct_files=1`,
`repeated_files=1`, and `burst_ratio=1.0`. These are arithmetic properties
of the timestamps and paths, not detection results.

Process-aware live decisions isolate events by explicit instance identity when
available, otherwise by PID generation keyed by `(ppid, process, exe)`.
This prevents unrelated processes from contributing to one process's features,
but can split a related operation sequence when a command changes process
metadata or when one process delegates work to a child. The captured PID 5956
rename is an example: `bash` execution and `mv` rename were separated
conservatively.

A bounded causal time window across processes could complement this design as a
separate correlation view, but must not replace per-process evidence or feed a
single-process feature vector. A safe future design would retain per-process
windows as the authoritative detector input and compute an explicitly labeled
cross-process summary keyed by parent/process relationships, with its own
supporting-event IDs, causal cutoff, identity limitations, and tests for
unrelated-process non-mixing. It is not implemented in this milestone.

## Behavioral correlation engine

The project now includes a separate, evidence-only correlation layer in
`src/ransomshield/telemetry/behavior_correlation.py`. Its schema is
`schema-behavior-correlation-v1`; it does not modify
`schema-event-window-v1`, the frozen `schema-mlran-rfe-483` schema, the
detector interface, or the advisory policy.

The data flow is:

```text
normalized event
  -> LiveDecisionPipeline
  -> per-process schema-event-window-v1 features (unchanged)
  -> BehaviorCorrelationEngine capture-scoped bounded state
  -> correlation result and relationship provenance
  -> EvidenceRecord and IncidentStore JSONL
  -> existing detector/policy path (unchanged)
```

`BehaviorCorrelationEngine` partitions state by `source_context`, retains at
most the configured event count per context, limits the number of contexts,
and applies a bounded causal window. Events without a source context are
isolated to their own observation context rather than correlated with other
captures.

Kernel `timestamp_ns` is preferred for ordering when valid. Events without a
matching valid kernel timestamp are not mixed into that ordering view. When
kernel time is unavailable, a finite event timestamp is used. Future events,
invalid timestamps, and events outside the configured window are excluded.
Original event timestamps remain in the supporting event payloads, and the
result records `timestamp_source`, `timestamp_unit`, and window boundaries.
Equal source event IDs are not deduplicated; separate observations remain
separate and are ordered deterministically by arrival sequence.

Cross-process correlation is intentionally conservative. A process can be
included with another process only when both are in the same capture context
and valid `pid`/`ppid` metadata supports a parent-child relationship. Time
proximity alone does not connect unrelated processes. The engine records
`process_spawned_by`, `process_performed_file_operation`,
`process_made_network_connection_attempt`, `file_rename_observed`, and
timestamp-supported `event_order` relationships. Network relationships record
destination evidence and preserve `success: null`; they do not claim that a
connection succeeded.

The initial descriptive features are:

| Feature | Definition and units | Missing/unavailable behavior |
|---|---|---|
| `observation_count` | Supporting observations; events | Unavailable with no causal observations |
| `operation_type_diversity` | Count of distinct event types; types | Unavailable with no observations |
| `related_process_count` | Count of connected process IDs; processes | Unavailable with no observations |
| `parent_child_relationship_count` | Supported parent-child edges; edges | Unavailable when no edge is observed |
| `file_operation_count` | Supported file operation events; events | Unavailable with no observations |
| `network_activity_count` | Network connection/destination events; events | Unavailable with no observations |
| `rename_count` / `delete_count` | Rename/delete events; events | Unavailable with no observations |
| `distinct_file_paths` | Distinct observed non-empty paths; paths | Unavailable with no observations |
| `repeated_file_paths` | Distinct paths occurring more than once; paths | Unavailable with no observations |
| `cross_process_activity` | Whether more than one connected process is present; boolean encoded numerically | Unavailable for a single-process view |
| `file_network_temporal_relation` | Whether file and network observations have a bounded causal relationship; boolean encoded numerically | Unavailable if either modality is absent |
| `process_identity_quality` | Whether every supporting event has a valid positive PID; boolean encoded numerically | Unavailable with no observations |

Every persisted correlation result includes its schema ID, capture context,
triggering event ID, exact supporting IDs, relationship records, feature
values and availability mask, window bounds, timestamp source/unit, ordering
IDs, limitations, and correlation rationale. The same correlation metadata is
also exposed in the `EvidenceRecord`.

The new layer remains a behavioral organization mechanism, not a ransomware
classifier. With the default unavailable detector, persisted records continue
to contain `malicious_probability: null` and the policy continues to return
`ABSTAIN`. No correlation feature is mapped to the MLRan 483-feature model.

Focused tests cover parent-child file/network correlation, unrelated-process
and capture isolation, invalid/future/out-of-order timestamps, duplicate IDs,
missing identities, bounded expiry, deterministic relationship provenance,
IncidentStore persistence, and unchanged unavailable-detector behavior.
These tests use harmless synthetic events and do not establish live-sensor
detection efficacy.

Validation performed for this milestone:

```text
PYTHONPATH=src python -m pytest tests/test_behavior_correlation.py tests/test_live_pipeline.py tests/test_evidence_traceability.py tests/test_event_features.py tests/test_telemetry_features.py -q
34 passed

PYTHONPATH=src python -m pytest -q
90 passed

python -m compileall -q collector schema src scripts tests
git diff --check
passed
```

The tests and compile checks ran against the existing working tree without
loading or attaching the eBPF sensor. No malware, destructive workload,
automatic containment, MLRan live mapping, or live detection-efficacy
measurement was performed.

## Evidence web dashboard

Added a minimal browser dashboard under `dashboard/web` and a read-only
FastAPI adapter in `dashboard/api.py`. The API is a bounded JSONL reader over
named, preconfigured sources. It does not accept arbitrary filesystem paths,
run the detector, recompute correlation, or expose containment operations.

Each configured source has a name, one of `replay`, `simulation`, or `live`
kind, an incident JSONL path, and optionally a normalized-event JSONL path.
When an event path is not supplied, the API derives a bounded event view from
persisted incident trigger/supporting payloads. Malformed lines are skipped
but counted and exposed in source status. Missing stores return an explicit
service error.

The API exposes source status, summary counts, paginated/filterable incidents,
incident detail, correlation detail, paginated events, event detail, and a
timestamp-basis-aware activity timeline. The React/Vite UI keeps source
identity visible, shows detector status and `ABSTAIN`/null probability
explicitly, renders persisted relationship records only, and displays
supporting event IDs, schemas, feature values, limitations, and timestamp
metadata. It is intentionally a restrained evidence console rather than a
second detection engine.

Dashboard validation:

```text
python -m pytest tests/test_dashboard_api.py -q
3 passed

cd dashboard/web
npm test
1 passed
npm run build
passed
```

The API tests verify source counts, malformed-line handling, pagination and
filters, incident-to-event traceability, correlation schema preservation,
explicit null success/probability values, and missing-store errors. The
frontend build is a production Vite build. These checks validate recorded
fixtures and UI/API behavior; they are not live-sensor validation or
detection-efficacy measurements.

## Behavioral correlation correctness audit

The live collector now creates one random session identifier at process
startup and passes a stable context of the form
`live:<resolved-output-path>:<session-id>` to every normalized event. Thus,
consecutive events from one live collector share a context, while two
collector sessions using the same output path receive different contexts.
Direct pipeline callers that omit a context receive a pipeline-instance
context; replay callers continue to provide their explicit capture context.
The context is not inferred from a PID or output path alone.

Correlation timestamp selection is now explicitly single-basis:

- If the triggering event has a valid kernel `timestamp_ns`, only events with
  valid kernel timestamps participate, and the window is measured in
  nanoseconds.
- If the trigger has no valid kernel timestamp, only events using the finite
  wall-clock/event timestamp participate, and the window is measured in
  seconds.
- Events using the other clock basis are excluded and a limitation records
  that exclusion.
- Missing, invalid, future, and out-of-window events are not silently used.
- Out-of-order events are sorted by the selected basis and arrival sequence.

Repeated source IDs are handled conservatively. An exact repeated delivery is
ignored for feature aggregation and recorded in `duplicate_event_ids`.
Legitimate repeated operations must have distinct source IDs and remain
separate observations. A conflicting payload for an existing source ID is
excluded from aggregation and recorded with the ID plus both the existing and
conflicting bounded payloads in `conflicting_event_details`. This prevents
silent feature inflation while preserving an audit trail.

The audit tests cover stable live-session contexts, cross-session isolation,
mixed kernel/wall-clock timestamp availability, missing and invalid timestamps,
out-of-order ordering, exact duplicate delivery, distinct repeated operations,
conflicting source-ID payloads, bounded state, incident persistence, and
unchanged unavailable-detector behavior.

Verified facts:

- `schema-event-window-v1` and its ordered feature names were not modified.
- No MLRan 483-feature file or schema was modified.
- `BehaviorCorrelationEngine` output is persisted as evidence/incident
  metadata and is not passed to the existing detector; the detector continues
  receiving `EventWindowFeatures`.
- The unavailable detector continues to produce
  `malicious_probability: null`, and the policy continues to return
  `ABSTAIN`.

Remaining assumptions and limitations:

- A collector session ID is process-local and intentionally not recoverable
  across restarts; persisted contexts distinguish sessions but cannot prove
  that two independently generated IDs refer to the same physical sensor
  boot.
- Kernel monotonic timestamps remain incomparable across boots or unrelated
  sensor sessions without a valid conversion.
- Source-ID correctness depends on the sensor or normalizer assigning stable
  occurrence IDs. Events without IDs are not deduplicated.
- Duplicate and conflict audit metadata is bounded by the configured event
  retention limit; older audit details expire with bounded state.
