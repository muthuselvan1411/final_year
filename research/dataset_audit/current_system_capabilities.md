# Current system capabilities audit

## Audit basis

- Repository commit inspected: `0123f2086008522aa336cd6aa8723f3c3edce35c`.
- Working tree was clean at audit start.
- No source, model, configuration, dataset, or existing result was modified.
- Current host is Windows; the native sensor is Linux/eBPF dependent.

## Verified data path

1. `ebpf/sensor.bpf.c` attaches Linux tracepoints and emits `event_t` records
   defined in `ebpf/event.h`.
2. `ebpf/sensor_loader.c` converts records to JSON. It maps file read/write,
   rename, delete, create, open, close, process exec/exit, and IPv4 connect
   events. It resolves `/proc/<pid>/exe` when possible and writes either stdout
   or JSONL.
3. `collector/collector.py` starts the loader, calls
   `EventNormalizer.normalize`, appends normalized JSONL, and updates the Rich
   dashboard. It does not call telemetry extraction, evidence construction, or
   the decision policy.
4. `src/ransomshield/telemetry/temporal.py` provides causal timestamp-window
   features and excludes invalid/future events.
5. `src/ransomshield/telemetry/process.py` summarizes supplied PID/PPID/process
   values and reports mixed or missing process evidence.
6. `src/ransomshield/decision/evidence.py` builds and validates an
   `EvidenceRecord`.
7. `src/ransomshield/decision/policy.py` evaluates an existing
   `PredictionRecord` and returns an advisory `DecisionRecord`.
8. `scripts/run_recorded_event_replay.py` is the only existing end-to-end path
   connecting normalized events, temporal/process evidence, and all four policy
   modes.

## Sensor fields and limitations

| Field | Current status |
|---|---|
| Event type | Measured and mapped from `event.h`; only the listed hooks are covered. |
| PID/PPID | Emitted from the kernel event structure; PID is not a durable process-instance identity. |
| Process/executable | `comm` is measured; executable path is `/proc/<pid>/exe` enrichment and can be unavailable. |
| File path/old path | Measured where the hook supplies it; bounded by fixed C buffers. |
| Bytes | Emitted for read/write records where available. |
| Network | IPv4 destination/port and a loader-emitted `"TCP"` protocol; IPv6 and robust outcome telemetry are absent. |
| Timestamp | `sensor_loader.c` uses `clock_gettime(CLOCK_REALTIME)` at user-space handling time; the kernel `timestamp_ns` is not used in the JSON timestamp. |
| Success | Normalized as `true` by the loader; operation success is not genuinely observed. |
| Entropy | Optional user-space file sample enrichment for `FILE_WRITE`; failures silently return `0.0` in `normalizer.py`. |
| Loss/latency | No persisted ring-buffer drop counter, per-stage latency, or kernel-to-user event latency artifact. |

## Model and policy boundary

The MLRan loader and validation path expects `schema-mlran-rfe-483` with 483
tabular features. Normalized events have a different schema and there is no
validated mapping or compatible event-window model. Sending live events to the
frozen MLRan model is therefore invalid. A live policy call requires an
approved event-window probability source; without one, the contract-safe output
is `ABSTAIN`.

## Reusable evidence

- `datasets/benign_events.jsonl`: 85 controlled benign events.
- `datasets/ransomware_events.jsonl`: 1,362 controlled synthetic-ransomware events.
- `results/event_level_data_audit_v2/audit.json`: confirms timestamps, PID/PPID
  coverage, trace durations, and incompatibility with MLRan.
- `results/recorded_event_replay_diagnostics_v2/`: saved evidence and policy
  diagnostics; functional replay only.

These traces are functional test inputs, not independent efficacy evidence.
