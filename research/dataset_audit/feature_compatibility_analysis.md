# Feature compatibility analysis

## Reliable today

The sensor reliably defines event categories, bounded file paths, PID/PPID
fields when emitted, process command names, and basic IPv4 endpoint fields.
The recorded traces prove that the normalizer and temporal/process modules can
consume these fields. This is functional compatibility, not efficacy evidence.

## Derivable from current events

Within a causal window, the existing code can derive observation count, file
modifications, rename/delete counts, distinct/repeated paths, event rate, burst
ratio, timestamp consistency, and single-process summaries. These derivations
must retain missingness and mixed-process limitations.

## Requires instrumentation or enrichment

Stable process-instance identity, genuine operation outcomes, kernel event
timestamps, ring-buffer loss counters, per-stage latency, and validated
network outcome/byte telemetry require additional sensor or loader work.
Entropy requires an explicit error state because `0.0` currently conflates
empty/failed sampling with low entropy.

## Requires a non-eBPF source or separate modality

Windows Registry semantics, Sysmon-specific fields, and PCAP-derived IoT
features are not equivalent Linux host telemetry. They require separate
adapters and models, not column-name substitution.

## Newly inspected datasets

The Linux archive is the closest source to the current Linux host telemetry:
its operation records include time-of-day timestamps, PIDs, process names,
operation names, arguments, and return values. A documented adapter could
derive relative temporal windows and operation counts. However, it lacks
PPIDs/stable process instances, has no benign class, has one unpaired report,
and its operation timestamps are not reliably ordered in file order.

EMW-DS's small CSV is a run-level matrix with 217 syscall-count features plus
`run_id` and label. It can support a separate clean-vs-infected run-level
classifier, but cannot support current temporal/process evidence, event-window
replay, early detection, or family-disjoint ransomware evaluation.

GuardFS is a related but incompatible modality: a Linux FUSE/Go-FUSE overlay
logs filesystem operations and derives five-window features
(`entropy_min`, `entropy_mean`, `entropy_max`, `sum_writes`, `sum_reads`).
The inspected release contains one benign raw log and three named malicious raw
logs, with no execution identifiers or verified independent groups. Its
relative timestamps are not universally monotonic, and the grouped tables
remove the original timestamp. It must not be merged with eBPF events, EMW-DS,
Linux operation reports, or MLRan features.

## Recommendation

Do not extend the sensor merely to reproduce EMW-DS or SILRAD columns. The
Linux archive is suitable for ransomware-family behavioral characterization and
relative-window adapter prototyping, but not alone for a supervised benign
versus ransomware detector. Use it only with separately collected benign Linux
traces and an explicit pairing/split protocol. EMW-DS should remain a separate
run-level syscall-count study. MLRan remains an offline benchmark.
