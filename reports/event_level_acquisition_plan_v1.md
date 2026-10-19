# Event-level data acquisition plan

## Current decision

Training is **not justified**. The repository has two controlled traces (one
benign and one synthetic-ransomware-like), no independent groups for
train/validation/test, and no detector trained on `schema-event-window-v1`.
The frozen MLRan model expects 483 tabular features and must not receive these
event records.

## Candidate leads requiring verification

These are acquisition leads, not imported data or benchmark results:

| Candidate | What is promising | Blocking verification |
|---|---|---|
| [CSU Ransomware Data](https://researchoutput.csu.edu.au/en/datasets/csu-ransomware-data/) | Publicly downloadable engineered CSV with 352,876 labeled rows and 19 engineered features. | **Verified limitation:** the public release contains no raw Sysmon records, timestamps, PID/PPID fields, trace/family identifiers, or declared license. Downloaded as auxiliary reference only; see `data/manifests/csu_ransomware_reference.json`. |
| [RanSAP](https://github.com/manabu-hirano/RanSAP) | Public repository states CC BY-ND 4.0 and reports 1,044 run directories across original and extra conditions. | **Verified limitation:** records are hypervisor-level ATA read/write operations (`UNIX time`, LBA, size, entropy), not normalized OS file/PID telemetry. Kept as a separate storage-access study; not suitable for the current event schema. |
| [IEEE synthetic behavioural traces](https://ieee-dataport.org/documents/synthetic-ransomware-behavioural-trace-dataset-secure-hybrid-sandbox-evaluation) | Catalogue describes controlled benign and synthetic-ransomware traces without live malware binaries. | **Access blocked pending account/subscription:** landing-page details indicate IEEE DataPort login is required. Raw fields, independent trace count, PID/PPID coverage, and exact license terms cannot be verified or downloaded from the public page. |

One external engineered-feature reference was downloaded, but no external
dataset has passed the event-level acceptance gate. The CSU reference must not
be represented as raw telemetry or used as the primary event-level benchmark.

## Minimum acceptance gate

Acquire at least several independent benign workloads and ransomware families,
with timestamped events, stable trace/process groups, file operation types,
labels defined before feature extraction, and enough groups for disjoint
train/validation/test partitions. Record source URL, license, acquisition
date, checksums, field mapping, and label provenance.

Only then may a separately trained event-level classifier produce per-window
probabilities. Calibration and policy thresholds must use training/validation
groups only; the locked test groups must remain untouched until final scoring.
