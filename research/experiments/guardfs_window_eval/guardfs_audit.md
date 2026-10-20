# GuardFS / FS-MTD-Detection audit

Audit date: 2026-10-20

## Official sources

- Paper: https://arxiv.org/html/2401.17917v1
- Resource index: https://github.com/Cyber-Tracer/guardfs
- Model/data repository: https://github.com/Cyber-Tracer/FS-MTD-Detection
- Collected-data release: https://github.com/Cyber-Tracer/FS-MTD-Detection/releases/tag/MA_Robert_Oles
- Testbed: https://github.com/Cyber-Tracer/Ransomare-Testbed

## Access and license

The collected-data release is publicly downloadable as
`MA_collected_data_analysis.zip` (135,776,262 bytes). The release exposes no
separate dataset license, data card, checksum, or redistribution terms. The
FS-MTD-Detection repository contains a New BSD license for the repository code
(the text identifies the Go-FUSE authors); that code license must not be
treated as a license for the collected CSV data. Attribution to the GuardFS
paper and Cyber-Tracer repositories is required for any research use, but
permission to redistribute or publish the data itself remains unverified.

The archive was downloaded for bounded inspection only. It was not executed.
The archive listing contained CSV logs, Python/Jupyter analysis material,
figures, a serialized model, and Git metadata. No filename with an executable
extension was observed in the archive listing. Malware samples referenced by
the repositories were not downloaded.

## Collection method and platform

GuardFS is a Linux FUSE/Go-FUSE overlay filesystem. File operations are
intercepted at the filesystem layer, not collected by eBPF. The repository's
classifier reads sequential CSV files from the overlay logger and groups rows
into fixed-width time buckets. The checked-in preprocessing code uses the
following source columns:

```text
pid, entropy, op, ext, timestamp
```

Malicious raw files additionally contain `filename`. The operation values
observed in the inspected logs are `read` and `write`. The release includes
2-second, 5-second, and 10-second derived tables. The checked-in classifier
uses a 5-second window, while the grouped release contains all three window
sizes.

## Verified release contents

The release contains these raw CSV logs:

| File | Rows excluding header | Unique PID values | Timestamp range | Operation counts |
|---|---:|---:|---:|---|
| `benign.csv` | 293,279 | 10,268 | 73–10,964 | 278,193 write; 15,086 read |
| `DarkRadiation.csv` | 1,360,598 | 8,490 | 109–2,813 | 1,242,883 write; 117,715 read |
| `Ransomware_PoC.csv` | 777,833 | 1 | 6–1,932 | 446,362 write; 331,471 read |
| `roar.csv` | 7,055 | 1 | 28–5,638 | 4,051 write; 3,004 read |

The raw timestamps are integer relative values, not wall-clock timestamps.
`DarkRadiation.csv` contains 2,154 adjacent timestamp decreases, so raw file
order is not a universally safe chronological ordering rule. The files have
no run ID, execution ID, sample hash, family column, process start/exit
marker, or collection-date field. PID values are observed, but PID is not an
independent execution identifier and cannot be used to reconstruct one.

The GuardFS resource index lists many ransomware samples used by the broader
testbed. The released collected tables inspected here contain only three
named malicious logs. The release therefore does not establish the number of
independent executions, workloads, or families beyond those file names.

## Feature provenance

### Genuinely measured or logged

- `pid`: value emitted by the overlay logger.
- `op`: intercepted operation label (`read` or `write` in the inspected CSVs).
- `ext`: file extension as logged.
- `filename`: present in malicious raw logs; absent from the benign raw log.
- `timestamp`: integer relative value emitted by the logger.
- `entropy`: logged entropy value; `-1` is used as a missing/unavailable
  sentinel in the checked-in preprocessing.

### Derived by the release preprocessing

- `time_id`: integer bucket from `timestamp // window_seconds`.
- `sum_reads` and `sum_writes`: counts within a time bucket, optionally grouped
  by PID.
- `entropy_min`, `entropy_mean`, and `entropy_max`: aggregate statistics within
  the grouped bucket.
- `entropy_ext_type`: a rule derived from a hard-coded low-entropy extension
  list and `op == "write"`; it is then used as a filter and is not retained in
  the final five-feature model table.

The released grouped tables have no label column. Class labels are inferred
from the source filename (`benign` versus `malicious_*`), which is acceptable
only as a documented release convention and not as a measured per-window
label. The grouped data also contains an unnamed CSV index column.

## Standalone experiment decision

**Decision: NO-GO for the requested defensible standalone experiment.**

The data is useful for understanding the GuardFS feature construction and for
future adapter design, but it cannot support an execution-disjoint evaluation:

1. There is one benign log and three named malicious logs, with no independent
   execution identifiers.
2. Adjacent windows from the same log would be correlated. Random-window
   train/test splitting would leak source-log and workload characteristics.
3. The three malicious files do not establish three independent executions,
   three ransomware families, or family-held-out evaluation.
4. The benign file has a different raw schema because it lacks `filename`.
5. The time values are relative integers, and at least one raw stream is not
   monotonic.
6. The archive has no verified data license or provenance manifest.
7. GuardFS feature windows are FUSE filesystem observations, not eBPF events
   and cannot be merged with MLRan, EMW-DS, or Linux operation logs.

Accordingly, no accuracy, precision, recall, F1, ROC-AUC, PR-AUC, false
positive rate, or family-generalization result was computed. A random-window
baseline would be mathematically computable but scientifically misleading.

## Reproducibility record

- Archive size: 135,776,262 bytes.
- Archive SHA-256:
  `c3a56b1d971eab007a80a5059169fab97c55e08e42c9147e1f2e3ec1561aa558`.
- Data and extracted CSVs are ignored by the local experiment `.gitignore`.
- No production source, collector, sensor, policy, model, or existing result
  was changed.

## What would remove the blocker

The publisher would need to provide a data manifest identifying each workload
and execution, stable source/sample identifiers, labels, timestamp semantics,
and data-use terms. Alternatively, new labelled benign and ransomware runs
would need to be collected with those identifiers. Only then should a
group-disjoint window evaluation be implemented.
