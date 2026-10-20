# Dataset schema and inspection report

## Verified without archive extraction

### EMW-DS

The official README describes compressed raw system-call traces and a
published `ebpf_malware.csv`. The inspected CSV has 2,937 rows and 218 columns:
`run_id`, 216 syscall-count columns, and `label`. It has 2,937 unique run IDs,
2,000 `CLEAN` rows, and 937 `INFECTED` rows. It has no event sequence, file
path, process identifier, family identifier, or timestamp field; names such as
`time`, `getpid`, and `getppid` are syscall-count columns. The raw traces are
reported as approximately 36 GB after extraction and were not downloaded.

### Linux Ransomware Analysis Reports

The inspected archive contains 32 `Reports` JSON files and 31 `ProcOPS` JSON
files across 16 family directories, with no non-JSON files. Report dynamic
sections include `fileops`, `procops`, and `netops`. Operation records use
`ts`, `pid`, `procname`, `func`, `args`, and `ret`; ProcOPS uses the same
operation fields. `ts` is a string such as `11:16:09.376205 UTC`: it has
microsecond time-of-day precision but no date. Report metadata has
`task_start_time`, `task_end_time`, and a sample SHA-256. There is no `ppid`
field in the inspected operation schema. Thirty-one report/ProcOPS submission
UUIDs pair; one report has no corresponding ProcOPS file. The archive contains
only ransomware-family samples and no benign class.

### SILRAD

Zenodo metadata verifies Windows Sysmon logs from benign and ransomware
executables, CC BY 4.0, and a 3,587,892-byte ZIP. Exact CSV names, columns,
timestamp encoding, grouping identifiers, and class counts require archive
extraction. SILRAD must be converted only through a documented replay adapter;
its Windows semantics are not equivalent to Linux eBPF.

### IoT datasets

MedBIoT's official page verifies raw PCAP, device/phase granularity, and
legitimate/malicious traffic labels. IoT-23's supplied official page verifies
the broader labelled-traffic catalogue but not the specific record contents in
this audit. Neither provides host PID/PPID/file-operation records.

## Existing local schemas

The current normalized event contract is:

`timestamp, pid, ppid, process, exe, event_type, path, bytes, dst_ip,
dst_port, protocol, success, extra`.

The recorded traces contain valid timestamps, PIDs, PPIDs, event types, and
paths, but they are controlled local workloads. The MLRan input is a separate
483-feature tabular schema. The CSU download is an engineered CSV and is not a
replacement for either raw event telemetry or MLRan.

## Bounded inspection result

The approved 1,772,573-byte archive was downloaded from the official Zenodo API,
verified against the published MD5, and saved under `research/dataset_audit/`.
Only JSON files were extracted to a temporary directory; no executable or
binary file was present. The local SHA-256 and counts are recorded in
`acquisition_manifest.json`.

Per-file timestamp order was not consistently monotonic: 0 of 32 Reports had
monotonic operation timestamps when dynamic operation sections were combined.
An adapter must therefore parse and order relative timestamps with documented
caveats. The reports contain 34,687 operation records in aggregate, including
`write`, `rename`, and `unlink` functions. The streams include PIDs but not
PPIDs or stable process-instance IDs.

## Required next inspection

The Linux archive supports bounded operation-sequence inspection and
family-level grouping, but not benign-vs-ransomware classification, PPID-aware
evidence, or reliable absolute-time early-detection metrics. EMW-DS supports
run-level clean/infected syscall-count experiments only.
