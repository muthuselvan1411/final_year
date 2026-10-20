# Recommended research direction

## Recommendation: Path D, then Path C

1. **Collect/obtain additional labelled Linux traces first (Path D).**
   Inspect and, with approval, acquire the Linux Ransomware Analysis archive.
   Use only reports/telemetry metadata; never retrieve or execute malware
   binaries.
2. **Retain MLRan as an offline benchmark and develop a separate live detector
   (Path C).** Do not map normalized events into the frozen 483-feature model.

## Why

- The current sensor and MLRan schemas are incompatible.
- Two local controlled traces cannot support grouped training/testing.
- EMW-DS is promising but its published table is aggregated syscall counts and
  its raw archive is very large.
- SILRAD is Windows Sysmon and is best used for supplementary replay only.
- The Linux Zenodo archive is the most directly relevant ransomware source: 16
  Linux families, 32 reports, 31 ProcOPS files, dynamic operation records,
  eBPF-based tracing, and open CC BY 4.0. It is ransomware-only and lacks
  PPID/stable process instances.
- EMW-DS supplies 2,937 labelled clean/infected run-level rows, but not event
  sequences or ransomware-family labels in the CSV.
- GuardFS supplies a related FUSE filesystem-window release, but its data
  manifest is missing, its license is unresolved, and its collected tables
  provide only one benign log and three named malicious logs without
  execution identifiers.

## Prerequisites

- Approval to download and inspect the Linux Zenodo ZIP.
- Confirm actual JSON event keys, timestamp units, process identity, execution
  IDs, labels, and family grouping.
- Obtain enough benign and independent executions for group-disjoint splits.
- Define or train a separate event-window model with its own schema/version.
- Only then consider the smallest safe live adapter; until then, a live policy
  integration must return `ABSTAIN` when no probability is available.

## Immediate next steps

1. Collect or obtain separately labelled benign Linux traces.
2. Define a documented parser for the Zenodo operation records, including
   relative UTC time handling and raw-argument provenance.
3. Freeze an event-window schema and execution/family-disjoint split protocol.
4. Decide whether a separate event-window model can be trained.
5. Add tests and implementation only after approval.

GuardFS is rejected as the next standalone benchmark. It should remain a
documented comparative reference for entropy and read/write window features,
not a source for RansomShield training, live integration, or family-disjoint
claims.
