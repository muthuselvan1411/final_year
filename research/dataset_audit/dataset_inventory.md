# Dataset inventory

Audit date: 2026-10-19. Metadata was inspected from official landing pages or
repository APIs. The approved Linux archive and small EMW-DS CSV were also
downloaded and inspected; details are in `acquisition_manifest.json`.

| Dataset | Official source | What is publicly verified | Access/size | Decision |
|---|---|---|---|---|
| EMW-DS:2025 | https://github.com/Javadkamyabi/ebpf-malware-dataset | Inspected CSV: 2,937 rows, 218 columns, 2,937 unique `run_id` values, 2,000 CLEAN and 937 INFECTED. Columns are syscall counts; no timestamp, PID/PPID, path, family, or process-instance fields. | CC BY 4.0. CSV 1,664,879 bytes; SHA-256 is in `acquisition_manifest.json`; raw traces are reported at approximately 36 GB expanded. | Useful for run-level syscall-count classification, not event-window, early-detection, or process-attributed evaluation. |
| Linux Ransomware Analysis Reports | https://zenodo.org/records/19617322 | Inspected archive: 63 JSON files (32 Reports, 31 ProcOPS), 16 family directories, 32 report sample hashes. Reports contain dynamic `fileops`, `procops`, and `netops`; ProcOPS records contain `ts`, `pid`, `procname`, `func`, `args`, `ret`. | Open; CC BY 4.0. One ZIP, 1,772,573 bytes; Zenodo MD5 `7467737f1adcba777c7f6a2e31460be0`; local SHA-256 is in `acquisition_manifest.json`. | Strong Linux ransomware behavior source, but ransomware-only, no PPID field, timestamps are time-of-day strings, and one report lacks a paired ProcOPS file. |
| SILRAD 1.0 | https://zenodo.org/records/17104902 and https://github.com/JamilIsp/SILRAD-dataset/tree/SILRAD-1.0 | Windows Sysmon ransomware/goodware dataset for incremental/concept-drift work. | Open; CC BY 4.0. ZIP, 3,587,892 bytes; Zenodo MD5 `05a032e64076721bd42c5e63288b0baa`. | Supplementary Windows replay source, not Linux training data. |
| IoT-23 | https://www.stratosphereips.org/datasets | Official site describes labelled real attack traffic and free datasets; detailed IoT-23 page was not available at the supplied URL during this audit. | Access details for the specific IoT-23 files remain unverified here. | Separate network-traffic study only. |
| MedBIoT | https://cs.taltech.ee/research/data/medbiot/ | Raw PCAP in bulk and fine-grained forms; legitimate, Mirai, BashLite, and Torii traffic; device and phase-specific files; labels derive from traffic source. | Public page; license terms were not stated on the inspected page. | Separate network telemetry/model; not comparable to host ransomware events. |
| CSU-Ransomware-Data | https://github.com/CSCRC-SCREED/CSU-Ransomware-Data | Downloaded auxiliary CSV: 352,876 engineered rows, no raw Sysmon fields, no declared license. | 25,594,540 bytes; SHA-256 recorded in `data/manifests/csu_ransomware_reference.json`. | Reference only; not event-level benchmark. |
| RanSAP | https://github.com/manabu-hirano/RanSAP | CC BY-ND 4.0; ATA read/write storage access patterns with timestamp, LBA, size, entropy. | Repository is very large; not downloaded. | Separate storage-access study; no PID/PPID OS telemetry. |
| GuardFS / FS-MTD-Detection | https://github.com/Cyber-Tracer/guardfs and https://github.com/Cyber-Tracer/FS-MTD-Detection | Downloaded official collected-data release for bounded inspection. FUSE/Go-FUSE overlay logs with `pid`, `entropy`, `op`, `ext`, optional `filename`, and relative integer `timestamp`; grouped 2s/5s/10s tables derive five features. | Release ZIP 135,776,262 bytes; SHA-256 and counts are in `research/experiments/guardfs_window_eval/acquisition_manifest.json`. No separate dataset license or checksum was published. | **Rejected for standalone efficacy/family experiment**: one benign log, three named malicious logs, no execution IDs, no verified independent groups, no family labels, and not eBPF telemetry. |

## Acquisition status

Downloaded external artifacts are the CSU engineered reference, the approved
Linux JSON-only archive, and the small EMW-DS CSV. The EMW-DS raw trace archive,
SILRAD, IoT-23, and MedBIoT were not downloaded. The GuardFS release was
downloaded into the ignored research-only experiment directory and inspected
without executing any included code or samples.
