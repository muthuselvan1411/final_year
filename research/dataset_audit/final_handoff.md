# Audit handoff

| Claim | Supporting source/artifact | Verification status | Limitation |
|---|---|---|---|
| Live collector does not invoke EADL | `collector/collector.py`, `reports/implementation_status.md` | Locally verified | No live integration claim is made. |
| MLRan is 483 tabular features | `src/ransomshield/data/loader.py`, `results/event_level_data_audit_v2/audit.json` | Locally verified | Not compatible with normalized events. |
| Local traces are controlled/synthetic | `datasets/*_results.json`, event-level audit | Locally verified | Not independent efficacy evidence. |
| Linux Zenodo candidate has 16 families and eBPF-based reports | Zenodo record 19617322 | Source-reported verified | JSON schema still requires inspection. |
| SILRAD is Windows Sysmon and CC BY 4.0 | Zenodo record 17104902 | Source-reported verified | Archive not extracted. |
| EMW-DS is public eBPF syscall data under CC BY 4.0 | Official GitHub README/LICENSE | Source-reported verified | Raw traces and exact rows not inspected. |
| Current Windows host cannot run native eBPF sensor | Makefile, native C/libbpf loader, environment | Locally verified | Linux/WSL prerequisite not tested. |
| Linux Zenodo archive contains 63 JSON files, 16 families, and 31 paired ProcOPS UUIDs | `acquisition_manifest.json`, local JSON inspection | Locally verified | Ransomware-only; no benign class, no PPID, and operation timestamps lack dates. |
| EMW-DS CSV contains 2,937 unique run-level rows with CLEAN/INFECTED labels | `acquisition_manifest.json`, local CSV inspection | Locally verified | Aggregated syscall counts; no event sequence, PID/PPID, path, or family field. |
| GuardFS release contains FUSE-derived windows and benign data | `research/experiments/guardfs_window_eval/guardfs_audit.md`, official release | Locally verified | One benign log and three named malicious logs; no execution IDs, no verified independent groups, unresolved data license, and not eBPF. |

## Bottom line

The repository has a functioning offline evidence/policy replay and a
collector/normalizer, but no verified live detector integration. The current
data is insufficient for a new event-level efficacy claim.

## Recommendation

Do not use either newly inspected dataset as the sole training/evaluation
source for the current live event-level detector. Use the Linux archive as a
candidate ransomware-family behavioral source, paired with separately
collected benign Linux traces. Keep EMW-DS as a separate run-level syscall
benchmark. Continue to keep MLRan offline. No code changes, model training, or
efficacy experiment is justified until the benign event-level data and
execution-disjoint protocol exist.

GuardFS was investigated as the next legitimate alternative and rejected for a
standalone experiment. Its five-feature window representation is useful
comparative prior art, but the release cannot support leakage-safe independent
evaluation or family generalization.
