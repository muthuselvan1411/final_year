# MLRan Dataset Card & Provenance Audit

**Audit Date:** 2026-10-15  
**Origin Repository:** https://github.com/faithfulco/mlran  
**Primary Citation:** Onwuegbuche et al. (2025/2026), *MLRan: A behavioural dataset for ransomware analysis and detection*, Journal of Network and Computer Applications, DOI: [10.1016/j.jnca.2026.104475](https://doi.org/10.1016/j.jnca.2026.104475)  
**License:** MIT License  
**Redistribution Status:** Feature tables permitted; no raw malware binaries stored or distributed.

---

## 1. Dataset Dimensions and Balance

| Property | Value |
|---|---|
| **Total Samples** | 4,880 |
| **Goodware (Label 0)** | 2,550 (52.3%) |
| **Ransomware (Label 1)** | 2,330 (47.7%) |
| **Unique Ransomware Families** | 65 |
| **Selected Feature Count** | 483 features (Mutual Information + Recursive Feature Elimination) |
| **Official Upstream Train Count** | 3,905 (80%) |
| **Official Upstream Test Count** | 975 (20%) |

---

## 2. Feature Schema & Behavioral Modalities

The 483 selected features capture dynamic sandbox behavioral indicators across:
- **Windows API Calls:** File manipulation, thread injection, crypto APIs (`CryptEncrypt`, `CryptAcquireContext`), memory allocations.
- **Filesystem Activity:** Directory enumeration, file extension renaming, shadow copy deletion (`vssadmin`).
- **Registry Modifications:** Persistence keys (`CurrentVersion\Run`), security provider modifications.
- **Process & Network Activity:** Child process spawning, socket connections, command-line arguments.

---

## 3. Leakage Protection & Provenance Controls

1. **Exact Hash Deduplication:** Samples are tracked by SHA-256 in `mlran_dataset_metadata.csv`.
2. **Locked Partitioning:**
   - `SOURCE_PROTOCOL`: Preserves the exact 3,905 train / 975 test partition used in the source publication.
   - `RANSHIELDSPLIT_v1`: Evaluates generalization on held-out ransomware families strictly excluded from training.
3. **No Target Leakage:** File paths, hashes, and provenance metadata are excluded from feature matrices.
