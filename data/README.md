# RansomShield Data Inventory & Governance

## 1. Directory Structure

```text
data/
├── README.md               # This inventory and data policy document
├── raw/                    # Git-ignored directory for downloaded raw datasets
│   └── .gitkeep
├── manifests/              # Versioned SHA-256 data manifests and metadata
└── splits/                 # Partition membership records (e.g., RANSHIELDSPLIT_v1)
```

## 2. Governance and Redistribution Rules

1. **No Raw Data in Version Control:**
   - Raw feature tables, traces, network packet captures, and sample binaries MUST NOT be committed to git.
   - Any raw files placed in `data/raw/` are excluded by `.gitignore`.

2. **No Malware Binaries:**
   - Live ransomware or botnet binaries must never be downloaded, stored, executed, or detonated.
   - Experiments operate strictly on approved tabular feature representations.

3. **Data Provenance Requirements:**
   Every dataset utilized must have an explicit record containing:
   - Origin URL / DOI and retrieval date
   - Primary file SHA-256 checksum and size
   - Verified sample unit (e.g. sample hash, time window, packet snapshot)
   - Verified feature list, types, and schema version
   - Family / group / temporal metadata availability
   - License and permissible use terms

4. **Status of Candidate Datasets:**
   - **CSU-Ransomware-Data:** Auxiliary engineered-feature reference downloaded from https://github.com/CSCRC-SCREED/CSU-Ransomware-Data. It contains 352,876 labeled rows and 19 engineered features plus the label, not raw Sysmon event records. The source does not declare a license; do not use it as the primary event-level training, validation, or test dataset. Provenance: `data/manifests/csu_ransomware_reference.json`.
   - **MLRan:** Host-behavior ransomware feature dataset (Journal of Network and Computer Applications, 2026). Source: https://github.com/faithfulco/mlran. Local download/hash: **Pending Stage 2 / Data Approval Gate**.
   - **N-BaIoT:** Commercial IoT botnet network traffic dataset (UCI DOI: 10.24432/C5RC8J). Evaluated in a separate, unmerged portability study. Local download/hash: **Pending Stage 2 / Portability Gate**.
