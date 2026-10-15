"""
Data Provenance and Data Card Generation for MLRan.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from ransomshield.data.loader import MLRanDataset


def generate_data_card(dataset: MLRanDataset, output_md: str | Path = "reports/DATA_CARD_MLRAN.md") -> str:
    summary = dataset.metadata_summary

    card_content = f"""# MLRan Dataset Card & Provenance Audit

**Audit Date:** 2026-10-15  
**Origin Repository:** https://github.com/faithfulco/mlran  
**Primary Citation:** Onwuegbuche et al. (2025/2026), *MLRan: A behavioural dataset for ransomware analysis and detection*, Journal of Network and Computer Applications, DOI: [10.1016/j.jnca.2026.104475](https://doi.org/10.1016/j.jnca.2026.104475)  
**License:** MIT License  
**Redistribution Status:** Feature tables permitted; no raw malware binaries stored or distributed.

---

## 1. Dataset Dimensions and Balance

| Property | Value |
|---|---|
| **Total Samples** | {summary['total_samples']:,} |
| **Goodware (Label 0)** | {summary['goodware_count']:,} ({summary['goodware_count']/summary['total_samples']*100:.1f}%) |
| **Ransomware (Label 1)** | {summary['ransomware_count']:,} ({summary['ransomware_count']/summary['total_samples']*100:.1f}%) |
| **Unique Ransomware Families** | {summary['unique_families']} |
| **Selected Feature Count** | {summary['feature_count']} features (Mutual Information + Recursive Feature Elimination) |
| **Official Upstream Train Count** | {summary['official_train_count']:,} (80%) |
| **Official Upstream Test Count** | {summary['official_test_count']:,} (20%) |

---

## 2. Feature Schema & Behavioral Modalities

The 483 selected features capture dynamic sandbox behavioral indicators across:
- **Windows API Calls:** File manipulation, thread injection, crypto APIs (`CryptEncrypt`, `CryptAcquireContext`), memory allocations.
- **Filesystem Activity:** Directory enumeration, file extension renaming, shadow copy deletion (`vssadmin`).
- **Registry Modifications:** Persistence keys (`CurrentVersion\\Run`), security provider modifications.
- **Process & Network Activity:** Child process spawning, socket connections, command-line arguments.

---

## 3. Leakage Protection & Provenance Controls

1. **Exact Hash Deduplication:** Samples are tracked by SHA-256 in `mlran_dataset_metadata.csv`.
2. **Locked Partitioning:**
   - `SOURCE_PROTOCOL`: Preserves the exact 3,905 train / 975 test partition used in the source publication.
   - `RANSHIELDSPLIT_v1`: Evaluates generalization on held-out ransomware families strictly excluded from training.
3. **No Target Leakage:** File paths, hashes, and provenance metadata are excluded from feature matrices.
"""
    out_p = Path(output_md)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    with open(out_p, "w", encoding="utf-8") as f:
        f.write(card_content)

    return card_content
