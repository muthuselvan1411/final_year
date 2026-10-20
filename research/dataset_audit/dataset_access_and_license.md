# Dataset access and license audit

| Dataset | Access | License verified | Redistribution/usage limitation |
|---|---|---|---|
| EMW-DS | Public GitHub repository and raw files. | CC BY 4.0 in repository `LICENSE`. | Attribution required; raw traces are approximately 36 GB and were not downloaded. |
| Linux Ransomware Analysis Reports | Public Zenodo record and archive. | CC BY 4.0 in Zenodo metadata. | Contains hashes of malware samples and reports; do not retrieve or execute binaries. Store only approved reports/metadata. |
| SILRAD 1.0 | Public Zenodo record and linked GitHub release. | CC BY 4.0 in Zenodo metadata. | Attribution required; Windows Sysmon data must remain a separate modality. |
| IoT-23 | Public Stratosphere catalogue. | Exact dataset-specific license not verified in this audit. | Verify terms on the dataset download page before acquiring PCAP. |
| MedBIoT | Public TalTech page with bulk/fine-grained PCAP links. | No explicit license observed on the inspected page. | Contact/verify terms before redistribution or committing derived data. |
| CSU-Ransomware-Data | Public GitHub repository. | No license declared in repository API/metadata. | Already stored as auxiliary reference only; do not redistribute or use as primary benchmark without clarification. |
| RanSAP | Public GitHub repository. | CC BY-ND 4.0 stated in README. | Attribution and no-derivatives conditions apply; repository not downloaded. |
| GuardFS / FS-MTD-Detection | Public GitHub release `MA_Robert_Oles`. | Repository code has a New BSD license; no separate license for the collected CSV release was verified. | Treat the data terms as unresolved; attribute the paper and repositories; do not redistribute until clarified. |

## Acquisition control

The Linux Zenodo inspection was approved and completed through the official API.
The archive was stored in the audit directory, hashed, and inspected as
JSON-only content. No binaries were present in the downloaded archive.

The EMW-DS CSV was downloaded from the official repository because the Linux
archive has no benign class and the task explicitly allowed inspection of the
small CSV. The approximately 36 GB raw trace archive was not downloaded.

The GuardFS collected-data release was downloaded only after its relevance and
size were established. Its 135,776,262-byte archive was hashed and inspected
as a ZIP listing plus selected CSV logs. No malware samples were downloaded or
executed. The archive and extracted data are excluded by the local experiment
`.gitignore`.
