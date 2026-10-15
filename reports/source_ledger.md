# RansomShield Source Ledger

**Status:** Verified source catalog  
**Audit Date:** 2026-10-15  
**Governing Standard:** All claims are classified as *verified source-reported fact*, *locally verified*, *hypothesis*, or *NOT RUN*.

| ID | Resource / Claim | Classification | Source / URI / DOI | Verified Details | Restrictions / Limitations |
|---|---|---|---|---|---|
| E1 | MLRan Dataset | Verified source-reported fact | [MLRan GitHub](https://github.com/faithfulco/mlran)<br>[DOI: 10.1016/j.jnca.2026.104475](https://doi.org/10.1016/j.jnca.2026.104475) | Reports 4,800+ dynamically analyzed samples, 64 families, 2006–2024 collection. Released 483 selected features (MI then RFE). | Not yet downloaded or count-verified locally. No local baseline run yet. |
| E2 | MLRan Feature Extraction Pipeline | Verified source-reported fact | [MLRan GitHub](https://github.com/faithfulco/mlran) | Source reports mutual-information filtering from 6.4M+ raw features down to 24,162, followed by RFE down to 483. | Upstream commit/revision must be pinned. |
| E3 | N-BaIoT Dataset | Verified source-reported fact | [ArXiv: 1805.03409](https://arxiv.org/abs/1805.03409)<br>[UCI DOI: 10.24432/C5RC8J](https://doi.org/10.24432/C5RC8J) | Reports traffic from 9 commercial IoT devices authentically infected with Mirai and BASHLITE. | Lab dataset, historical botnet behavior; must be kept strictly separate from MLRan. |
| E4 | N-BaIoT UCI Catalog Dimensions | Verified catalog fact | [UCI DOI: 10.24432/C5RC8J](https://doi.org/10.24432/C5RC8J) | UCI catalog lists 115 continuous features and 7,062,606 instances. | Downloaded release dimensions must be independently verified. |
| E5 | Temporal and Split Best Practices | Verified literature recommendation | [IEEE DOI: 10.1109/AAIML67890.2026.11498152](https://doi.org/10.1109/AAIML67890.2026.11498152) | Highlights random splits and inadequate temporal testing as sources of inflated performance; recommends time-aware evaluation, fixed-TPR/FPR reporting, and latency measurement. | Methodological guidance; does not imply any specific performance outcome. |
| H1 | Split Generalization Gap | Hypothesis | Internal Research Premise | Group, family, or chronological splits will show a performance gap compared to random/sample splits. | NOT RUN. To be evaluated under Phase 3–5. |
| H2 | Calibrated Operational Decision Layer (EADL) | Hypothesis | Internal Research Premise | Validation-locked calibrated thresholds with structured action tiers (ALLOW, REVIEW, CONTAIN_CANDIDATE, ABSTAIN) improve decision safety under fixed false-positive budgets. | NOT RUN. Dependent on validation set calibration. |
| H3 | N-BaIoT Device Generalization Gap | Hypothesis | Internal Research Premise | Leave-one-device-out (LODO) evaluation will yield lower detection performance than within-device random splits. | NOT RUN. To be tested in separate N-BaIoT study. |
