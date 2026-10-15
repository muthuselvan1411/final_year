# Research evidence ledger

| ID | Claim | Type | Source / verification | Use limitation |
|---|---|---|---|---|
| E1 | MLRan reports 4,800+ samples, 64 families, 2006–2024 | verified source-reported fact | [project README](https://github.com/faithfulco/mlran), [article DOI](https://doi.org/10.1016/j.jnca.2026.104475) | not independently downloaded/count-verified |
| E2 | MLRan source reports MI then RFE and 483 selected features | verified source-reported fact | [project README](https://github.com/faithfulco/mlran) | implementation/data revision must be pinned |
| E3 | N-BaIoT contains traffic from 9 IoT devices infected with Mirai/BASHLITE | verified source-reported fact | [paper](https://arxiv.org/abs/1805.03409), [UCI DOI](https://doi.org/10.24432/C5RC8J) | lab dataset; not current deployment evidence |
| E4 | N-BaIoT UCI catalog lists 115 features and 7,062,606 instances | verified catalog fact | [UCI DOI](https://doi.org/10.24432/C5RC8J) | verify downloaded release dimensions |
| H1 | group/time/device splits may reduce apparent performance | hypothesis | design premise; test in P3–P7 | no result claimed |
| H2 | calibrated abstention may improve decision safety | hypothesis | design premise; test in P5 | depends on decision costs and validation |

**Legend:** “verified” means the linked authoritative/repository source was checked on 2026-10-15. It does not mean independently replicated. “Hypothesis” and “NOT RUN” must remain so until evidence is produced.
