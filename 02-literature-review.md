# Literature review and verified citations

## Dataset anchors

1. Onwuegbuche, F. C., Olaoluwa, A., Jurcut, A. D., & Pasquale, L. (2026). *MLRan: A behavioural dataset for ransomware analysis and detection*. Journal of Network and Computer Applications, 250, 104475. [DOI](https://doi.org/10.1016/j.jnca.2026.104475) | [open project repository](https://github.com/faithfulco/mlran). The paper/repository report 4,800+ dynamically analyzed samples, 64 ransomware families, 2006–2024 coverage, and a released 483-feature selected representation. Those are source-reported facts, not independently revalidated here.
2. Meidan, Y. et al. (2018). *N-BaIoT: Network-based Detection of IoT Botnet Attacks Using Deep Autoencoders*. IEEE Pervasive Computing. [DOI](https://doi.org/10.1109/MPRV.2018.03367731) | [author manuscript](https://arxiv.org/abs/1805.03409) | [UCI dataset](https://doi.org/10.24432/C5RC8J). The paper reports nine commercially available IoT devices infected in a lab with Mirai and BASHLITE; UCI lists 115 features and 7,062,606 instances.

## Evaluation motivation

Recent ransomware-survey guidance highlights random splits and inadequate temporal testing as sources of inflated results under drift, and recommends time-aware evaluation, fixed-TPR/FPR reporting, latency, and environment disclosure: [IEEE record](https://doi.org/10.1109/AAIML67890.2026.11498152). This motivates our stronger-split protocol; it does **not** establish that any RansomShield model will outperform a baseline.

## Positioning

MLRan supplies host/sandbox behavioral features (e.g., API, registry, strings in the source work); N-BaIoT supplies aggregated network behavior. They support a shared research theme—behavioral detection under distribution shift—but represent distinct sensing layers, labels, sampling units, and deployment points. The project’s novelty should be framed as an auditable evaluation-plus-policy workflow across two related but separate security detection studies.

## Citation discipline

Use the publisher DOI for the journal article when available; retain the repository commit/tag and access date for implementation artifacts. Do not cite the reported maximum MLRan metrics as RansomShield results.
