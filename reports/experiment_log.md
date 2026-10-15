# RansomShield Experiment Log

**Governing Standard:** Every run has an entry with an immutable Run ID, manifest pointer, git commit, seed, status, and outcome.
**Rule:** No metric or claim is entered without a verified, saved artifact.

| Run ID | Timestamp | Git Commit | Config Checksum | Dataset Checksum | Split Rule | Model / Arm | Status | Outcome / Metrics Summary |
|---|---|---|---|---|---|---|---|---|
| `P0-INVENTORY-01` | 2026-10-15T12:46:28Z | `f4ce63c` | `a8f3c1d9` | `8bf6eb39` (train), `b10ed700` (test) | N/A | Dataset Ingest Validator | COMPLETED | Verified 4,880 samples, 483 features, MIT license. Provenance card written. |
| `P1-SMOKE-01` | 2026-10-15T12:35:00Z | `f4ce63c` | `9b21e04a` | `05eb9689` | `SYNTHETIC_DEV` | Pipeline Smoke Test | COMPLETED | 31/31 unit tests PASSED. All safety constraints verified. |
| `P2-MLRAN-SOURCE` | 2026-10-15T13:09:06Z | `f4ce63c` | `c104e76a` | `8bf6eb39` | `SOURCE_PROTOCOL` | B4 (MLRan Random Forest) | COMPLETED | Test N=975: Recall=0.9570, Precision=0.9549, F1=0.9560, FPR=0.0412, ROC-AUC=0.9931 |
| `P3-MLRAN-LADDER` | 2026-10-15T13:09:06Z | `f4ce63c` | `c104e76a` | `8bf6eb39` | `SOURCE_PROTOCOL` | B0–B3 Baselines | COMPLETED | B0 (Majority F1=0.0), B1 (LogReg F1=0.9710), B2 (RF F1=0.9560), B3 (GBDT F1=0.9743) |
| `P4-MLRAN-CHALLENGE` | 2026-10-15T13:22:30Z | `f4ce63c` | `e2a40b12` | `8bf6eb39` | `RANSHIELDSPLIT_v1` challenge w/ SRC-trained model | B4 on Held-out Families | **SUPERSEDED** | AUDIT FAIL: 340/495 challenge samples in SOURCE_PROTOCOL train. All 5 families in training set. Results invalid as OOD claim. |
| `P4-CHALLENGE-D-CLEAN-01` | 2026-10-15T19:52:46Z | `f4ce63c` | `run_challenge_d_clean` | `8bf6eb39` | `RANSHIELDSPLIT_v1` (fully isolated) | B4 trained on V1 train only | COMPLETED | Clean OOD: N=495, Recall=95.56%, Precision=100%, F1=97.73%. Family isolation VERIFIED. ALERT+ recall=95.56%. |
| `P5-EADL-SIMULATION` | 2026-10-15T13:22:30Z | `f4ce63c` | `e2a40b12` | `b10ed700` | `SOURCE_PROTOCOL` | B4 + EADL Policy v1.0 | COMPLETED | Containment Prec=97.07%, Benign False Escalation=2.55%, Insufficient Esc=3.66% |
| `P6-NBAIOT-DIAG` | TBD | TBD | TBD | TBD | Within-Device Diagnostic | N-BaIoT Baselines | NOT RUN | Diagnostic baseline on IoT traffic |
| `P7-NBAIOT-LODO` | TBD | TBD | TBD | TBD | Leave-One-Device-Out | N-BaIoT Baselines + EADL | NOT RUN | IoT cross-device generalization |
| `P8-ROBUSTNESS` | 2026-10-15T13:22:30Z | `f4ce63c` | `e2a40b12` | `8bf6eb39` | Fold-local CV | Feature Attribution & Stability | COMPLETED | Top features: memory injection, crypto API, shadow copy deletion. |
