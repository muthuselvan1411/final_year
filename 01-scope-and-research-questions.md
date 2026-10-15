# Scope and research questions

## Problem statement

Ransomware detection research can appear strong on a random split while failing on related samples, unseen families, future behavior, or legitimate encryption-like software. RansomShield therefore prioritizes reproducibility, generalization, calibrated actions, and transparent limitations over a headline score.

## In scope

- **Primary study:** binary ransomware-versus-goodware classification using the released MLRan feature data and documented repository workflow.
- **Secondary study:** Mirai/BASHLITE/benign detection using N-BaIoT traffic features, analyzed independently by device and attack family.
- Classical baselines, feature-selection ablations, calibration, explanations, confidence-aware policy simulation, and statistical uncertainty.

## Out of scope

- A real-time endpoint protection product, live malware execution, cross-dataset feature fusion, or a claim of preventing ransomware.
- Comparing raw accuracy between MLRan and N-BaIoT as if they measured one task.

## Research questions

| ID | Question | Evidence needed |
|---|---|---|
| RQ1 | Can documented MLRan baselines be reproduced within a predeclared tolerance? | frozen data manifest, split, metrics, run log |
| RQ2 | How much performance remains under family/group and, if metadata permits, chronological holdouts? | grouped/time split results with CIs |
| RQ3 | Does the selected model meet a predeclared false-positive operating point after calibration? | locked validation threshold; untouched test report |
| RQ4 | Which robust behavioral feature groups support decisions? | fold-local attribution and stability analysis |
| RQ5 | Does a device-aware N-BaIoT protocol generalize to held-out devices and separately identify Mirai/BASHLITE? | leave-one-device-out results, per-class metrics |

## Hypotheses (not results)

- **H1:** random or sample-level splits will be more optimistic than group-aware splits.
- **H2:** calibration plus an abstain/review option can improve action safety at a chosen false-positive budget, at a coverage cost.
- **H3:** device-held-out N-BaIoT performance will be lower than within-device evaluation.
