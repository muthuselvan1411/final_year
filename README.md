# RansomShield — Antigravity Research Package

**Status:** design and reproducibility package; no RansomShield experiment has been run.  
**Purpose:** a journal-style, auditable research plan for behavioral ransomware detection (MLRan) with a *separate* IoT botnet extension (N-BaIoT: Mirai/BASHLITE). This is not a claim that the two datasets are interoperable or that any accuracy has been reproduced.

## Research claim to test

RansomShield will test whether a reproducible, leakage-controlled behavioral classifier can detect ransomware from MLRan while maintaining an explicit operating policy and a defensible false-positive analysis. A separate N-BaIoT study will test device-aware detection of Mirai and BASHLITE network behavior. The common contribution is an evaluation and decision-policy framework—not a single model trained across incompatible modalities.

## Reading order

1. [Scope and research questions](01-scope-and-research-questions.md)
2. [Evidence ledger](11-evidence-ledger.md) and [literature review](02-literature-review.md)
3. [MLRan reproduction](03-mlran-reproduction.md) and [N-BaIoT extension](04-nbaiot-extension.md)
4. [Methodology / safeguards](07-methodology-and-leakage-safeguards.md), then [metrics](08-metrics-and-statistical-analysis.md)
5. [experiment plan](09-experiment-plan.md), [result templates](10-result-templates.md), and [acceptance tests](12-acceptance-tests.md)

## Deliverables map

| File | Use |
|---|---|
| `05-system-architecture.md` | Buildable component and data-flow design |
| `06-decision-policy-contract.md` | Alert, review, block, and abstain behavior |
| `13-implementation-roadmap.md` | Staged engineering and research work |
| `14-antigravity-instructions.md` | Exact instructions for an Antigravity agent |

## Non-negotiable reporting rules

- Preserve source versions, hashes, manifests, split IDs, random seeds, package versions, and run logs.
- Do not report an MLRan-paper number as a RansomShield result.
- Never fit imputation, scaling, feature selection, calibration, or thresholds on the test partition.
- Report both a conventional grouped benchmark and at least one stronger generalization split; label them distinctly.
- Treat the MLRan host-behavior task and N-BaIoT network-traffic task as separate experiments.

## Safety

Use feature tables and published artifacts only unless an institutionally approved malware-lab procedure exists. Do not download, execute, distribute, or detonate malware as part of this package.
