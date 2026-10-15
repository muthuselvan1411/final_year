# RansomShield Publication-Readiness Audit Report

**Audit Date:** 2026-10-15
**Scope:** MLRan RansomShield evaluation - Phases P2-P5 + Challenge D

## A1. Metric Recalculation - Status: PASS

All reported baseline metrics reproduce exactly from paired_predictions.csv:
TP=445, FP=21, TN=489, FN=20, N_mal=465, N_ben=510
Recall=95.70%, Precision=95.49%, F1=95.60%, FPR=4.12%

## A2. Reconcile 95.70% Enhanced Recall - Status: REQUIRES CLARIFICATION

Three distinct recall tiers:
- Detector Recall (binary y_pred=1): 445/465 = 95.70%
- ALERT-or-higher EADL recall: 439/465 = 94.41%
- CONTAINMENT-only EADL recall: 430/465 = 92.47%

9 malicious TP samples Platt-calibrated into MONITOR tier (0.35-0.50 range).

Malicious action breakdown (N=465):
CONTAINMENT_RECOMMENDED: 430 (92.47%)
ALERT: 9 (1.94%)
MONITOR: 9 (1.94%)
NO_ALERT: 17 (3.66%)

## A3. Verify 38.1% False-Alert Reduction - Status: PASS

CONTAINMENT-only: (21-13)/21 = 38.1% (CORRECT as reported)
ALERT-or-higher: (21-20)/21 = 4.8% (must also be reported for transparency)

Benign action breakdown (N=510):
NO_ALERT: 489 (95.88%)
MONITOR: 1 (0.20%)
ALERT: 7 (1.37%)
CONTAINMENT: 13 (2.55%)

## A4. Challenge D Family Isolation - Status: CRITICAL FAIL

TRAINING LEAKAGE: 340 of 495 challenge samples appear in SOURCE_PROTOCOL training set.
All 5 held-out families (cryptolocker, locker, pajetbin, reveton, virlock) are in training.

Remediation:
Option A: Train B4 on RANSHIELDSPLIT_v1 train set (2807 samples) for legitimate OOD result.
Option B: Re-label as intra-distribution generalization (not OOD).

## A5. RFE Feature Selection - Status: PASS

Local pipeline does not re-fit RFE. Upstream limitation disclosed.
All SOURCE_PROTOCOL partitions are disjoint (3124+781+975=4880).

## A6. Overall Verdict

A1 PASS: Metrics correct
A2 CLARIFY: Report 3 recall tiers separately
A3 PASS: Add ALERT-or-higher comparison
A4 FAIL: Critical - fix before submission
A5 PASS: Add upstream disclaimer

## Complete Metric Table

Test N=975, Mal=465, Ben=510
TP=445, FP=21, TN=489, FN=20
Detector Recall=95.70%, Precision=95.49%, F1=95.60%, FPR=4.12%
ROC-AUC=0.9931
EADL: NO_ALERT=506, MONITOR=10, ALERT=16, CONTAIN=443
Mal->CONTAIN=430(92.47%), Mal->ALERT=9(1.94%), Mal->MONITOR=9(1.94%), Mal->NA=17(3.66%)
Ben->NA=489(95.88%), Ben->MON=1(0.20%), Ben->ALERT=7(1.37%), Ben->CONTAIN=13(2.55%)
ALERT-or-higher Recall=94.41%
CONTAINMENT-only Recall=92.47%
CONTAINMENT Precision=97.07%
CONTAINMENT reduction=38.1%, ALERT+ reduction=4.8%
Challenge D N=495 (all malicious), Recall=99.80%, Training leakage: 340/495
