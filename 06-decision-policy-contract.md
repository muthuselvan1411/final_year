# Decision-policy contract

## Inputs

`p_malicious`, calibrated probability; `model_version`; `feature_schema_version`; `data_quality_ok`; `ood_score` (optional, validated); and policy version. The model may score; only the policy proposes an action.

## Contract (proposed; must be validation-locked)

| Condition | Action | Audit fields |
|---|---|---|
| schema/quality fails | `ABSTAIN` | failing checks |
| high OOD or low confidence | `REVIEW` | score, threshold |
| `p >= tau_contain` and safeguards pass | `CONTAIN_CANDIDATE` | probability, threshold, feature rationale |
| `tau_alert <= p < tau_contain` | `ALERT_REVIEW` | probability, queue priority |
| `p < tau_alert` | `ALLOW_LOG` | probability/model version |

`tau_alert`, `tau_contain`, confidence and OOD thresholds are **TBD**. They must be selected on validation according to a stated false-positive budget and reviewed by the deployment owner. A research classifier should not automatically contain a host.

## Invariants

- Same input + model + policy versions produces the same proposed action.
- Thresholds are versioned and cannot be modified by test outcomes.
- Any operator override has a reason and does not overwrite the original recommendation.
- Feature attribution is explanatory evidence, never proof of causation.
