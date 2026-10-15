# System architecture

```text
Released feature tables → manifest + validation → split registry
                                      ↓
training-only preprocessing → candidate models → validation calibration/threshold
                                      ↓                              ↓
                               frozen model bundle ─────────→ policy engine
                                                                   ↓
                                              alert | review | contain | abstain
                                                                   ↓
                                            audit log + analyst outcome feedback
```

## Components

| Component | Responsibility | Must not do |
|---|---|---|
| Ingest | schema, hash, provenance, duplicate checks | execute samples |
| Split registry | immutable partition/group assignment | derive labels from test data |
| Feature pipeline | training-fitted transforms and validation | fit globally |
| Model service | probability + model version | make containment decision alone |
| Calibration | validation-derived probability mapping | see test labels during fitting |
| Policy engine | apply contract in `06` | silently change thresholds |
| Audit store | immutable prediction/action rationale | omit abstentions/overrides |

The architecture is a research target; it has not been implemented or deployed.
