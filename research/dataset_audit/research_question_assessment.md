# Research-question assessment

## Ranking

1. **RQ4 — Robustness/generalisation:** strongest potential contribution if
   the Linux ransomware archive supplies independent executions and families.
2. **RQ5 — Monitoring cost/reliability:** highly credible and measurable, but
   requires instrumentation before results.
3. **RQ2 — Process attribution/evidence:** feasible after an event-window model
   exists; policy comparisons must not be confused with detector improvement.
4. **RQ3 — Early detection/damage:** scientifically valuable but unavailable
   until ordered traces and a live-compatible score exist.
5. **RQ1 — Temporal behaviour:** already well represented in related work and
   needs a sharper protocol to be novel.
6. **RQ6 — IoT extension:** separate study, not an efficient extension of the
   current host pipeline.

## Primary recommendation

Use RQ4 as the primary question, with RQ5 and RQ2 as supporting questions:

> Under execution- and family-disjoint evaluation, how well does a Linux
> event-window detector generalize, and how do telemetry quality and
> evidence-aware policy tiers affect operational alerts?

The inspected Zenodo archive supplies family labels, sample hashes, report
submission UUIDs, relative operation timestamps, and PIDs, but no benign class,
PPID, or stable process-instance field. The smallest credible additional data
is therefore separately collected benign Linux traces plus a documented
execution identity and time normalization protocol.

GuardFS does not remove this requirement. Its released data has one benign log
and three named malicious logs but no execution identifiers or verified
family/sample groups. It is therefore unsuitable for the primary
execution- and family-disjoint question, although its documented five-feature
window construction is useful as comparative feature-engineering prior art.
