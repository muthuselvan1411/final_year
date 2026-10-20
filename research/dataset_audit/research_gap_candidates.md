# Research-gap candidates

| Candidate | Current evidence | Required additional evidence | Status |
|---|---|---|---|
| Causal temporal windows plus operational policy on independent Linux traces | Existing temporal/policy code; only controlled replay | Independent labelled executions and a compatible event-window probability model | NEEDS MORE LITERATURE |
| Process-attributed evidence reduces false escalation | Process context and policy exist; no independent event-level comparison | Baseline policy, process identity, calibration protocol, and grouped test traces | NEEDS MORE LITERATURE |
| Early detection measured by files modified before alert | Current sensor counts events but no validated live probability or damage protocol | Ordered event traces, alert-time definition, protected-file ground truth, and delay metrics | NOT FEASIBLE WITH CURRENT DATA |
| Family-disjoint Linux generalisation | Linux archive has 16 family directories, 32 reports, sample hashes, and submission UUIDs | Benign traces, validated relative-time adapter, independent execution protocol, compatible model | SUPPORTED CANDIDATE for ransomware-family characterization; detector claim blocked without benign data |
| Monitoring cost/event loss versus detection utility | Sensor has no persisted loss/overhead artifact | Linux benchmark harness, ring-buffer counters, CPU/memory/latency instrumentation | SUPPORTED CANDIDATE after instrumentation |
| IoT botnet extension | MedBIoT/IoT-23 are PCAP/network datasets | Separate network pipeline and model; no merger with ransomware host task | NOT FEASIBLE WITH CURRENT DATA |

No novelty claim is approved by this audit. The most defensible direction is
family-disjoint Linux ransomware generalisation with explicit telemetry
quality and operational-policy reporting, but it requires separately collected
benign Linux traces and must not treat the Zenodo archive alone as a complete
classification benchmark.
