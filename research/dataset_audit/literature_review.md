# Literature review (initial evidence)

## Verified relevant sources

1. **Ransomware Detection Using Machine Learning in the Linux Kernel**
   ([arXiv:2409.06452](https://arxiv.org/abs/2409.06452)). The paper describes
   in-kernel/eBPF collection and ML-oriented Linux ransomware detection, with
   attention to latency and kernel overhead. It establishes that eBPF-backed
   real-time detection is an existing research direction; it does not validate
   this repository's sensor or its MLRan mapping.
2. **Real-Time Defense System using eBPF for Machine Learning-Based Ransomware
   Detection Method** ([CANDARW 2023 PDF](https://www.cs.hiroshima-u.ac.jp/Proceedings23/CANDAR%202023/pdfs/CANDARW2023-dDGdIIHvWRXlB0gY3qHj3/069400a213/069400a213.pdf)).
   The indexed paper describes eBPF file-operation collection, temporal
   features, and real-time defense evaluation. It makes temporal/file-operation
   monitoring a known baseline, not a novel claim by itself.
3. **LARM: Linux Anti Ransomware Monitor**
   ([ScienceDirect record](https://www.sciencedirect.com/science/article/abs/pii/S016740482500389X)).
   This is a directly relevant Linux anti-ransomware system and must be
   compared against before claiming novelty.
4. **EMW-DS:2025** (official
   [repository](https://github.com/Javadkamyabi/ebpf-malware-dataset)).
   The dataset demonstrates public eBPF syscall-trace collection for broad
   malware detection, but its published table is aggregated and not
   ransomware-specific in the README.
5. **RanSAP** ([paper DOI](https://doi.org/10.1016/j.fsidi.2021.301314)) is
   a storage-access-pattern dataset. It supports a distinct storage-I/O
   baseline, not process-attributed OS event detection.

## Evidence gaps in the current project

The existing repository has implemented causal feature extraction and an
evidence-aware policy, but its recorded replay uses companion detector
probabilities and only two controlled traces. No source inspected here proves
that this combination has been evaluated on independent Linux executions,
held-out families, early-detection damage, or measured event-loss/overhead in
this repository.

## Research integrity conclusion

Combining eBPF, temporal features, and evidence records is not by itself a
defensible gap. A gap can only be stated after comparing the selected Linux
dataset and protocol against LARM, the CANDARW system, and other primary
baselines with execution/family-disjoint evaluation.
