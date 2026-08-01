# Benchmark evidence

Dataset: `evaluation/memory_cases.json`, schema version 1, six deterministic adversarial
cases. Run with `recallops-eval`; the same command is a required CI gate.

| Policy | Safe top-1 accuracy | Unsafe selection rate | MRR | Isolation violations |
| --- | ---: | ---: | ---: | ---: |
| Similarity-only retrieval | 33.3% | 66.7% | 0.70 | 0 |
| RecallOps outcome-aware policy | **100.0%** | **0.0%** | **1.00** | **0** |

RecallOps improves safe top-1 accuracy by 66.7 percentage points and reduces unsafe
selection by 66.7 points on this dataset. Cases cover failed-but-similar advice,
service-version incompatibility, abstention, invalid state, and tenant isolation.

These results establish a regression baseline, not a population-level efficacy claim.
The dataset is small, synthetic, deterministic, and authored with the policy. Before a
production rollout, add blinded historical incidents, expert labels, inter-rater
agreement, latency/cost distributions, calibration error, and prospective shadow-mode
evaluation. The honest scope of the claim is stronger than an inflated benchmark:
the tests prove the implemented safety invariants remain executable.
