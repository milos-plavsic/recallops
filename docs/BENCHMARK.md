# Retrieval evaluation

RecallOps keeps two deliberately different evaluation layers. Neither is presented
as population-level efficacy evidence.

## 1. Synthetic policy-invariant suite

`evaluation/memory_cases.json` contains six authored score-level adversarial cases.
It tests policy arithmetic and security controls without invoking an embedder or a
database. Run it with:

```bash
uv run recallops-eval
```

The raw similarity control represents an ungoverned vector lookup. It is useful as
an isolation attack probe, but it is not a fair ranking-only comparison because it
does not apply the eligibility filter. `governed_similarity` is the fair ranking
ablation: it receives the same tenant, service, embedding-space, validity and state
filter as RecallOps.

| Policy ablation | Safe top-1 | Unsafe selection | MRR | Isolation | Eligibility |
| --- | ---: | ---: | ---: | ---: | ---: |
| Raw similarity (security probe) | 0.0% | 100.0% | 0.50 | 1 | 2 |
| Governed similarity | 33.3% | 66.7% | 0.70 | 0 | 0 |
| + outcome | 83.3% | 16.7% | 0.90 | 0 | 0 |
| + compatibility | 100.0% | 0.0% | 1.00 | 0 | 0 |
| Full RecallOps weighting | 100.0% | 0.0% | 1.00 | 0 | 0 |

The isolation metric is no longer derived after removing every ineligible item. A
candidate explicitly labeled as a tenant-boundary violation can be selected by the
raw control, and that selection increments the metric. The governed policies then
demonstrate that the same attack candidate is excluded. Eligibility violations are
reported separately because an invalid-state candidate is not necessarily a tenant
isolation failure.

The suite also reports selection coverage and correct-abstention rate. MRR is
computed only for cases with an expected memory; it is `0.0` rather than undefined
when no such cases exist.

`scripts/capture-ablation-evidence.py` reproduces all five policy variants and adds a
deterministic paired bootstrap over cases. The release artifact records the random seed,
sample count, confidence intervals, exact case count, and limitations. With only six authored
cases, even a passing interval is regression evidence rather than population-level efficacy.

## 2. Raw-text end-to-end retrieval suite

`evaluation/end_to_end_cases.json` contains raw incident and memory text rather than
preassigned similarity values. The harness executes the production components:

```text
raw incident -> DeterministicEmbedder -> MemoryStore.find_memories
             -> IncidentService abstention policy -> proposed action or abstention
```

Run the hermetic version with:

```bash
uv run recallops-eval --mode end-to-end
```

The six cases cover an identical failed remediation, version mismatch, failure-only
abstention, tenant and governance exclusion, ambiguous successful candidates and
weak evidence. The gate requires:

- 100% case-level safe top-1 accuracy;
- 0% unsafe action selection;
- 100% correct abstention on labeled abstention cases;
- 100% retrieval recall@K for expected memories;
- zero tenant isolation violations; and
- zero invalid/governance-state retrievals.

Latency mean, p50 and p95 are emitted for observability, but local sub-millisecond
numbers are not a production latency claim.

### CockroachDB/Postgres execution

The same harness can exercise `PostgresStore` and the actual vector SQL. Use only a
disposable, already migrated database because the benchmark intentionally persists
uniquely namespaced evidence rows for auditability:

```bash
export RECALLOPS_DATABASE_URL='postgresql://.../recallops_eval?...'
RECALLOPS_MIGRATIONS_DIR="$PWD/migrations" uv run recallops-migrate

export RECALLOPS_EVAL_DATABASE_URL="$RECALLOPS_DATABASE_URL"
uv run recallops-eval --mode end-to-end --candidate-multiplier 8 \
  > evaluation-report.cockroach.json
```

Never point this command at a production database. The output is the immutable
artifact to retain with a build SHA, database version, cluster class, corpus size
and `EXPLAIN ANALYZE` output. Compare latency only across equivalent environments.

`scripts/capture-managed-load.py` exercises the managed CockroachDB path at bounded concurrency
levels against an explicitly disposable database. It reports completed requests, errors,
throughput and percentile latency. This is an integration/load-step check, not a saturation,
soak, capacity, or multi-region benchmark.

## Retrieval architecture under test

Cockroach-backed retrieval now unions two bounded candidate lanes before application
reranking:

1. exact-version, positive-outcome candidates; and
2. the broad governed semantic nearest-neighbour lane.

Both lanes apply tenant, service, embedding-space, validity and active-state filters
inside SQL. They use a configurable candidate multiplier (default `8`) and are
deduplicated before outcome-aware ranking. This prevents a dense cluster of very
similar failures or obsolete memories from crowding the only safe exact-version
success out of a small semantic shortlist.

Version compatibility remains conservative and explicit. Every memory persists a versioned policy:
`exact`, `semver_patch`, or `semver_minor`. Exact equality always scores `1.0`; a reviewed
`semver_patch` policy can authorize the same major/minor line, and `semver_minor` can authorize the
same major line. Other SemVer proximity receives partial ranking credit only, while unknown version
formats never receive non-exact authorization. The default remains `exact`.

## Interpreting the evidence honestly

The synthetic suite proves executable invariants against authored candidate scores.
The deterministic end-to-end suite proves component wiring and reproducibility. A
database run proves the query path against one configured schema. None establishes
generalization to real incidents.

Before a production rollout, add at least 100 held-out historical cases, blinded SRE
labels, inter-rater agreement, bootstrap confidence intervals, action-level cost and
severity weighting, calibration error, prompt-injection cases, shortlist recall at
multiple K values, realistic corpus sizes, and prospective shadow-mode evaluation.
