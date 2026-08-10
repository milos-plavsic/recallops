# Official Agent Skill transaction review

Status: **provisional until the RecallOps release commit replaces `WORKTREE-PENDING` below**.

## Provenance

- Tool: CockroachDB Agent Skill `designing-application-transactions`
- Official repository: `cockroachlabs/cockroachdb-skills`
- Upstream revision: `e14e86d23ce8ee2e7e40a34ce2944c2502b6eadd`
- Skill path: `skills/cockroachdb-application-development/designing-application-transactions/SKILL.md`
- Agent: OpenAI Codex
- Invocation time: `2026-08-10T18:25:00Z`
- RecallOps revision: `WORKTREE-PENDING` (base `04606cb21100d22286758443d3b2d47c21b67e88`)
- Environment class: source and hermetic-test review; no managed-cluster claim
- Redaction: no database URLs, credentials, incident content, embeddings, or live query results

## Invocation

Review `src/recallops/store.py`, `src/recallops/migrate.py`, and
`src/recallops/outbox.py` using the official transaction-design skill. Check transaction lifetime,
retry behavior, ambiguous commits, idempotency, invariants in SQL, locking, set-based operations,
pool bounds, statement bounds, and external side effects. Report pass, fail, or unverified; do not
infer a live CockroachDB result from source alone.

## Findings

| Control | Result | Source evidence | Decision |
|---|---|---|---|
| External calls outside DB transactions | Pass | S3 delivery occurs after the outbox claim transaction | Preserve the transaction/outbox boundary |
| Incident and outbox atomicity | Pass | `PostgresStore.save_analysis` writes both in one connection transaction | Keep both writes in one unit |
| Idempotent incident creation | Pass | unique tenant/idempotency key plus `ON CONFLICT` | Replays return the stored analysis |
| Idempotent execution evidence | Pass | one row per incident and stored hash comparison | Conflicting replays fail closed |
| Governance consistency | Pass | row lock, state update, and event insert share one transaction | Retain `FOR UPDATE` on the governed memory |
| Migration serialization | Pass | singleton lock row and checksum ledger | Bounded retry handles `40001` |
| General application transaction retry | Unverified | store mutations rely on driver/implicit transaction behavior | Load-test concurrent mutations on live CockroachDB before production claims |
| Ambiguous commit handling | Pass with limitation | unique constraints make mutation replays inspectable | Never blindly replay an unkeyed mutation |
| Pool and statement bounds | Pass | pool max 10, connect timeout, server statement timeout | Verify values under representative load |
| Vector retrieval bounds | Pass | three bounded candidate lanes and bounded final result | Keep candidate multiplier configuration bounded |
| Live contention/latency behavior | Unverified | requires a representative managed cluster | Capture release evidence separately |

## Remediation applied

The review confirmed that S3 outbox delivery must use a dedicated worker identity and remain
outside API database transactions. RecallOps therefore runs an independent outbox container with
its own least-privilege database secret; the API no longer performs delivery in its lifespan.
Local Compose now uses the checksum-aware migrator rather than executing raw SQL files directly.

## Verification gate

The final release artifact passes only after:

1. `WORKTREE-PENDING` is replaced by the immutable release SHA and this file is renamed to
   `<sha>.md`;
2. unit, migration, outbox, and direct-database boundary tests pass for that SHA; and
3. the final evidence package records live-database checks separately from this source review.
