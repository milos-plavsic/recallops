# RecallOps video proof card

Use this fixed, no-scroll split view for the 2:23–2:36 CockroachDB Agent Skill shot. It is a
recording aid, not a substitute for the linked upstream skill or implementation.

## Official CockroachDB Agent Skill

`designing-application-transactions`

- Pinned upstream revision: `e14e86d23ce8ee2e7e40a34ce2944c2502b6eadd`
- Recorded review: `evidence/agent-skills/<FINAL_RELEASE_SHA>.md`

## Visible implementation consequences

1. Incident state and its evidence-outbox row commit in one database transaction.
2. Bedrock and S3 calls remain outside database transactions.
3. CockroachDB serialization failures use bounded exponential retry and checksum-tracked migrations.

## Distributed Vector Indexing proof

Captured managed plan:
`evidence/cockroach-query-plan/<FINAL_RELEASE_SHA>.json`

Frame these redacted lines in the preceding database shot:

```text
• vector search
  table: memories@memories_embedding_v2
```

State the limitation if the artifact remains on screen long enough to read: the plan used synthetic
rows in a disposable managed database, and optimizer choices can vary with cardinality and statistics.

Do not record this card while `<FINAL_RELEASE_SHA>` remains unresolved. Generate both artifacts from
the final committed release, replace the placeholders, deploy that exact SHA, and verify it through
`/v1/system/status` first.
