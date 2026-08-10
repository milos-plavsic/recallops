# Release evidence

This directory is reserved for sanitized, immutable evidence captured from the final
deployed build. Do not add credentials, connection strings, raw incident symptoms,
access tokens, embeddings, or unredacted query results.

Before submission, add artifacts named with the deployed Git SHA:

- `cockroach-mcp/<sha>.json`: timestamped tool calls, sanitized outputs, query-plan
  digest, cluster-ID digest, and the engineering decision produced by Managed MCP;
- `agent-skills/<sha>.md`: the pinned official Agent Skill revision, invocation scope,
  inspected source revision, redacted findings, and remediation decisions;
- `ccloud/<sha>.json`: output of `scripts/ccloud-inspect.ps1`, including CLI and
  CockroachDB versions;
- `bedrock-readiness/<sha>.json`: model authorization and successful-invocation
  request IDs after the account gate clears;
- `end-to-end-cockroach/<sha>.json`: raw-text benchmark report from a disposable
  migrated CockroachDB database;
- `ablation/<sha>.json`: five-policy ablation with paired bootstrap intervals and
  explicit small-corpus limitations;
- `managed-load/<sha>.json`: bounded managed-database concurrency steps, errors,
  throughput and latency percentiles;
- `deployment/<sha>.json`: deployed image digest, ECS task definition, migration
  checksums, provider model IDs, and smoke-test timestamp; and
- `data-restore/<sha>.json`: encrypted native backup, full restore, and per-table
  content-integrity comparison;
- `resilience/<sha>.json`: controlled degradation, retry, idempotency and dead-letter
  assertions;
- `cost/<sha>.json`: deployed dimensions, observed usage, retrieved unit prices and
  explicit estimate exclusions;
- `supply-chain/<sha>.json`: lockfile, SBOM, scan, managed-signature and OCI-label
  verification; and
- `restore-drill/<sha>.md`: bounded infrastructure recovery drill result and timing.

Every artifact must identify its command, UTC timestamp, build SHA, tool version,
environment class, redaction method, and pass/fail criteria. Evidence generated from
the deterministic local provider must say so explicitly and must not be presented as
Bedrock or managed-cluster evidence.

`agent-skills/` is the second-tool proof that can be reproduced without managed-cluster
credentials. It must use a skill already present in the official CockroachDB repository at the
pinned revision. A proposed or unmerged skill contribution is ecosystem work, not eligibility
proof.
