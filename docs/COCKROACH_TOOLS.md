# CockroachDB tool demonstrations

## Distributed Vector Indexing

`migrations/001_initial.sql` creates a cosine vector index prefixed by tenant and service. The demo proves that compatible successful memory outranks a semantically similar obsolete failure.

On CockroachDB Cloud Basic/Serverless, vector indexing is enabled by default. RecallOps therefore
does not run `SET CLUSTER SETTING feature.vector_index.enabled = true`, which is a privileged and
unnecessary operation on that tier. The migrations issue `CREATE VECTOR INDEX` directly; migration
`020_embedding_space_vector_index.sql` creates the current tenant-, service-, and embedding-space-
prefixed index, and migration `021_drop_legacy_vector_index.sql` removes the superseded index.

## Agent Skills (reproducible engineering workflow)

RecallOps uses the official CockroachDB `designing-application-transactions` Agent Skill as its
second qualifying tool. The skill is pinned to an upstream Git SHA, applied to the CockroachDB
store, migrator, and transactional outbox paths, and recorded under `evidence/agent-skills/`.
The report separates verified controls from live-database checks and records concrete findings;
it is not a claim that reading a `SKILL.md` alone proves correctness.

Reproduce the review by checking out the recorded upstream revision, loading
`skills/cockroachdb-application-development/designing-application-transactions/SKILL.md` in an
Agent Skills-compatible coding agent, and asking it to review the exact RecallOps paths and Git
revision listed in the attestation. Run the referenced tests after applying any remediation.

The separate upstream proposal and draft PR for `verifying-agent-memory-retrieval-safety` are
open-source ecosystem contributions. They are intentionally not counted as hackathon tool use
unless and until that skill is accepted upstream and actually applied from an official revision.

## Managed MCP Server (optional read-only evidence workflow)

Copy `.vscode/mcp.json.example` to `.vscode/mcp.json`, provide the cluster ID when prompted, and authenticate with OAuth. Keep the judge demonstration read-only.

Suggested prompts:

1. List the RecallOps tables and describe the memory schema.
2. Show the latest checkout incident and its selected remediation without returning embeddings.
3. Explain the vector retrieval query and confirm tenant predicates are present.
4. Show the approval record for the incident.

The example targets the public identifier of the hackathon `recallops` cluster by default. Cluster
IDs route requests but do not authenticate them. Authorize the connection with OAuth and grant
read-only access for inspection. OAuth is preferred because it uses short-lived credentials. Never
commit an API key.

The judge-visible MCP proof is a workflow, not a claim that configuration alone proves
tool use. Before submission, run it against the deployed cluster and commit a sanitized,
timestamped attestation under `evidence/cockroach-mcp/` (never embeddings, credentials,
connection strings, or sensitive incident text). The attestation should include the tool
name/version, cluster identifier digest, command/prompt, UTC timestamp, result digest, and
the resulting schema/query-plan observation. If no such artifact exists, mark this item
pending in the submission checklist.

The intended MCP workflow is:

1. `list_databases` identifies `recallops`.
2. `list_tables` identifies `memories`, `incidents`, and `approvals`.
3. `get_table_schema` shows `VECTOR(1024)`, `source_incident_id`, and tenant-prefixed indexes.
4. `explain_query` verifies that tenant and service equality predicates make the vector index
   eligible.
5. `select_query` reads the latest incident, approval, and learned outcome without selecting the
   embedding column.

This workflow is deliberately read-only: database mutation remains inside the typed application
API, where tenant checks, idempotency, and approval policy are enforced.

## ccloud CLI (optional read-only evidence workflow)

Install the current official CLI, authenticate with `ccloud auth login`, then run:

```powershell
./scripts/ccloud-inspect.ps1
```

The command emits a sanitized JSON attestation containing the cluster state, AWS placement,
CockroachDB version, regions, and SQL identity names. It uses only `cluster info` and `cluster user
list`; it cannot mutate infrastructure and never prints connection strings or credentials.

Do not retain the date/version statement below as proof unless the command is rerun from clean
`main` and its output is attached to the submission evidence. A ccloud installation or a sample
script proves availability only; the actual read-only inspection must be executed and recorded.

Use the common sanitization and provenance requirements in
[`evidence/README.md`](../evidence/README.md) for both workflows.
