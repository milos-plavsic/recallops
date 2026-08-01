# CockroachDB tool demonstrations

## Distributed Vector Indexing

`migrations/001_initial.sql` creates a cosine vector index prefixed by tenant and service. The demo proves that compatible successful memory outranks a semantically similar obsolete failure.

## Managed MCP Server

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

The judge-visible MCP proof is:

1. `list_databases` identifies `recallops`.
2. `list_tables` identifies `memories`, `incidents`, and `approvals`.
3. `get_table_schema` shows `VECTOR(1024)`, `source_incident_id`, and tenant-prefixed indexes.
4. `explain_query` verifies that tenant and service equality predicates make the vector index
   eligible.
5. `select_query` reads the latest incident, approval, and learned outcome without selecting the
   embedding column.

This workflow is deliberately read-only: database mutation remains inside the typed application
API, where tenant checks, idempotency, and approval policy are enforced.

## ccloud CLI

Install the current official CLI, authenticate with `ccloud auth login`, then run:

```powershell
./scripts/ccloud-inspect.ps1
```

The command emits a sanitized JSON attestation containing the cluster state, AWS placement,
CockroachDB version, regions, and SQL identity names. It uses only `cluster info` and `cluster user
list`; it cannot mutate infrastructure and never prints connection strings or credentials.

Verified on August 1, 2026 with `ccloud 0.6.12` against the AWS-hosted CockroachDB Cloud cluster
`recallops` running CockroachDB `v26.2.1` in `us-east-1`.
