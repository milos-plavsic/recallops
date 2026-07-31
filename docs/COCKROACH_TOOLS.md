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

OAuth is preferred because it uses short-lived credentials. Never commit an API key.

## ccloud CLI

Run `scripts/ccloud-inspect.ps1` after `ccloud auth login`. It emits JSON cluster and service-account evidence and does not mutate infrastructure.
