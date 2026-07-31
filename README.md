# RecallOps

RecallOps is an outcome-conditioned incident-response agent. It recalls prior incidents by semantic similarity, rejects operationally incompatible memories, proposes bounded remediations, and requires explicit human approval before consequential actions.

This is a new project for the CockroachDB × AWS Build with Agentic Memory Hackathon. Its architectural starting points are disclosed in [docs/PROVENANCE.md](docs/PROVENANCE.md).

## What is implemented

- CockroachDB-backed structured incident state and 1024-dimensional distributed vector memory.
- Tenant-prefixed vector retrieval and application-level tenant isolation.
- Outcome, confidence, and service-version-aware memory ranking.
- Idempotent incident ingestion.
- Closed-loop outcome learning: resolved incidents become idempotent, attributable vector memories.
- Mandatory approval records for mutating remediation proposals.
- Amazon Bedrock Converse reasoning and Titan embeddings behind explicit provider flags.
- Versioned, encrypted Amazon S3 evidence archival when a bucket is configured.
- Deterministic offline providers for tests and a no-credentials local demo.

## Run locally

```bash
docker compose up --build
```

Open `http://localhost:8080/docs`. CockroachDB Console is at `http://localhost:8081`.

Seed three incident memories and run the outcome-conditioned retrieval scenario:

```powershell
docker compose --profile seed run --rm seed
./scripts/demo.ps1
```

The demo analyzes an incident, records the operator's decision, observes the real outcome, and
persists that experience as memory for future incidents. Re-running the seed is safe: the three
demonstration memories use deterministic identifiers.

For development without Docker:

```bash
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"
.venv/Scripts/pytest
```

## Enable Amazon Bedrock

Use an AWS identity limited to `bedrock:InvokeModel` for the configured models:

```text
RECALLOPS_REASONING_PROVIDER=bedrock
RECALLOPS_EMBEDDING_PROVIDER=bedrock
RECALLOPS_AWS_REGION=us-east-1
```

Do not place AWS credentials in this repository. Use an ECS task role or another short-lived AWS credential provider.

## Safety boundary

RecallOps does not execute infrastructure mutations in this milestone. It proposes a typed action, labels it as read-only or mutating, and persists at most one human decision per incident. Execution adapters will require allowlisted operations, least-privilege roles, timeouts, and postcondition checks.

## Validation

```bash
ruff check .
mypy
pytest --cov=recallops --cov-report=term-missing
```

## License

MIT

## AWS and CockroachDB tools

- AWS Fargate task resources: `infra/aws/cloudformation.yaml`
- Managed MCP and ccloud judge flow: `docs/COCKROACH_TOOLS.md`
