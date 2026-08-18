# RecallOps

**Live judge demo:** https://ltfrottcxj.execute-api.us-east-1.amazonaws.com

**Demo video:** https://youtu.be/4YVucwgoJLk · **Architecture:**
[docs/recallops-architecture.png](docs/recallops-architecture.png)

RecallOps is an SRE agent that remembers whether a remediation actually worked. It uses vector
similarity to find candidates, then deterministically rejects memories from the wrong tenant,
service version, governance state, or observed outcome before proposing an action.

## See the product in 60 seconds

Open the **[live judge demo](https://ltfrottcxj.execute-api.us-east-1.amazonaws.com)** and follow
the numbered lifecycle already displayed in the result panel:

1. Click **Analyze incident**. Open **Candidate evidence** to compare the raw semantic candidates
   with the final policy decision and its rejection reasons.
2. Approve the exact proposed action, attest its execution, and record the observed outcome.
3. Confirm that the resulting memory is **PENDING REVIEW** and therefore retrieval-ineligible.
4. Switch to the independent reviewer identity and activate it.
5. Click **Analyze again** and confirm that the reviewed outcome now participates in the decision.

That proves the product's central claim in one causal path:

> retrieve evidence → propose and approve → observe outcome → hold learning for review → independently
> activate → recall during the next incident

No infrastructure mutation is performed in this milestone. “Execution” is explicitly an operator
attestation; the safety contribution is governed memory and deterministic authorization around the
reasoning layer.

### What changes the recommendation

| Stage | Evidence | Effect |
| --- | --- | --- |
| Candidate generation | CockroachDB 1024-dimensional vector search | Finds semantically similar incident memories; similarity grants no authority. |
| Eligibility gates | Tenant, service, active state, validity, and compatibility policy | Excludes memories that must never reach ranking. |
| Policy ranking | Observed outcome, version compatibility, confidence, and age | Promotes compatible successes and preserves known-failure penalties. |
| Action control | Typed risk plus persisted human approval | Prevents the LLM or deterministic reasoner from authorizing a mutation. |
| Outcome learning | Operator attestation plus independent review | Creates quarantined evidence that becomes retrievable only after four-eyes activation. |

**Concrete cloud proof:** CockroachDB stores the incident, embedding, decision, approval, outcome,
memory state, and governance event transactionally. The deployed application runs on Amazon ECS
behind API Gateway; Cognito separates operator and reviewer identities, S3 archives versioned
evidence, and CloudWatch supplies logs, metrics, and server-verifiable alarm evidence. Bedrock is an
optional provider and is deliberately not required for the reliable public judge path.

This is a new project for the CockroachDB × AWS Build with Agentic Memory Hackathon. Its architectural starting points are disclosed in [docs/PROVENANCE.md](docs/PROVENANCE.md).

**Local proof:** run `./scripts/judge-demo.ps1`. **Three-minute recording path:** follow the
[recording-day runbook](docs/VIDEO_RECORDING_RUNBOOK.md). **Deep evidence:** use the
[judge guide](docs/JUDGE_GUIDE.md) only after seeing the product loop. The curated
[evidence index](docs/EVIDENCE_INDEX.md) maps every major claim to live and reproducible proof.

[![CI](https://github.com/milos-plavsic/recallops/actions/workflows/ci.yml/badge.svg)](https://github.com/milos-plavsic/recallops/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-c8ff4d.svg)](LICENSE)

## Implementation details

- CockroachDB-backed structured incident state and 1024-dimensional distributed vector memory.
- Tenant-prefixed vector retrieval, application-level row isolation, direct-SQL composite tenant
  constraints, and separate least-privilege migration/API/outbox database roles.
- Outcome, confidence, and service-version-aware memory ranking.
- Idempotent incident ingestion.
- Closed-loop outcome learning: operator-attested outcomes become idempotent, attributable vector memories.
- Four-eyes memory governance with quarantine, activation, revocation, supersession, and audit events.
- Conservative confidence decay: positive evidence ages while known failure penalties persist.
- RS256 OIDC authentication with issuer, expiry, application, access-token, tenant, and role checks.
- Mandatory approval records for mutating remediation proposals.
- Evidence-strength claims fail closed: AWS deployments verify CloudWatch alarms or
  scoped S3 objects server-side; local mode accepts manual attestations only.
- Reliable deterministic reasoning and embeddings for the public demo, with optional Amazon Bedrock
  providers behind explicit flags; the UI reports the active provider and degradation state.
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

The demo analyzes an incident, records the operator's decision, records an operator-attested outcome,
quarantines the candidate memory, and activates it through an independent reviewer. Re-running the
seed is safe: the three demonstration memories use identifiers deterministic within each embedding
space, so switching providers never reuses incompatible vectors.

For development without Docker:

```bash
uv sync --extra dev --locked
uv run pytest
```

## Optionally enable Amazon Bedrock

Use an AWS identity limited to `bedrock:InvokeModel` for the configured models:

```text
RECALLOPS_REASONING_PROVIDER=bedrock
RECALLOPS_EMBEDDING_PROVIDER=bedrock
RECALLOPS_AWS_REGION=us-east-1
```

Bedrock is not required by the application or hackathon deployment. Do not place AWS credentials in
this repository. Use an ECS task role or another short-lived AWS credential provider.

## Enable verified identity

Local demos use explicit `X-Tenant-ID`, `X-Actor-ID`, and `X-Roles` headers. That mode is never a
production trust boundary. Public deployments set:

```text
RECALLOPS_AUTH_MODE=oidc
RECALLOPS_OIDC_ISSUER=https://cognito-idp.us-east-1.amazonaws.com/<user-pool-id>
RECALLOPS_OIDC_AUDIENCE=<app-client-id>
RECALLOPS_OIDC_TENANT_CLAIM=tenant_id
RECALLOPS_OIDC_ROLES_CLAIM=cognito:groups
```

OIDC mode accepts RS256 access tokens only. It validates the signature against the issuer JWKS,
requires expiry and issued-at claims, binds the token to the configured application, and derives
tenant, actor, and roles exclusively from verified claims. Callers cannot override identity with
headers or request fields. Operators may approve and observe outcomes; reviewers govern memory.

## Safety boundary

RecallOps does not execute infrastructure mutations in this milestone. It proposes a typed action, labels it as read-only or mutating, and persists at most one human decision per incident. Execution adapters will require allowlisted operations, least-privilege roles, timeouts, and postcondition checks.

## Validation

```bash
ruff check .
mypy
pytest --cov=recallops --cov-report=term-missing
recallops-eval
```

`recallops-eval` runs a versioned, deterministic policy regression suite against a similarity-only
baseline. These authored cases validate invariants; they are not an end-to-end provider accuracy
estimate. CI fails unless RecallOps selects the labeled safe action in every case, abstains when no
successful compatible memory exists, and produces no tenant or validity isolation violations.

## License

MIT

## AWS and CockroachDB tools

- Secure AWS Fargate deployment: [`docs/AWS_DEPLOYMENT.md`](docs/AWS_DEPLOYMENT.md)
- Failure semantics and reproducible drills: [`docs/RESILIENCE.md`](docs/RESILIENCE.md)
- AWS resources: ECS, private S3 evidence, CloudWatch, HTTPS ingress, and conditional scoped Bedrock IAM:
  `infra/aws/cloudformation.yaml`
- Official Agent Skill evidence, plus optional Managed MCP and ccloud judge workflows:
  [`docs/COCKROACH_TOOLS.md`](docs/COCKROACH_TOOLS.md)
- Live, sanitized CockroachDB Cloud evidence: `./scripts/ccloud-inspect.ps1`

## Open-source ecosystem work

RecallOps has proposed and implemented a reusable CockroachDB Agent Skill for verifying that
semantic-memory retrieval preserves trust boundaries before vector ranking. The contribution is
tracked in [cockroachdb-skills issue #19](https://github.com/cockroachlabs/cockroachdb-skills/issues/19)
and [draft PR #20](https://github.com/cockroachlabs/cockroachdb-skills/pull/20). It is not counted as
an official tool used by this submission unless CockroachDB accepts it; the pinned, already-published
transaction-design skill is the reproducible second-tool proof.
