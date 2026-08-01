# Judge guide

Live demo: https://c1mmwo9632.execute-api.us-east-1.amazonaws.com

Use the separately supplied operator and reviewer credentials. Sign in as the
operator for analysis and outcome capture, then select **Switch identity** and sign
in as the reviewer to activate the pending memory. The two accounts deliberately
cannot substitute for one another.

## The 30-second thesis

Most agent memory retrieves what sounds similar. RecallOps retrieves what is allowed,
compatible, independently reviewed, and proven to have worked. CockroachDB keeps the
incident, vector, outcome, approval, and governance event in one transactional causal
record. Amazon Bedrock reasons over that evidence; AWS runs and observes the secure
service.

## One-command local proof

```powershell
./scripts/judge-demo.ps1
```

The command builds the production image, starts CockroachDB and RecallOps, applies
checksum-tracked migrations, seeds deterministic governed memories, runs the safety
benchmark, waits for health, and opens <http://localhost:8080>. It does not require
AWS credentials because deterministic providers exercise the identical policy path.

In the console:

1. Inspect the live benchmark. Similarity-only RAG selects known-unsafe candidates;
   RecallOps reaches 100% safe top-1 with zero unsafe selections.
2. Analyze the prefilled incident. The compatible successful memory outranks a more
   dangerous historical action, and the proposed mutation requires approval.
3. Record the outcome. It enters `pending_review` and remains retrieval-ineligible.
4. Activate it as the independent reviewer, then analyze again. This demonstrates the
   complete incident → decision → outcome → governed memory → future recall loop.
5. Open `/docs` to inspect the typed API contract.

## Submission narrative

Operational agents fail when semantic resemblance is mistaken for evidence. The same
symptom can belong to another tenant, another version, or a remediation that previously
made the outage worse. RecallOps makes retrieval a safety decision before it becomes a
ranking problem.

Every memory is scoped by tenant and service, tied to observed outcomes, and governed
through a state machine. New observations are quarantined from retrieval until a
different operator reviews them. Positive evidence decays; known failure never becomes
safe merely because it is old. Revocation and supersession are transactional and
auditable. Mutating actions remain proposals until a human approves them.

CockroachDB is not an interchangeable storage badge: its relational constraints,
JSON incident record, vector index, unique idempotency boundary, and governance audit
form one consistent memory system. Bedrock supplies reasoning and embedding behind
bounded failure controls. ECS, ALB, WAF, Secrets Manager, S3, and CloudWatch make the
demonstration deployable with secure defaults.

The result is an agent that can learn without silently teaching itself a mistake.

## Three-minute video plan

| Time | Visual | Spoken proof |
| --- | --- | --- |
| 0:00–0:20 | Title, unsafe similarity candidate beside successful candidate | “Similarity is not operational truth. RecallOps remembers consequences.” |
| 0:20–0:45 | Architecture section | Show CockroachDB as transactional vector memory; Bedrock reasoning; AWS security and evidence path. |
| 0:45–1:15 | Live benchmark cards | Contrast 33% versus 100% safe accuracy and 67% versus 0% unsafe selection. State that CI enforces the gate. |
| 1:15–1:50 | Analyze prefilled incident | Show compatible outcome-aware retrieval, rationale, confidence, and mandatory approval. |
| 1:50–2:25 | Observe then review | Show pending memory excluded, independent reviewer activation, and provenance. |
| 2:25–2:40 | Analyze again | Close the learning loop and show the governed memory recalled. |
| 2:40–2:55 | Security/resilience badges and GitHub tests | Tenant isolation, OIDC, timeouts, conservative fallback, immutable deployment. |
| 2:55–3:00 | Closing thesis | “An agent that learns what worked—and knows who proved it.” |

Record at 1080p with browser zoom near 110%, a clean demo database, no terminal secrets,
and captions. Keep the live path rehearsed but do not replace it with mock screenshots.
