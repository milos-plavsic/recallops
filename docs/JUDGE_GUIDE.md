# Judge guide

Live demo: https://ltfrottcxj.execute-api.us-east-1.amazonaws.com

Use the separately supplied operator and reviewer credentials. Sign in as the
operator for analysis and outcome capture, then select **Switch identity** and sign
in as the reviewer to activate the pending memory. The two accounts deliberately
cannot substitute for one another.

## The 30-second thesis

Most agent memory retrieves what sounds similar. RecallOps retrieves what is allowed,
compatible, independently reviewed, and backed by an observed outcome. CockroachDB keeps the
incident, vector, outcome, approval, and governance event in one transactional causal
record. A deterministic, evidence-bounded provider keeps the judge flow reliable; ECS runs the
agent, S3 archives evidence, and CloudWatch observes it. Bedrock is an optional provider, not a
demo dependency.

Open **Replayable agent trace** after analysis to inspect the ordered tools, their actual
risk classification, retry and timeout bounds, degradation state, and evidence
references used by the agent. The candidate evidence drawer shows why each returned
memory was selected or ranked below the winner.

## One-command local proof

```powershell
./scripts/judge-demo.ps1
```

The command builds the production image, starts CockroachDB and RecallOps, applies
checksum-tracked migrations, seeds deterministic governed memories, runs the safety
benchmark, waits for health, and opens <http://localhost:8080>. It does not require
AWS credentials because deterministic providers exercise the identical policy path.

In the console:

1. Inspect the live policy regression suite. It is a small, synthetic, deterministic
   set of authored cases; it is not an end-to-end Titan/CockroachDB retrieval benchmark.
   Similarity-only RAG selects known-unsafe candidates while the policy path is expected
   to pass its safety invariants.
2. Analyze the prefilled incident. The compatible successful memory outranks a more
   dangerous historical action, and the proposed mutation requires approval.
3. Record the outcome. It enters `pending_review` and remains retrieval-ineligible.
4. Activate it as the independent reviewer, then analyze again. This demonstrates the
   complete incident → decision → outcome → governed memory → future recall loop.
5. Open `/docs` to inspect the typed API contract.

## Browser-level judge-flow checks

The repository also includes a deterministic Chromium smoke suite for the surface a
judge sees. It intercepts the API at the browser boundary, so it is fast, does not
need AWS or CockroachDB credentials, and cannot turn a provider outage into a passing
backend test. The fixtures cover the truthful synthetic-benchmark label, initial API
readiness, successful analysis with the rendered trace risk, safe abstention with
candidate rejection reasons, keyboard focus, and serious/critical axe accessibility
violations. Browser console errors fail the initial-render check.

```bash
npm ci
npx playwright install chromium
npm run test:browser
```

The suite starts an isolated in-memory API automatically. In CI, the browser job uses
Python 3.12, installs the project, installs only Chromium, and uploads the Playwright
HTML report and failure artifacts. The browser fixtures are not product benchmark
data; the live CockroachDB and end-to-end evaluation gates remain authoritative for
retrieval behavior.

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
form one consistent memory system. The public deployment uses deterministic reasoning and
embedding so model-account authorization cannot break judging. ECS, API Gateway, Cognito,
Secrets Manager, S3, and CloudWatch provide meaningful AWS execution, identity, evidence, and
observability. Bedrock remains an optional provider behind bounded failure controls.

The result is an agent that can learn without silently teaching itself a mistake.

## Three-minute video plan

The production-ready action-first script, exact clicks, database proof query, and
recording checklist are in [`VIDEO_PRODUCTION.md`](VIDEO_PRODUCTION.md). The live
application must act within the first 10 seconds; architecture and regression evidence
belong after the complete memory loop.

| Time | Visual | Spoken proof |
| --- | --- | --- |
| 0:00–0:10 | Live incident console and one-sentence problem | “Similarity is not operational truth. RecallOps remembers consequences.” |
| 0:10–0:49 | Analyze and open candidate evidence | Show outcome-aware retrieval, the rejected dangerous candidate, and mandatory approval. |
| 0:49–1:02 | Replayable agent trace | Show ordered tools, bounded risk, status, and evidence references. |
| 1:02–1:51 | Approve, attest, observe, then switch identity and review | Show `pending_review` exclusion and independent reviewer activation. Cut all credential entry. |
| 1:51–2:10 | Analyze again and open candidate evidence | Prove that the newly governed memory participates in the next decision. |
| 2:10–2:28 | Live read-only CockroachDB query | Show the stored outcome, active state, observer/reviewer presence, governance event, and DVI index. |
| 2:28–2:43 | Architecture section | Name CockroachDB DVI and AWS ECS, API Gateway, Cognito, S3, and CloudWatch on screen. Label Bedrock optional. |
| 2:43–2:54 | Regression and test evidence | Label policy cases as synthetic regression evidence, not production accuracy. |
| 2:54–3:00 | Closing thesis | “An agent that learns what worked—and knows who proved it.” |

Record at 1080p with browser zoom near 110%, a clean demo database, no terminal secrets,
and captions. Keep the live path rehearsed but do not replace it with mock screenshots.
