# RecallOps judge guide

Live candidate: <https://6n4hjbd6xh.execute-api.us-east-1.amazonaws.com>

RecallOps is an **Existing** project; the WebMCP-specific delta is disclosed in
[`WEBMCP_PROVENANCE.md`](WEBMCP_PROVENANCE.md). Do not evaluate an older AWS URL as the challenge
release. The final URL must report the same source/image/policy/key identity as the downloadable
release evidence.

## The 20-second thesis

RecallOps is an incident co-control room. Its visiting agent may investigate and prepare, but the
website continuously withdraws capabilities where operator or reviewer authority must begin. We call
this **Capability Sculpting**: authoritative state changes the actual WebMCP tool surface instead of
asking the agent to practice self-restraint.

The signature moment is visible: after the agent stages one exact remediation proposal,
`propose_mitigation` disappears and the authority owner becomes `HUMAN_OPERATOR`.

## Fastest complete judge path

1. Open the live URL. Select **Start judge scenario** if a run is not already open.
2. Use `checkout-latency-42` and give the agent this prompt:

   > Find a safe response and stage it. Do not authorize or execute anything. If we later observe an
   > outcome, do not let the system reuse it until an independent reviewer approves it.

3. Watch the agent call `inspect_incident`; its bounded result separates candidate similarity from
   policy eligibility and exposes explicit rejection codes.
4. Confirm the highest-similarity candidate is not treated as authority:
   `mem_47 — 0.94 — rejected: SERVICE_VERSION_MISMATCH, KNOWN_FAILED_OUTCOME`.
5. Watch the agent call `propose_mitigation`. Confirm that tool is withdrawn immediately and a stale
   callback cannot stage another proposal.
6. Use only the protected operator buttons to approve the exact action hash and attest the clearly
   labeled simulator action. There is no real-infrastructure execute button.
7. Confirm the application creates the immutable observation and only then exposes
   `record_postcheck_assessment`. The agent submits an assessment; the backend computes a separate
   policy verdict. The resulting memory is `PENDING_REVIEW` and absent from governed retrieval.
8. Open the purpose-bound reviewer handoff. Confirm the reviewer page registers zero WebMCP tools.
   Activate the memory as the distinct reviewer.
9. Confirm `recall_reviewed_memory` appears only now. Invoke it and verify that reviewed compatible
   evidence changes the `checkout-latency-43` recurrence.
10. Open the Authority Receipt. The visual chain and offline bundle bind the exact ledger prefix,
    while the adjacent limitations prevent a cryptographic-integrity claim from becoming an
    external-truth claim.

Use **Reset judge workflow** to invalidate old sessions, hashes, handoffs, and tool epochs and obtain a
fresh isolated run. A reset must never revive prior authority.

## Exactly four agent tools

| Tool | State-dependent purpose | Authority limit |
| --- | --- | --- |
| `inspect_incident` | Bounded incident/workflow and candidate-decision inspection | Read-only; similarity is separate from eligibility and external text is untrusted |
| `propose_mitigation` | Exact idempotent proposal bound to evidence and action hash | Cannot approve or execute; withdrawn while unresolved |
| `record_postcheck_assessment` | Assessment of one server-created observation | Cannot invent metrics, compute policy verdicts, or activate memory |
| `recall_reviewed_memory` | Compatible recurrence after certification | Read-only; absent before reviewed evidence is admissible |

Protected operator/reviewer transitions are absent from WebMCP and denied server-side when guessed.
The separation claim is about authenticated subjects and WebMCP authority; it does not claim to prove
two physical people or prevent arbitrary browser automation.

## What to notice without DevTools

- **Capability Inspector:** current authoritative state, authority owner, available/withdrawn tools,
  and never-exposed operations.
- **Activity Rail:** distinguishes agent calls, system registrations/withdrawals, human actions,
  denials, and committed authority events.
- **Three-layer evidence:** immutable measurement, attributable agent assessment, independent policy
  verdict. Agreement and disagreement are both preserved.
- **Recurrence proof:** the pending memory has no influence; the same reviewed memory becomes eligible
  only after certification.
- **Readiness gates:** Live proof and Assurance are independent and bound to the same release.

## Failure proof

The primary fail-closed case stops observation collection after operator approval and simulation
attestation. The workflow enters `POSTCHECK_UNAVAILABLE`; the assessment tool never appears and no
memory is created. A separate validation case supplies a stale or mismatched observation ID after the
tool exists; the call is rejected and still creates no memory.

## Reproduce local assurance

```bash
uv sync --frozen --all-extras
uv run ruff check $(git ls-files '*.py')
uv run mypy
docker compose up -d cockroach
export RECALLOPS_INTEGRATION_DATABASE_URL='postgresql://root@127.0.0.1:26257/recallops?sslmode=disable'
uv run pytest --cov=recallops --cov-branch --cov-fail-under=100
CI=1 npm run test:browser
CI=1 npm run test:judge
CI=1 npm run test:webmcp:native
uv run python scripts/verify-authority-vectors.py
uv run python scripts/generate-requirements-trace.py --check
uv run recallops-eval
```

CI additionally runs the exact appended Cockroach/CLI coverage sequence, dependency audits, IaC
lint, the 70% mutation gate, and a production image under the non-root/read-only/cap-drop profile.

## Verified local results

- 480 Python tests, including real CockroachDB integration and direct managed-database probes.
- 100.00%: 5,392/5,392 statements and 1,206/1,206 branches.
- 74.06% mutation score: 1,519/2,051 killed; zero untested mutations or timeouts.
- 10 browser, 2 first-time-judge, and 4 native WebMCP tests all passing.
- 2 public browser tests and a distinct native Chromium 151 live lifecycle proof passing.
- 15/15 exact valid/tampered independent-verifier outcomes.
- 149/149 story, 16/16 edge, and 15/15 cross-cutting requirements represented.

## Honest release boundary

The public candidate is deployed by immutable ECR digest and has live KMS/S3, credential-free bundle,
managed CockroachDB, native Chromium, and automated accessibility proof. Assurance is complete.
Release readiness remains false until direct ChatGPT desktop Site Tools acceptance exists for the
same frozen source/image. The receipt proves supplied-chain integrity and declared policy; it does
not prove external truth, physical-person separation, trusted time, or signer completeness.

**Similarity can discover experience. Only reviewed evidence earns authority.**
