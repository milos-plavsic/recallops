# RecallOps judge guide

Live release: `[REPLACE_WITH_FROZEN_RELEASE_URL]`

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
`stage_remediation` disappears and the authority owner becomes `HUMAN_OPERATOR`.

## Fastest complete judge path

1. Open the live URL. Select **Start judge scenario** if a run is not already open.
2. Use `checkout-latency-42` and give the agent this prompt:

   > Find a safe response and stage it. Do not authorize or execute anything. If we later observe an
   > outcome, do not let the system reuse it until an independent reviewer approves it.

3. Watch the agent call `inspect_incident` and `compare_memory_candidates`.
4. Confirm the highest-similarity candidate is not treated as authority:
   `mem_47 — 0.94 — rejected: SERVICE_VERSION_MISMATCH, KNOWN_FAILED_OUTCOME`.
5. Watch the agent call `stage_remediation`. Confirm that tool is withdrawn immediately and a stale
   callback cannot stage another proposal.
6. Use only the protected operator buttons to approve the exact action hash and attest the clearly
   labeled simulator action. There is no real-infrastructure execute button.
7. Confirm the application creates the immutable observation and only then exposes
   `record_verified_postcheck`. The agent submits an assessment; the backend computes a separate
   policy verdict. The resulting memory is `PENDING_REVIEW` and absent from governed retrieval.
8. Open the purpose-bound reviewer handoff. Confirm the reviewer page registers zero WebMCP tools.
   Activate the memory as the distinct reviewer.
9. Open `checkout-latency-43`. Confirm the reviewed compatible memory now changes the recommendation.
10. Open the Authority Receipt. The visual chain and offline bundle bind the exact ledger prefix,
    while the adjacent limitations prevent a cryptographic-integrity claim from becoming an
    external-truth claim.

Use **Reset judge scenario** to invalidate old sessions, hashes, handoffs, and tool epochs and obtain a
fresh isolated run. A reset must never revive prior authority.

## Exactly four agent tools

| Tool | State-dependent purpose | Authority limit |
| --- | --- | --- |
| `inspect_incident` | Bounded incident/workflow inspection | Read-only; external text is untrusted |
| `compare_memory_candidates` | At most three candidates with similarity, eligibility, and rejection codes | Ineligible memory is never recommended |
| `stage_remediation` | Exact idempotent proposal bound to evidence and action hash | Cannot approve or execute; withdrawn while unresolved |
| `record_verified_postcheck` | Assessment of one server-created observation | Cannot invent metrics or activate memory |

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

- 415 unit/API tests and 28 real CockroachDB integration tests.
- 100.00%: 5,288/5,288 statements and 1,172/1,172 branches.
- 73.95% mutation score: 1,493/2,019 killed; zero untested mutations.
- 10 browser, 2 first-time-judge, and 4 native WebMCP tests all passing.
- 15/15 exact valid/tampered independent-verifier outcomes.
- 149/149 story, 16/16 edge, and 15/15 cross-cutting requirements represented.

## Honest release boundary

The local core is complete. Until the final deployment work is recorded, the repository intentionally
keeps both release gates red and uses placeholder image/key values. Do not treat the local image ID,
test signer, old public deployment, or automated Chromium tests as substitutes for the final ECR
digest, live KMS/S3 proof, direct ChatGPT site-tool observation, or dated manual accessibility result.

**Similarity can discover experience. Only reviewed evidence earns authority.**
