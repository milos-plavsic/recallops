# RecallOps — The Incident Co-Control Room

> **RecallOps demonstrates Capability Sculpting:** a WebMCP website changes the tools available to
> its visiting agent as authority moves between agent, operator, application, and reviewer.

[![CI](https://github.com/milos-plavsic/recallops/actions/workflows/ci.yml/badge.svg)](https://github.com/milos-plavsic/recallops/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-c8ff4d.svg)](LICENSE)

**Challenge release status:** the public AWS candidate is live at
<https://6n4hjbd6xh.execute-api.us-east-1.amazonaws.com>. Its independently derived Assurance gate
passes. Final release readiness remains deliberately false until the same frozen image receives a
direct ChatGPT desktop Site Tools observation; native Chromium proof is not substituted for that
separate client gate.

## Why this exists

Operational agents often mistake semantic similarity for permission. The closest historical fix may
target the wrong version, contain a known failed outcome, belong to another tenant, or still be
awaiting review. Asking an agent to “be careful” does not create an authority boundary.

RecallOps makes the website enforce that boundary. The agent can investigate and prepare, but it can
never approve its proposal, attest execution, activate memory, switch role, or override policy. Those
protected transitions remain server-enforced human actions.

**Similarity can discover experience. Only reviewed evidence earns authority.**

## The four WebMCP tools

| Tool | Purpose | Boundary |
| --- | --- | --- |
| `inspect_incident` | Return bounded incident, workflow state, and at most three candidate decisions | Read-only; similarity is separate from eligibility and external content is untrusted |
| `propose_mitigation` | Create one idempotent, digest-bound proposal | Cannot approve or execute; withdrawn while unresolved |
| `record_postcheck_assessment` | Record the agent's assessment of a server-created observation | Cannot invent metrics, compute the policy verdict, or activate memory |
| `recall_reviewed_memory` | Read one compatible recurrence after certification | Read-only; absent until reviewed evidence is admissible |

The registry is derived from server-authoritative workflow state. Separate lifecycle-bound
`AbortController`s withdraw registrations on state changes, while server epochs, hashes, roles, and
idempotency protect against stale callbacks, cancellation ambiguity, and replay.

## The deterministic judge story

1. `checkout-latency-42` starts in `INVESTIGATING`.
2. The agent inspects the incident and compares memory candidates.
3. `mem_47` has similarity `0.94` but is rejected before ranking for
   `SERVICE_VERSION_MISMATCH` and `KNOWN_FAILED_OUTCOME`; reviewed compatible `mem_12` at `0.81`
   remains eligible.
4. The agent stages an exact proposal. `propose_mitigation` disappears and authority moves to the
   operator.
5. The operator approves the exact hash and attests one allowlisted simulator action. RecallOps does
   not execute production infrastructure.
6. The application creates immutable measurements. Only then does `record_postcheck_assessment`
   appear; the agent submits an attributable assessment and backend policy computes an independent
   verdict.
7. The new memory remains `PENDING_REVIEW` and retrieval-ineligible.
8. A distinct reviewer opens a purpose-bound page that exposes zero WebMCP tools and decides the
   memory's disposition.
9. Only after certification does `recall_reviewed_memory` appear and prove the compatible
   `checkout-latency-43` recurrence can reuse the memory.
10. A pinned-key Authority Receipt binds the supplied ledger prefix and can be verified offline.

The Capability Inspector and Activity Rail show available, withdrawn, and never-exposed capabilities,
the current authority owner, agent calls, human actions, denials, and committed authority events.

## Architecture

- **Browser:** semantic control room, native `document.modelContext.registerTool`, capability
  reconciliation, protected operator/reviewer controls, and accessible evidence views.
- **API:** FastAPI with strict schemas, origin/CSRF/session enforcement, run isolation, bounded outputs,
  and state-derived capability manifests.
- **Persistence:** CockroachDB transactionally couples domain writes, workflow CAS, authority-event
  append, ledger-head update, memory lifecycle, reviewer separation, and receipt outbox.
- **Evidence:** immutable simulator observation, attributable agent assessment, deterministic policy
  verdict, review disposition, canonical hash bindings, and deterministic evaluation artifacts.
- **Proof:** RFC 8785/I-JSON material, RFC 9864 `Ed25519` JWS profile, repository-pinned keys,
  deterministic ZIP, versioned private S3 persistence, and a network-free Node verifier.
- **Deployment:** digest-pinned, non-root distroless image behind the existing private-task AWS
  boundary; production signing has no local-key fallback.

See [the architecture and frozen specification](docs/hackathon-build/spec.md),
[the threat model](docs/THREAT_MODEL.md), and [the evidence index](docs/EVIDENCE_INDEX.md).

## Run locally

Prerequisites: Docker, Python 3.12, `uv`, Node 22, and Chromium for the browser suites.

```bash
docker compose up --build
```

Open <http://localhost:8080>. The local environment uses the isolated deterministic simulator and
does not require AWS credentials. It must not be presented as live AWS/KMS/S3 proof.

For development:

```bash
uv sync --frozen --all-extras
npm ci
uv run pytest
```

## Assurance

The exact CI sequence currently proves:

- 480 Python tests, including real CockroachDB integration and direct managed-database probes;
- 100.00% Python statement and branch coverage: 5,392/5,392 statements and 1,206/1,206
  branches, with zero partial branches;
- 74.06% safety-critical mutation score: 1,519/2,051 killed and zero untested mutations or timeouts;
- 10/10 product browser tests, 2/2 first-time-judge journeys, and 4/4 native WebMCP tests;
- 2/2 public browser journeys and a separate native Chromium 151 live lifecycle proof;
- one valid and 14 materially tampered authority bundles producing all 15 exact expected codes;
- all 149 story, 16 edge, and 15 cross-cutting requirements represented;
- zero known vulnerabilities in current production and development lock audits;
- IaC lint, Docker Compose validation, and a hardened production-image startup test.

```bash
uv run ruff check $(git ls-files '*.py')
uv run mypy
uv run pytest --cov=recallops --cov-branch --cov-fail-under=100
CI=1 npm run test:browser
CI=1 npm run test:judge
CI=1 npm run test:webmcp:native
uv run python scripts/verify-authority-vectors.py
uv run python scripts/generate-requirements-trace.py --check
uv run recallops-eval
```

Coverage and mutation resistance are separate claims. The project does not call 74.06% mutation
coverage “100% testing,” nor does it claim formal verification.

## Impact benchmark

The committed 12-case synthetic benchmark gives similarity-only and governed retrieval the identical
candidate inputs and tie-breaking. Similarity-only makes 11 unsafe selections and leaks two pending
memories; RecallOps makes zero unsafe selections, leaks zero pending memories, and produces all three
expected abstentions. These are deterministic policy-regression results, not production incident-rate
or universal-safety claims.

## Receipt limitations

The Authority Receipt proves integrity and policy consistency of the supplied chain under the pinned
key. It does not prove external truth, physical-person independence, trusted time, or completeness
against a compromised signer. Supporting observations never establish authority by themselves.

## Existing-project provenance

RecallOps is submitted as an **Existing** project. Baseline
`cee362c5ce3cb3bb44c63a4c1ba80b558881d21c` predates the challenge; the complete WebMCP delta and
dated milestone ledger are in [WEBMCP_PROVENANCE.md](docs/WEBMCP_PROVENANCE.md).

## Release checklist

The current candidate has an exact ECR digest and zero-finding registry scan, live KMS/S3 receipt,
credential-free bundle download, managed-database boundary proof, native Chromium lifecycle proof,
and automated accessibility smoke. Direct ChatGPT desktop Site Tools acceptance, the scheduled
availability observation, and the public sub-three-minute video remain explicit external gates.

See [SUBMISSION_CHECKLIST.md](docs/SUBMISSION_CHECKLIST.md),
[JUDGE_GUIDE.md](docs/JUDGE_GUIDE.md), and
[VIDEO_RECORDING_RUNBOOK.md](docs/VIDEO_RECORDING_RUNBOOK.md).

## License

[MIT](LICENSE)
