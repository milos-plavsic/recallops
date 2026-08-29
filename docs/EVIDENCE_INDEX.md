# RecallOps judge evidence index

This index separates product proof, reproducible local assurance, and external release evidence.
Evidence is valid for a submitted release only when source SHA, deployed ECR digest, capability and
receipt policies, evaluation version, and pinned key thumbprint agree.

| Scored claim | Fast product proof | Reproducible proof | Honest boundary |
| --- | --- | --- | --- |
| Capability Sculpting is real WebMCP behavior | Watch `stage_remediation` disappear and authority move to operator | `tests/webmcp-native/native.spec.ts`, `tests/browser/recallops.spec.ts`, `src/recallops/static/webmcp.js` | UI labels are explanatory; server epochs and tool registration/withdrawal are authoritative |
| Exactly four tools, no protected transition | Inspect the Capability Inspector and reviewer page | `src/recallops/webmcp_contracts.py`, API contract tests, native reviewer-zero-tools test | Nondiscovery is paired with server denial; obscurity alone is not claimed |
| Stale/cancelled tools retain no authority | Run stale callback and cancellation cases | native/browser lifecycle tests and WebMCP idempotency boundary tests | Client cancellation cannot prove non-receipt, so server state reconciles the result |
| Similarity does not grant authority | Compare rejected `mem_47` at 0.94 with eligible `mem_12` at 0.81 | `evaluation/governed_benchmark.json`, `tests/test_retrieval.py`, `tests/test_memory_lifecycle.py` | Synthetic deterministic policy regression, not a production incident-rate estimate |
| Missing evidence fails closed | Show `POSTCHECK_UNAVAILABLE`: no assessment tool and no memory | `tests/test_sandbox.py`, `tests/test_resilience.py`, API boundary tests | The demo mutates only an isolated allowlisted simulator |
| Agent cannot invent measurements | Show the server-created observation and small assessment input | sandbox/service tests and exact observation/action/proposal digest checks | Operator attests the simulation; RecallOps does not claim real infrastructure execution |
| Review gates future reuse | Show pending memory excluded, reviewer page with zero tools, then compatible recurrence | lifecycle, reviewer, judge-browser, and native WebMCP tests | Distinct authenticated subjects are proven; distinct physical people are not |
| Authority events are atomic and complete | Refresh the Activity Rail and final visual chain | `tests/test_ledger.py`, real Cockroach fault/concurrency tests, migration 029 | Supporting observations do not establish authority |
| Receipt verifies supplied authority policy | Download bundle and run network-free Node verifier | `artifacts/authority-vectors/`, `tools/verify-authority-bundle.mjs`, 15 exact vectors | Signature proves integrity/policy of supplied chain, not external truth, trusted time, or signer completeness |
| Evidence and release readiness cannot be hand-waved green | Inspect separate Live proof and Assurance badges | release-status/evidence tests and generated `artifacts/release/` | Current committed placeholders intentionally keep both gates false |
| Product experience is coherent and accessible | Complete the no-documentation judge path in wide and 390px layouts | 10 browser tests, 2 judge journeys, axe, keyboard/focus assertions | Direct screen-reader and ChatGPT site-tool observations remain manual release gates |
| Security/functionality tests are complete locally | Open the assurance summary | exact CI sequence: 100.00% coverage, 73.95% mutation, dependency/IaC/container gates | Structural coverage is not called mutation coverage or formal verification |

## Independent verifier vectors

`uv run python scripts/verify-authority-vectors.py` requires one valid vector to return `VERIFIED`
and 14 materially tampered vectors to fail with their declared stable code. Covered attacks include
content replacement, deletion, duplication, reordering, duplicate JSON keys, key substitution,
signature corruption, actor/capability/disposition/policy changes, causal binding changes, and build
identity changes.

## Requirement and claim trace

- `evidence/requirements-trace.json`: all 149 story acceptance criteria, 16 edge cases, and 15
  cross-cutting requirements with owner, boundary, test, live, assurance, claim, and reproduction
  destinations.
- `evidence/claims.json`: 12 rubric-facing claims with live route, workflow event, tests, raw data,
  receipt fields, and deterministic reproduction command.
- `artifacts/release/gates.jcs.json`: independently derived Live proof and Assurance results.
- `evaluation/governed_benchmark.json`: identical candidate inputs and complete synthetic outcomes.

## Release consistency gate

Before recording or submitting, require all of the following for one immutable release:

1. Public default branch contains the source and generated evidence commits.
2. ECR scan completes for the exact deployed manifest digest.
3. Runtime status reports the bound source/image/policy/evaluation/key identity.
4. KMS signs the release statement and receipt with the repository-pinned Ed25519 key.
5. The public, credential-free bundle download verifies offline at the recorded S3 version.
6. Native Chrome and direct ChatGPT site-tool journeys both pass against that digest.
7. Manual accessibility protocol and six-hour smoke identify the same release.
8. The video, Devpost copy, and provenance comparison contain no stale URL, SHA, digest, or claim.

Older evidence remains useful history but must not be presented as proof of a newer deployment.
