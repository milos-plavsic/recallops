# WebMCP Challenge provenance

## Submission classification

RecallOps is an **Existing** project. Its original incident-memory, retrieval, approval,
execution-attestation, outcome, review, AWS, CockroachDB, evaluation, and judge-console functions
predate The WebMCP Challenge submission period. Only the challenge-period extension described below
is presented for WebMCP judging.

## Disclosed baseline

- Baseline commit: `cee362c5ce3cb3bb44c63a4c1ba80b558881d21c`
- Baseline commit date: `2026-08-18T18:48:20+02:00`
- Challenge start: `2026-08-25T19:00:00Z`
- Tested deployed source: recorded by the candidate's `/v1/system/status`, generated release
  identity, and immutable ECR-digest evidence rather than hand-written into this source commit.
- Generated evidence wrappers: later commits contain only derived evidence or judge documentation and
  intentionally do not self-identify by Git SHA; use the public default-branch tip for those files.

The baseline remains in public history. The final entry must link the comparison from the baseline to
the deployed release commit; generated evidence commits are kept separate to avoid a self-referential
source-SHA digest cycle.

## Challenge-period extension

- Exactly four native `document.modelContext.registerTool` tools.
- Server-authoritative Capability Sculpting with lifecycle cancellation and stale-call rejection.
- A visible Capability Inspector and Activity Rail sharing the same authoritative workflow state.
- Protected operator and reviewer transitions that are absent from WebMCP and server-denied over the
  WebMCP channel.
- An allowlisted simulator, exact action/evidence hashes, immutable observation, attributable agent
  assessment, and independently computed policy verdict.
- Review-gated positive and negative memory recurrence, revocation, expiry, and supersession.
- An append-only authority ledger, pinned-key Ed25519 receipt profile, deterministic proof bundle,
  and network-free independent verifier.
- Fair synthetic policy evaluation, generated claim/requirement traceability, 100.00% enforced Python
  statement and branch coverage, mutation testing, and browser/native WebMCP tests.

## Verified milestone ledger

| Milestone | Status | Principal evidence |
| --- | --- | --- |
| Native WebMCP vertical slice | Complete | `8998b9c`; native registration, annotations, visible capability surface |
| Authoritative workflow policy | Complete | `fa0110d`, `adbaa15`; eight states, epochs, manifests, CSRF/origin and atomic transitions |
| Sandbox action and verified observation | Complete | `d804584`; allowlisted mutation, exact bindings, fail-closed evidence path |
| Isolated judge runs and review-gated recurrence | Complete | `95bc66b` through `6a7eca3`; distinct sessions, lifecycle governance, compatible recurrence |
| Atomic authority ledger and visible control room | Complete | `1e700a4`, `2c2e796`; canonical event chain, honest timeline, accessible judge journey |
| Receipt and independent proof core | Complete locally | `61bdcb9` through `e13fd12`; strict Ed25519 profile, deterministic ZIP, 15 verifier vectors, production finalizer |
| Evaluation and complete assurance | Complete | generated dual gates, 5,392/5,392 statements and 1,206/1,206 branches, 74.06% clean mutation score |
| Hardened immutable image boundary | Complete locally | `68b2dd2`, `74d7cff`; 2.026 MB context, locked production dependencies, non-root/read-only/cap-drop smoke |
| AWS candidate and native-client proof | Complete | digest-pinned ECR/ECS, live KMS/S3 receipt, credential-free download, managed Cockroach boundaries, public browser and native Chromium 151 proof |
| Direct ChatGPT Site Tools proof | External gate open | Requires a dated invocation in the ChatGPT desktop app's built-in browser against the final frozen image |

## Exact local assurance result

- Python: 480 tests, including real CockroachDB integration and managed-database direct probes.
- Coverage: 5,392 statements and 1,206 branches; zero misses and zero partial branches.
- Mutation: 1,519/2,051 killed (74.06%); zero untested, skipped, suspicious, timeout, or interrupted mutations.
- Browser: 10/10 product tests and 2/2 first-time-judge journeys.
- Native WebMCP: 4/4 lifecycle and protected-boundary tests, including zero tools on reviewer page.
- Independent proof: 1 valid plus 14 tampered bundles produce all 15 exact expected verifier codes.
- Trace: 149/149 story, 16/16 edge, and 15/15 cross-cutting requirements represented.
- Supply chain: production and development lock audits report zero known vulnerabilities; IaC lint and
  hardened container smoke pass.

## External proof boundary

The candidate evidence binds a real ECR manifest digest, KMS Ed25519 key, versioned S3 bundle,
managed database, and public/browser clients. Assurance is complete. Live Proof remains false until
the separate direct ChatGPT Site Tools observation is captured for the same frozen release. Native
Chromium, test-only signers, screenshots, and inferred compatibility must never substitute for that
target-client observation.

Baseline comparison:
<https://github.com/milos-plavsic/recallops/compare/cee362c5ce3cb3bb44c63a4c1ba80b558881d21c...main>
