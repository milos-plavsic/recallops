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
- Tested local release source: `74d7cff203cfc69ecd3e956f792eefaf6e686b19`
- Generated evidence wrapper: `325e66908dd89ad6fefe7287f106cd83e518a625`

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
| Evaluation and complete local assurance | Complete locally | `dbebd30` through `3a551ed`; generated dual gates, 5,288/5,288 statements and 1,172/1,172 branches, 73.95% mutation score |
| Hardened immutable image boundary | Complete locally | `68b2dd2`, `74d7cff`; 2.026 MB context, locked production dependencies, non-root/read-only/cap-drop smoke |
| AWS release and cross-client proof | External gate open | Requires renewed AWS identity, immutable ECR digest, live KMS/S3/ECS proof, public URL, and direct ChatGPT site-tool observation |

## Exact local assurance result

- Python: 415 unit/API tests plus 28 real CockroachDB integration tests.
- Coverage: 5,288 statements and 1,172 branches; zero misses and zero partial branches.
- Mutation: 1,493/2,019 killed (73.95%); zero untested, skipped, suspicious, timeout, or interrupted mutations.
- Browser: 10/10 product tests and 2/2 first-time-judge journeys.
- Native WebMCP: 4/4 lifecycle and protected-boundary tests, including zero tools on reviewer page.
- Independent proof: 1 valid plus 14 tampered bundles produce all 15 exact expected verifier codes.
- Trace: 149/149 story, 16/16 edge, and 15/15 cross-cutting requirements represented.
- Supply chain: production and development lock audits report zero known vulnerabilities; IaC lint and
  hardened container smoke pass.

## External proof boundary

The committed release identity intentionally contains an all-zero image digest and an unpinned
placeholder receipt-key thumbprint. Both Live proof and Assurance remain false. Local image IDs,
test-only signing keys, screenshots, and manual attestations must never be substituted for the
required ECR manifest digest, AWS KMS key, versioned S3 object, deployed release statement, or direct
target-client observation.

Baseline comparison:
<https://github.com/milos-plavsic/recallops/compare/cee362c5ce3cb3bb44c63a4c1ba80b558881d21c...74d7cff203cfc69ecd3e956f792eefaf6e686b19>
