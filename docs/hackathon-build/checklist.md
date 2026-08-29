# RecallOps Build Checklist

## Build Preferences

- **Build mode:** Autonomous. This choice locks when `$build-project` begins.
- **Comprehension checks:** N/A for this experienced-builder, delegated implementation run.
- **Git:** One narrow commit after each checklist item passes its verification. Stage only files
  owned by that item; preserve all participant-owned and unrelated dirty-worktree files.
- **Verification:** Yes. Every item requires executable verification; security invariants have
  binary pass/fail acceptance and cannot be waived.
- **Check-in cadence:** Milestone-only. Pause after items 4, 6, 8, and 11 for a concise evidence
  report; otherwise continue autonomously. Stop only for a genuine external-authority blocker,
  required manual ChatGPT-client observation, or a failed invariant that cannot be corrected safely.

## Sequencing Contract

The first three WebMCP milestones already provide a verified native-tool, authoritative-workflow,
and sandbox-evidence baseline. Remaining work is ordered by dependency and failure cost:

1. freeze exact requirement/provenance accounting;
2. finish isolation and independent governance before adding more UI;
3. introduce the ledger before generating cryptographic claims from it;
4. complete the live recurrence story before receipt/evaluation sophistication;
5. finish proof, adversarial verification, deployment, and submission against one frozen build.

The signature wow moment is the proposal tool visibly disappearing while the authority owner
changes from agent to operator. The submission story remains one causal loop: unsafe similarity is
rejected, a bounded action is independently measured, review governs reuse, and a later recurrence
changes only after certification.

No item may add a fifth tool, ninth workflow state, production adapter, second scenario family,
embedded model, arbitrary action/metric input, or claim outside the frozen PRD. An item is complete
only when its product behavior and corresponding assurance evidence both pass.

## Verification Gates

- **Authority gate — after item 4:** run/session isolation, review separation, lifecycle predicates,
  and every accepted transition are transactionally enforced and ledgered.
- **Live-story gate — after item 6:** the complete two-occurrence operator/agent/reviewer journey,
  visible capability withdrawal, fail-closed observation path, refresh, and accessibility work.
- **Independent-proof gate — after item 8:** a valid pinned-key bundle verifies offline and every
  material tampered vector fails for the expected reason.
- **Frozen-release gate — after item 11:** the public image, live journey, both target clients,
  evidence, gates, and monitoring identify the same release.

## Checklist

- [x] **1. Freeze the requirement, provenance, and regression baseline**
  Spec ref: `spec.md > Normative Requirement Inventory`; `spec.md > Existing Baseline And Required Delta`
  What to build: Generate `evidence/requirements-trace.json` with stable entries for all 149
  `PRD-<story>-AC<n>` requirements, 16 `EDGE-*` requirements, and 15 cross-cutting requirements.
  Each entry must initially record its owner, enforcing boundary, planned positive/negative test,
  live-proof location, assurance path, and status without inventing pass results. Reconcile
  `docs/WEBMCP_PROVENANCE.md` to baseline `cee362c5...`, current post-start commits, and the exact
  remaining delta. Record a clean regression result for the current Milestone 3 commit before
  changing behavior.
  Acceptance: PRD 11.2 and 12.2; every requirement is represented exactly once, every proof claim
  has a release-binding destination, the project remains classified Existing, and no pre-challenge
  capability is presented as challenge-period work.
  Verify: Run a deterministic trace validator that reports `149/149`, `16/16`, and `15/15` with no
  duplicate or orphan IDs; then lint all tracked Python plus the trace generator, run `uv run mypy`,
  `uv run pytest --cov=recallops --cov-branch --cov-report=term-missing`,
  `npm run test:browser`, and `npm run test:webmcp:native`.

- [x] **2. Make judge runs and role sessions independently isolated**
  Spec ref: `spec.md > Data Model And Database Boundaries > Migration 027 — judge runs and role handoff`; `spec.md > Judge Run Isolation And Session Security`
  What to build: Add migration 027, unique run/tenant fixture allocation, run-bound operator
  sessions, purpose-bound single-use reviewer handoffs, distinct reviewer sessions, quota/TTL,
  reset-generation invalidation, and exact role-cookie selection. Implement the judge-run,
  handoff/exchange, reset, and snapshot contracts without exposing tenant, role, subject, or
  workflow authority as client input. Keep reviewer and operator controls mutually exclusive.
  Acceptance: PRD 1.1, 4.1, 6.1, 6.3, 9.1, and 12.1; `EDGE-08`, `EDGE-11`, `EDGE-14`, and
  `EDGE-15`. Concurrent visitors cannot observe or mutate one another; the same subject cannot
  review/revoke; expired or consumed links reveal no evidence; reset cannot revive stale authority.
  Verify: Run targeted session/API tests plus real CockroachDB relationship/grant probes. Exercise
  two parallel runs, mixed cookies, expired/reused handoffs, same-subject review, reset races, and
  cross-run object guesses; require one authoritative result and zero cross-run disclosures.

- [x] **3. Complete governed memory lifecycle and recurrence semantics**
  Spec ref: `spec.md > Data Model And Database Boundaries > Migration 028 — complete memory governance`; `spec.md > Sandbox, Observation, And Policy > Memory outcome semantics`
  What to build: Add certification, quarantine, rejection, revocation, expiry, and supersession
  constraints; immutable memory digests; policy-defined positive/negative/inconclusive semantics;
  reviewer reason-code enforcement; retrieval predicates before ranking; the immutable
  `checkout-latency-43` recurrence; and the read-only recurrence API. Preserve observation,
  assessment, verdict, and review as separate layers. Certification of failure creates negative
  evidence; inconclusive evidence cannot become retrievable.
  Acceptance: PRD 5.3, 6.2, 6.3, 7.1, 7.2, and 11.1; `EDGE-01`, `EDGE-07`, `EDGE-09`, and
  `EDGE-10`. Pending/quarantined/rejected/revoked/expired/superseded/incompatible/cross-tenant
  memories never influence recommendations, while a compatible certified success changes the
  later recurrence and a certified failure can only warn or penalize.
  Verify: Run the complete lifecycle retrieval matrix and property tests against in-memory and real
  CockroachDB stores. Assert immutable evidence, at-most-one pending memory, immediate revocation,
  historical inspectability, exact abstention, and identical candidate inputs for baseline and
  governed ranking.

- [ ] **4. Make the authority ledger atomic and the activity timeline honest**
  Spec ref: `spec.md > Data Model And Database Boundaries > Migration 029 — authority event ledger`; `spec.md > Authority Receipt And Proof Bundle > Finalization boundary`
  What to build: Add ledger heads, canonical authority events, supporting activity observations,
  domain-separated RFC 8785 event hashes, deterministic timeline projection, and transaction
  integration for every accepted authority transition. Domain write, workflow CAS, epoch change,
  event append, and head update must commit or roll back together. Keep read-only/browser activity
  outside the authority chain and visibly labeled; denial logging may support but never establish
  authorization correctness.
  Acceptance: PRD 2.1, 4.2, 8.2, 8.3, 9.1, and 11.2; `XSEC-02`, `XSEC-04`, `XFUNC-03`, and
  `XEVID-04`. The rail survives refresh, preserves deterministic chronology, distinguishes
  attempts from commits, and cannot fabricate or silently omit a committed transition from the
  receiptable ledger prefix.
  Verify: Fault-inject before and after every domain/workflow/event/head write; run concurrent head
  append and Cockroach serialization-retry tests; recompute every event hash independently; prove
  that activity-observation writes have no path to authority tables. Stop at the Authority gate if
  any atomicity, ordering, role, channel, or isolation assertion fails.

- [ ] **5. Complete the four-tool WebMCP and reviewer journey**
  Spec ref: `spec.md > WebMCP Tool Contracts`; `spec.md > Data Flow > Flow D — assessment and independent review`; `spec.md > Data Flow > Flow E — receipt and recurrence`
  What to build: Implement exactly the four frozen tool definitions and the server-issued manifest:
  add `recall_reviewed_memory`, correct current callback `options.signal` handling, separate
  registration controllers, stable schemas, generation-safe reconciliation, bounded activity
  observations, and state-specific withdrawal. Build the zero-WebMCP reviewer page and protected
  initial-review/revocation flows. Keep protected operations undiscoverable and server-denied over
  the WebMCP channel.
  Acceptance: PRD 2.1–3.2, 5.3, 6.1–7.2, 8.1, 9.1, 9.3, and 10.2; `EDGE-02`, `EDGE-03`,
  `EDGE-06`, `EDGE-11`, and `EDGE-12`. Tool names, schemas, annotations, output budgets, state
  availability, cancellation reconciliation, and recurrence results match in native Chrome and the
  supported ChatGPT site-tool path; no fake fallback exists.
  Verify: Run API contract tests and native WebMCP discovery/invocation/withdrawal/cancellation
  tests for every state. Capture a stale callback after withdrawal, rapid manifest changes,
  invocation cancellation after possible server receipt, unsupported-client behavior, and reviewer
  page discovery showing zero tools.

- [ ] **6. Finish the judge-visible control room and accessible causal proof**
  Spec ref: `spec.md > Browser Application Architecture`; `spec.md > Demo And Submission Flow > Frozen demo sequence`
  What to build: Complete the first-viewport incident proof, rejected 0.94 candidate, exact prompt,
  Capability Inspector, role-exclusive Protected Action panel, persisted Activity Rail, three-layer
  evidence view, recurrence comparison, progressive Verify Evidence drawers, Authority Chain shell,
  readiness badges, read-only degraded state, and honest unsupported-client state. Implement the
  specified semantic HTML, focus, live-region, keyboard, reduced-motion, narrow-layout, timestamp,
  safe-rendering, and security-header contracts.
  Acceptance: PRD 1.1–1.2, 2.2–2.3, 3.2, 4.1–5.3, 6.1–8.3, 9.1–10.2, and 11.3;
  `EDGE-01` through `EDGE-16` for their visible responses. A first-time judge can complete the
  successful two-occurrence story without documentation, see capability withdrawal as the wow
  moment, recover safely, and understand proof meaning without relying on color or DevTools.
  Verify: Run Playwright desktop/narrow/refresh/duplicate-tab/failure journeys and axe with zero
  serious/critical findings. Complete keyboard and screen-reader protocols, verify no material
  horizontal scroll, inspect CSP/Permissions-Policy/OAC headers, scan for unsafe dynamic HTML, and
  manually approve the Live-story gate in both wide and constrained layouts.

- [ ] **7. Build the pinned-key receipt cryptographic core**
  Spec ref: `spec.md > Authority Receipt And Proof Bundle > Compact manifest schema`; `spec.md > Authority Receipt And Proof Bundle > JWS/KMS profile`
  What to build: Add migration 030 receipt/release records, strict I-JSON/RFC 8785 canonicalization,
  event-prefix verification, compact manifest construction, fully specified RFC 9864 `Ed25519` JWS,
  KMS `ECC_NIST_EDWARDS25519`/`ED25519_SHA_512`/RAW adapter, local returned-signature verification,
  RFC 7638 thumbprints, repository-pinned trusted-key registry, explicit key transitions, and a
  no-fallback deployment preflight. Keep KMS outside serializable transactions.
  Acceptance: PRD 8.3, 9.2, 11.2, and 11.3; `XEVID-03` and `XEVID-04`. The manifest remains within
  KMS's message limit, binds the exact ledger prefix and release identity, rejects deprecated
  `EdDSA`/unknown headers/unpinned keys, and states that cryptographic integrity is not external
  truth, physical-person proof, trusted time, or signer completeness.
  Verify: Run canonicalization and digest fixed vectors, duplicate-key/unsafe-number/Unicode tests,
  KMS contract and live preflight tests, wrong-algorithm/key/build vectors, returned-signature
  verification, transaction/outbox fault tests, and exact manifest-size assertions.

- [ ] **8. Export and independently verify the complete authority bundle**
  Spec ref: `spec.md > Authority Receipt And Proof Bundle > Bundle layout`; `spec.md > Authority Receipt And Proof Bundle > Offline verifier`
  What to build: Implement idempotent outbox finalization, acyclic evidence-index/checksum/bundle
  digests, private versioned S3 persistence, credential-free finalized synthetic download, human-
  readable authority-chain projection, the network-free Node verifier, and fixed valid/tampered
  bundles. Include policies, ordered events, claims, evaluation case/result, frozen release identity,
  pinned public key, checksums, limitations, and exact reproduction instructions.
  Acceptance: PRD 8.3, 9.2, 11.2–11.3, and 12.2; `EDGE-10`, `EDGE-13`, and `EDGE-16`. KMS/S3
  failure never changes domain outcome or turns Assurance green; valid bundles verify offline;
  replacement, deletion, duplication, reordering, key substitution, policy/tool/role/binding/build/
  disposition changes all fail with stable expected codes.
  Verify: Generate the valid bundle and every material tampered vector, disable network access, run
  `node tools/verify-authority-bundle.mjs <bundle>`, require the valid vector to pass and all tampered
  vectors to fail for their declared reasons, test digest-graph acyclicity and retry idempotency,
  and verify the public download from a credential-free browser. Stop at the Independent-proof gate
  on any false accept, false reject, unsigned fallback, or circular binding.

- [ ] **9. Generate fair impact evidence, claims, and dual gates**
  Spec ref: `spec.md > Evaluation And Verification > Fair impact benchmark`; `spec.md > Evaluation And Verification > Claim registry and dual-gate derivation`
  What to build: Publish immutable WebMCP cases and the governed benchmark; run similarity-only and
  RecallOps over identical inputs/tie-breaking; generate exact counts/denominators; complete the
  claim registry and every field of `evidence/requirements-trace.json`; derive Live proof and
  Assurance independently from build-bound artifacts; and generate the external KMS-signed release
  statement without a digest cycle. Never hand-edit measured results or green statuses.
  Acceptance: PRD 2.2–2.3, 7.1–7.2, 10.2, 11.1–11.3, and 12.2; all `XEVID-*`. The headline
  baseline chooses the incompatible known failure, governed retrieval rejects it before ranking,
  pending leakage and accepted security violations are zero, all failures are published, results
  are labeled synthetic, and both gates become complete only for the identical source/image.
  Verify: Regenerate all cases/results twice and require byte-identical output; validate every claim
  and all 180 requirement IDs have live/raw/reproduce links; run stale-SHA/image/policy/key/failing-
  test negative cases; compare displayed counts to raw cases; and require both gates false when any
  mandatory artifact is absent, failed, mismatched, or stale.

- [ ] **10. Pass the complete adversarial and cross-client assurance matrix**
  Spec ref: `spec.md > Evaluation And Verification > Deterministic test layers`; `spec.md > Risks And Verification`
  What to build: Close every remaining test/evidence gap across strict schemas, prompt-like content,
  role/channel confusion, stale and guessed calls, exact digest binding, replay/idempotency,
  cancellation ambiguity, concurrent tabs/runs, dependency faults, immutable evidence, retrieval
  lifecycle, ledger atomicity, receipt tampering, refresh/reset/expiry, accessibility, and both
  target clients. Update the trace record from actual generated artifacts only.
  Acceptance: All 149 story criteria, 16 edge cases, 15 cross-cutting standards, and every risk-table
  row have explicit passing assertions and evidence. Security invariants have zero accepted
  violations; probabilistic agent results publish all failures and denominators; branch-aware
  tracked application coverage remains 100%; no unknown/waived/stale requirement remains.
  Verify: Run the complete Ruff/mypy/coverage suite, all real CockroachDB integration and direct
  grant/binding probes, Playwright, native WebMCP, accessibility/manual protocols, agent evaluations,
  verifier vectors, dependency/container/IaC/SBOM scans, and a trace-completeness validator. Preserve
  raw environment/client/version/date/source results and fail the item on any red gate.

- [ ] **11. Freeze, deploy, and continuously prove one release candidate**
  Spec ref: `spec.md > External APIs And Dependencies > AWS deployment`; `spec.md > Demo And Submission Flow > Release freeze`
  What to build: Produce a clean immutable image, deploy judge auth through the private-task AWS
  boundary, provision the exact KMS key/private S3 policies, run migrations/grant verification,
  expose the stable no-signup URL, and bind runtime SHA/image/policy/evaluation/key identity. Exercise
  the full journey, reset, public bundle, and both gates on the live image; complete native Chrome
  and manual ChatGPT site-tool acceptance; configure six-hour external smoke/alerting without any
  ability to force gates green.
  Acceptance: PRD 1.1, 9.2–9.3, 10.2, 11.2–11.3, and 12.1–12.2; `XFUNC-01..04`. The deployment
  supports concurrent isolated runs, has no Cognito/signup friction or production target, survives
  refresh/reset/retry, presents honest degraded states, and every live/artifact surface identifies
  the same frozen release. Any post-freeze change reopens both gates.
  Verify: Deploy by image digest, run database verifier and live smoke, complete both-client evidence
  protocols, download and verify a live credential-free bundle, run concurrent public journeys,
  inspect response/security headers and sanitized logs, exercise KMS/S3/observer failure states,
  and require `LIVE_PROOF_COMPLETE=true` plus `ASSURANCE_COMPLETE=true` for the same release before
  passing the Frozen-release gate.

- [ ] **12. Prepare the Devpost handoff from the frozen release**
  Spec ref: `spec.md > Demo And Submission Flow`; `prd.md > Submission Proof Points`; `prd.md > Demo Acceptance`
  What to build: Update the Existing-project provenance and baseline-to-final comparison; write the
  one-page judge guide, evidence index, exact tested-client disclosure, simulation/threat boundary,
  public repo/live URL instructions, reviewer handoff/recovery, and submission narrative. Capture
  screenshots that show the rejected unsafe shortcut, current capability/authority, verified
  evidence/review, and recurrence. Record a 2:40–2:50 product-only video against the frozen image,
  with the working product in the first 10–15 seconds and the approved closing line. Gather all
  materials needed by `$prepare-submission`; do not submit in this item.
  Acceptance: PRD 11.2, 12.2, all Submission Proof Points, and all Demo Acceptance criteria. The
  repo, live app, video, proof bundle, benchmark, public key, judge guide, screenshots, and Devpost
  draft identify one release; every scored statement has a live and reproducible proof path; the
  video remains under three minutes and does not substitute for the accessible live product.
  Verify: Perform an incognito public-access check, replay the exact judge path from the guide,
  verify video runtime/audio/first-15-second proof and release identity, run the repository's
  submission audit against the final URLs, check every evidence link/digest, and confirm the next
  command is `$prepare-submission`.
