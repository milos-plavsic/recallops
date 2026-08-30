# Guided Build Notes

## 2026-08-29 — Checklist item 5: frozen four-tool WebMCP and independent review

- Replaced the provisional browser surface with exactly four frozen tools and a server-issued
  manifest bound to run generation, workflow epoch, memory governance version, capability policy,
  and build SHA. Protected operator/reviewer operations remain disjoint and undiscoverable.
- Added exact judge routes for bounded incident inspection, idempotent proposal staging, immutable
  postcheck assessment, reviewed recurrence, and bounded supporting activity. Proposal and assessment
  idempotency records commit atomically with domain state, workflow CAS, authority event, and ledger
  head in CockroachDB.
- Derived WebMCP agent attribution server-side so visiting-agent events never inherit the operator's
  authenticated subject merely because browser requests carry the operator session cookie.
- Implemented separate registration controllers, current callback `options.signal`, manifest
  generation guards, late-registration discard, conditional visible-page polling, stale callback
  rejection, and post-cancellation reconciliation to server authority. No fallback tool registry is
  installed when native WebMCP is unavailable.
- Added a dedicated reviewer document that loads no WebMCP registration script. It consumes the
  single-use fragment handoff before network use, renders immutable measurement, attributable agent
  assessment, and independent policy verdict safely, and permits only purpose-bound reviewer actions.
- Preserved agent/policy disagreement rather than collapsing it, kept all resulting memory pending
  until independent disposition, and withdrew recall immediately after revocation, expiry, or other
  admissibility loss.
- Corrected in-memory assessment indexing to match the database's one-assessment-per-incident key;
  this was found by the full disagreement/reviewer journey test.
- Verified 251 Python tests against a fresh CockroachDB schema, including exact 48 runtime grants,
  16 cross-tenant constraints, 25 runtime denials, proposal idempotency replay, and fault-injected
  rollback after authority-event insertion. The focused browser suite passes 10/10 and native
  Chromium WebMCP passes 4/4, including reviewer discovery of zero tools.
- The repository-wide 100% coverage release gate remains intentionally open for the later evidence
  milestone: the combined suite currently reports 97.84% while all functional tests pass. No green
  assurance claim was made from that incomplete gate.

## 2026-08-29 — Checklist item 2: isolated judge authority

- Added migration 027 with run/tenant/source-incident composite integrity, run-bound role sessions,
  purpose-bound single-use reviewer handoffs, least-privilege grants, and explicit invalidation of
  every legacy unbound session during migration.
- Removed reusable operator/reviewer bootstrap exchange from the public design. Operator authority
  now originates only from an isolated anonymous judge-run allocation; reviewer authority originates
  only from a 256-bit, fragment-delivered, short-lived, single-consumption handoff.
- Bound operator and reviewer cookies to different `__Host-` names and exact run generation. Only
  hashes persist; exact Origin and distinct per-session CSRF remain mandatory. When both cookies
  coexist, the server route selects exactly one role cookie; cookie order and client role hints
  cannot choose authority.
- Reset closes the old run, revokes its sessions and outstanding handoffs, and allocates a new run,
  tenant, incident, operator subject, generation, CSRF secret, and cookie. Old credentials remain
  invalid even when replayed after the new run exists.
- Added a reviewer-session-to-handoff foreign-key binding so purpose and object scope remain
  independently recoverable for later governance authorization; operator sessions cannot carry a
  reviewer grant.
- Verified two-run isolation, cross-run guessing, launch quota, exact request shape, CSRF/Origin,
  route-specific mixed-cookie selection, handoff expiry/replay, same-subject denial, reset races,
  stale-cookie replay, and purpose/state prerequisites in memory-backed API tests.
- Applied all 27 migrations to a fresh CockroachDB database and verified composite relationship
  failures, exact grants/denials, hashed credential persistence, PostgreSQL-path handoff exchange,
  expiry, and atomic reset. The complete Python source touched by this item reaches 100% statement
  and branch coverage when run through the repository's CI-equivalent coverage sequence.
- Re-ran the browser regression suites after retiring bootstrap exchange: all 8 Playwright product
  tests and all 3 native Chromium WebMCP tests pass.

## 2026-08-29 — Onboarding

- Calibrated the participant as an experienced builder from the existing repository rather than
  requiring an unnecessary self-assessment.
- Confirmed the security-first priority: choose best-known security and functionality practices
  before speed or feature count.
- Initially discussed a 70% judge-visible / 30% artifact allocation; this was superseded during
  scope review by two independent 100% completion gates.
- Confirmed first-class testing in both ChatGPT's in-app browser and Google Chrome WebMCP.
- Reviewed the live official Devpost overview, rules, judging criteria, submission requirements,
  key dates, resources, prizes, and latest announcement for The WebMCP Challenge.
- Scope decision: no production infrastructure adapter in the submission. The live path performs an
  actual server-side mutation against an isolated deterministic checkout sandbox, with independent
  measurement and explicit claims. A disconnected production adapter contract may be documented,
  but simulator trust must never be presented as production-remediation safety.
- Participant actively emphasized: “the strongest proof possible” and decisions that maximize the
  hackathon judging result.
- Optional aesthetic round closed without changes; retain the serious incident control-room design.

## 2026-08-29 — Scope

- Froze RecallOps as one deterministic two-occurrence incident story rather than a broad platform.
- Defined judge-visible product proof and independently reproducible assurance as two separate
  completion gates, each required at 100%; neither can compensate for weakness in the other.
- Kept exactly four bounded WebMCP tools and reserved approval, sandbox execution, observation
  retry, review, role changes, policy override, and reset for authenticated non-WebMCP authorities.
- Retained a real allowlisted server-side sandbox mutation with independent measurement while
  explicitly excluding production infrastructure access and production-safety claims.
- Made review-gated recurrence the impact proof and a signed, offline-verifiable authority receipt
  the supporting assurance proof.
- Cut generic platform scope, extra scenarios, extra tools, speculative cryptography, browser-
  automation claims, and presentation work that could weaken live reliability.
- Mapped the product story directly to WebMCP Leverage, Execution, Potential Impact, and Creativity
  & Ambition, with a binary acceptance gate for each material claim.

## 2026-08-29 — Dual-proof standard

- Replaced percentage-based effort allocation with a dual-proof invariant: every material claim
  must have both judge-visible live evidence and independently reproducible assurance.
- A feature is not complete when only its interface works, and an artifact is not complete when it
  cannot be connected to the deployed behavior a judge sees.
- Work may be sequenced by dependency and submission risk, but neither proof surface is allowed a
  reduced acceptance threshold.
- Submission readiness is the intersection of both gates: `LIVE_PROOF_COMPLETE` and
  `ASSURANCE_COMPLETE`.

## 2026-08-29 — PRD interview

- Approved direct entry into an active operator room with the incident, capability state, and a
  copyable agent prompt already visible.
- Approved one sequential protected action at a time after proposal creation so the operator sees
  approval before the distinct sandbox-application step.
- Approved a separate pre-provisioned reviewer link with an unmistakable identity and role banner
  and no operator controls.
- Approved an expandable `Verify evidence` view on every material activity-rail event so assurance
  remains connected to the live product rather than hidden in a separate artifact archive.

### Deepening round 1 — judge recovery and proof presentation

- Approved immediate first-screen proof: active incident, rejected high-similarity memory, current
  capability set, and one copyable agent prompt without a splash or setup flow.
- Approved server-state reconciliation across refresh, duplicate tabs, stale sessions, repeated
  clicks, and out-of-order actions; the interface exposes only an authorized recovery action.
- Approved presenting fail-closed observation and validation outcomes as product states, including
  proof that no memory or unauthorized write was created.
- Approved persistent, mutually exclusive operator and reviewer role experiences with explicit
  server-rejection feedback for cross-role attempts.
- Approved progressive evidence disclosure: human-readable bindings first, technical digests and
  versions one level deeper, and a final receipt summarizing the complete authority chain.

### Deepening round 2 — adversarial journeys and misuse

- Approved nondiscovery of protected operations and bounded denials for guessed, withdrawn, or
  stale actions without leaking sensitive policy or endpoint details.
- Approved explicit untrusted-content treatment: incident and memory text may inform analysis but
  cannot alter capability, authority, workflow state, tool arguments, or eligibility policy.
- Approved invalidation of prior authorization after reset, expiration, proposal replacement, or
  state advancement, with no silent transfer of intent to a new action.
- Approved one authoritative outcome under replay and concurrent requests, with losing requests
  reconciling to committed server state and no duplicate mutations or memories.
- Approved a precise separation-of-duties claim: distinct authenticated subjects are verifiable;
  physical-person independence and general browser-automation prevention are not claimed.

### Deepening round 3 — empty, degraded, and boundary states

- Approved an honest unsupported-client state with no simulated substitute WebMCP calls.
- Approved read-only degraded behavior until authoritative synchronization succeeds; stale cached
  state can never enable an authority-bearing action.
- Approved explicit abstention and bounded rejection reasons when no memory is eligible; ineligible
  memory cannot be relabeled as advisory evidence.
- Approved `POSTCHECK_UNAVAILABLE` with no assessment capability or memory, operator-only recovery,
  and retry that cannot repeat the recorded sandbox mutation.
- Approved independent display of agent assessment and policy verdict; reviewed failures may become
  negative evidence while inconclusive or rejected evidence remains non-retrievable.
- Approved server-authoritative expiry behavior for proposals and sessions rather than treating a
  client countdown as authority.

### Deepening round 4 — accessibility and immediate comprehension

- Approved a first viewport that answers incident, available capability, authority owner, trusted
  evidence, and next-action questions within five seconds.
- Approved redundant text and visual semantics so no role, state, or outcome relies on color alone.
- Approved complete keyboard and screen-reader journeys with concise state announcements and
  restrained focus movement.
- Approved responsive behavior for ChatGPT's constrained in-app browser and standard Chrome with no
  horizontal scrolling for material controls or evidence.
- Approved plain-language workflow meaning before expandable protocol, digest, epoch, and policy
  details.
- Approved reduced-motion behavior and exact UTC timestamps alongside readable relative time.
- Approved consequence and binding previews for enabled protected controls, plus prerequisite
  explanations for disabled controls.

### Deepening round 5 — three-minute emotional narrative

- Approved capability withdrawal and visible transfer from agent to operator as the primary wow
  moment.
- Approved opening on the rejected 0.94-similarity, wrong-version known failure within ten seconds.
- Approved a successful main path with measured recovery, agreement, independent review, and later
  positive reuse; disagreement stays a secondary live evaluation rather than complicating the
  central story.
- Approved one compact observation-unavailable proof without replaying a full failure journey.
- Approved a 2:40–2:50 product-first video with no source-code detour.
- Approved “Similarity can discover experience. Only reviewed evidence earns authority.” as the
  sole closing line.

### Deepening round 6 — credible impact measurement

- Approved a committed, versioned synthetic benchmark spanning compatibility, lifecycle,
  tenancy, review, revocation, inconclusive evidence, and abstention cases.
- Approved a fair similarity-only counterfactual using the identical candidate pool, query,
  similarity values, and deterministic tie-breaking, with the baseline algorithm published.
- Approved exact counts and denominators for unsafe selection, pending leakage, abstention,
  incompatibility rejection, and reviewed-evidence recurrence changes.
- Approved zero accepted violations as the requirement for stale mutation, unauthorized protected
  transition, duplicate side effect, cross-tenant leakage, and receipt-tampering cases.
- Approved explicit synthetic-evaluation labeling and rejected unsupported production impact,
  time-saved, or universal-safety extrapolation.
- Approved direct binding from the live scenario to its raw benchmark case, evaluation version,
  source revision, expected and observed outcomes, and generation command.
- Approved publication of all cases and failures, with submission readiness false until any
  failing invariant is corrected and artifacts are regenerated.

### Deepening round 7 — claim-to-evidence traceability

- Approved stable claim IDs mapping every scored statement to rubric category, live state, event,
  test, raw evaluation case, and receipt field.
- Approved live exposure and bundle binding of source commit, deployed image digest, capability
  policy, benchmark version, and receipt-key thumbprint.
- Approved a credential-free complete proof bundle and deterministic offline verifier with valid
  and materially tampered fixed vectors.
- Approved treating in-product verification as supporting evidence and the offline verifier as the
  independent assurance surface.
- Approved precise receipt limitations: the signature and supplied-chain policy are verifiable;
  external truth, physical presence, trusted time, and completeness against a compromised signer
  are not claimed.
- Approved dated public-key continuity and explicit key transitions rather than silent replacement.
- Approved one judge-facing evidence index with live, raw, and reproduction paths per claim.

### Deepening round 8 — reviewer governance and memory lifecycle

- Approved immutable observation, agent assessment, and policy verdict; review changes admissibility
  only and cannot rewrite evidence.
- Approved policy-defined positive/negative semantics that a reviewer cannot relabel.
- Approved certify, quarantine, and reject decisions with bounded reasons and exact evidence/digest
  previews.
- Approved certified failures as warnings and ranking penalties, never recommended remediations.
- Approved protected reviewer revocation that removes future retrievability while preserving prior
  receipts and appending a new event.
- Approved policy-defined expiry and supersession with historical inspectability but no silent
  recommendation influence.
- Approved separation of duties across all review and revocation decisions, not only activation.

### Deepening round 9 — differentiation and memorable product polish

- Approved an agent-native incident room rather than a generic embedded chatbot.
- Approved stable incident/evidence, Capability Inspector, and Activity Rail visual anchors.
- Approved capability withdrawal plus authority-owner change as the signature visual transition,
  with reduced-motion support.
- Approved a compact, explorable authority chain for the final receipt.
- Approved disciplined product vocabulary and rejected vague autonomous, trusted-AI, safe-by-
  design, and production-remediation claims.
- Approved progressive disclosure that keeps raw proof in context without displacing the workflow.
- Approved visibly separate demo start/reset controls that cannot be mistaken for WebMCP tools.
- Approved independent Live proof and Assurance completion indicators tied to deployed evidence.

### Deepening round 10 — public-demo resilience and release operations

- Approved fresh bounded workflow leases and sandbox namespaces so concurrent judge runs remain
  isolated.
- Approved workflow-bound short-lived reviewer handoff to a distinct subject rather than global
  role switching.
- Approved safe no-signup availability with quotas, expiry, payload limits, abuse controls, and an
  honest exhaustion state.
- Approved stable public bootstrap, one-time session exchange, and fresh-run recovery without reuse
  of expired authority.
- Approved fail-closed dependency behavior and independently stale-aware Live proof and Assurance
  gates.
- Approved one deployed build identity across page and artifacts and reopening both gates after any
  deployment change.
- Approved continuous end-to-end smoke proof in both target clients throughout judging.
- Approved synthetic-only public data, redacted logs, bounded retention, and secret-free bundles.
- Approved a concise judge runbook and one frozen release candidate across deployment, video,
  repository, receipt, benchmark, and Devpost submission.

### PRD completion

- Completed ten deepening rounds after the mandatory behavior interview.
- Converted the scope into user journeys, twelve behavior epics, testable acceptance criteria,
  edge-case responses, dual-proof standards, submission proof points, and demo acceptance.
- Active shaping by the participant: replaced the initial effort split with two 100% gates and
  explicitly requested sophisticated maximum-depth refinement before document generation.

## 2026-08-29 — Technical specification

- Preserved the modular monolith and isolated judge sandbox; introduced no production adapter,
  generic platform surface, embedded model, fifth WebMCP tool, or new demo scenario.
- Translated the PRD into exact trust boundaries, eight workflow states, four tool schemas,
  protected route namespaces, role/session rules, canonical bindings, database migrations,
  runtime grants, file ownership, data flows, failure semantics, and verification gates.
- Verified current WebMCP behavior against the 26 August 2026 Community Group draft. Registration
  withdrawal uses the registration signal; in-flight cancellation uses the callback's
  `options.signal`; neither substitutes for server state/epoch/idempotency enforcement.
- Kept human authority server-enforced through separate operator/reviewer cookies, exact route-
  derived channels, CSRF/Origin checks, object digests, workflow CAS, and distinct-subject review.
- Specified a persisted observational timeline for judge-visible tool/browser activity while
  keeping it outside the authoritative hash chain and incapable of changing domain authority.
- Froze fail-closed evidence semantics, policy/assessment disagreement preservation, lifecycle-
  gated recall, exact allowlisted sandbox action, and zero arbitrary command/metric authority.
- Defined an RFC 8785 hash-chained ledger, KMS Ed25519 compact JWS receipt using RFC 9864's fully
  specified `Ed25519` JOSE identifier, credential-free finalized synthetic bundle, versioned S3
  export, and network-free verifier with tampered vectors and exact proof limitations.
- Bound Live proof and Assurance independently to the same source SHA/image digest and prohibited
  green readiness after any dependency failure, stale artifact, or release change.
- Inventoried all 30 stories and exactly 149 story acceptance criteria, plus 16 edge cases and 15
  cross-cutting standards. The checklist must assign an explicit assertion/evidence link to every
  derived requirement ID; no waiver or score-weighted partial completion is allowed.
- Active shaping by the participant: “completely translate these requirements into technical
  boundaries without weakening or expanding them” using maximum-depth reasoning and choosing
  security, functionality, and judge-verifiable proof first.

## 2026-08-29 — Build checklist

- Treated “use high reasoning to do it” as a planning handoff consistent with the learner profile:
  autonomous build mode, no comprehension quizzes, narrow verified commits, and milestone-only
  check-ins rather than repeated preference questions.
- Selected verification pauses after the authority core, complete live story, independent proof,
  and frozen deployment. Codex continues through passing work and stops only for a real invariant,
  external-authority, or manual ChatGPT-client blocker.
- Preserved the already verified three-milestone baseline and sequenced the remaining work by
  dependency and failure cost: traceability → run/session isolation → governance → ledger → four-
  tool/reviewer journey → accessible UI → receipt core → offline bundle → evaluation/gates → full
  adversarial matrix → deployment → Devpost handoff.
- Kept the signature wow moment unchanged: `propose_mitigation` disappears while authority visibly
  transfers from agent to operator. The later recurrence and offline verifier complete the same
  causal story rather than becoming separate demos.
- Produced twelve implementation items. Every item carries a spec reference, concrete build scope,
  PRD/edge acceptance, and executable verification; the final item is always the Devpost handoff.
- Required the final trace to account for all 180 normative identifiers: 149 story acceptance
  criteria, 16 edge cases, and 15 cross-cutting standards, with no unknown, waived, or stale status.
- The checklist audit found and corrected a documentation-only inventory typo in `spec.md`: the
  closed **What We Are Building** allowlist contains eight PRD bullets, not seven; scope itself was
  unchanged.
- Deepening rounds: handoff path, so no separate interview round; performed an internal dependency,
  hidden-risk, proof-quality, item-size, release-order, and submission-readiness audit instead.

## 2026-08-29 — Build execution

### Item 3 — governed memory lifecycle and recurrence semantics

- Added RFC 8785/domain-separated canonical digests for new memories and three independently
  bound evidence layers. Supplied v1 digests are recomputed and constant-time checked; migrated
  pre-existing rows are explicitly labeled `legacy-memory-v1` instead of being misrepresented as
  canonical v1 evidence.
- Completed certification, quarantine, rejection, revocation, expiry, and compatible supersession
  semantics. Policy—not the reviewer or agent—derives positive, negative, or inconclusive meaning;
  inconclusive evidence is structurally barred from active state, and certified negative evidence
  can warn but cannot become a recommendation.
- Added CockroachDB checks plus a database trigger that permits governance metadata transitions but
  rejects changes to immutable memory evidence, digests, policy bindings, embeddings, or creation
  identity. Retrieval now applies tenant, service, lifecycle, expiry, revocation, supersession, and
  conclusiveness predicates before ranking.
- Added exact-digest, purpose-bound reviewer handoffs and role-route cookie selection, immutable
  reviewer evidence packets, closed reason/decision combinations, `If-Match` generation/epoch
  preconditions, transactionally coupled initial disposition, and protected secondary revocation.
- Added immutable `checkout-latency-43` recurrence comparison. It exposes the identical candidate
  pool to the published similarity-only baseline while the governed result can select only a
  compatible certified positive; certified negatives are bounded warnings and every other
  lifecycle state is absent from governed influence.
- Verification passed from a fresh database through migrations 001–028c: 214 unit/property/API
  tests and 11 real CockroachDB integration tests, including evidence-tamper rejection, active-
  inconclusive constraint failure, lifecycle filtering, revocation immediacy, historical
  inspectability, exact handoff binding, and transactional reviewer disposition. Ruff and strict
  mypy pass; all 8 Playwright product tests and all 3 native Chromium WebMCP regressions pass.

### Item 1 — requirement/provenance/regression baseline

- The first global Ruff invocation correctly exposed that an unrelated participant-owned untracked
  video helper is outside the repository's tracked quality baseline and currently has style errors.
  Preserved that file unchanged and narrowed the checklist wording to tracked Python plus the new
  generated-trace script, matching the existing milestone evidence scope rather than laundering an
  unrelated asset into this build item.
- Generated a deterministic 180-record trace skeleton with exact requirement text digests, stable
  IDs, owner/boundary/test/live/assurance destinations, the verified Milestone 3 source revision,
  and `planned` status only; no future test or release result was represented as passing.
- Verification passed: trace `149/149 + 16/16 + 15/15`, tracked Ruff, strict mypy over 24 source
  files, 204 Python tests with all 8 CockroachDB integration tests, branch-aware coverage 100%, 8
  Playwright judge/accessibility tests, and 3 native Chromium WebMCP tests.
- Used a fresh local `recallops_ci` database and the repository's CI-equivalent appended coverage
  sequence. The initial unit-only 196-test run correctly failed the 100% gate at 94.87% because its
  8 integration tests were skipped; it was not recorded as acceptance evidence.

### Item 4 — atomic authority ledger and honest activity timeline

- Added migration 029 with per-run ledger heads, append-only accepted authority events, and a
  structurally separate activity-observation table. Composite run/tenant/workflow/event foreign
  keys prevent cross-boundary attribution, exact runtime grants deny event mutation/deletion, and
  browser observations have no database path that can advance workflow or ledger authority.
- Implemented RFC 8785 canonical authority payloads and the frozen domain-separated predecessor
  hash construction. Sequence and epoch values are canonical decimal strings; timestamps, UUIDs,
  digests, build identity, capability policy, before/after state, before/after tool sets, actor,
  role, and channel are bound into every event. A system-authored genesis event now binds the
  initial isolated run and capability surface inside run allocation.
- Coupled workflow CAS/epoch mutation, authority-event append, and conditional ledger-head update
  to the same serializable transaction used by each protected domain write. A PostgreSQL ledger
  refuses receipt-capable appends without an enclosing transaction. Reset likewise commits run
  invalidation, session/handoff revocation, workflow invalidation, reset event, and head advance as
  one unit.
- Added an honest deterministic timeline projection ordered by database `recorded_at` then UUID.
  Entries expose `authority_commit` versus `supporting_observation` explicitly; only the former
  carries a sequence and event hash, and the API states that observations confer no authority.
- Verification passed on a fresh CockroachDB database through migrations 001–029: 224 unit/API/
  property tests and 22 real integration tests. The integration suite injects faults before and
  after domain, workflow, event, and head writes; every case leaves the domain, epoch, event table,
  and head unchanged. Four concurrent appends serialize into one independently recomputable chain.
  Exact-grant verification reports 45 grants, 15 cross-boundary constraint rejections, and 24
  prohibited runtime operations. Ruff and strict mypy pass; all 8 browser tests and all 3 native
  Chromium WebMCP regressions pass.
- The combined branch-aware repository report is currently 99%, with remaining branches tracked
  for the full adversarial matrix in item 10. No 100% coverage claim is made at this checkpoint;
  the Authority gate is based on the explicit atomicity, ordering, role/channel, isolation, and
  independent-recomputation assertions above.

### Item 6 — judge-visible control room and accessible causal proof

- Reframed the first viewport around the product thesis, exact agent prompt, deterministic
  `checkout-latency-42` incident, and a real cosine-similarity contrast: the 0.94 known-failed,
  incompatible memory remains visible but ineligible while the compatible reviewed 0.81 memory is
  admissible. The values are derived from fixture embeddings rather than presentation-only labels.
- Added server-derived Capability Inspector, Protected Action panel, chronological authority
  timeline, three-layer evidence view, explicit authority handoff chain, reviewer evidence cards,
  and the later compatible recurrence proof. Operator evidence is role-protected and bounded; it
  exposes digests and lifecycle state but no embeddings or credentials.
- Made browser startup deny-all. No WebMCP tool is registered until configuration, identity, run,
  and the authoritative capability manifest establish the current state. Any synchronization error
  withdraws every tool and disables protected controls until reconciliation succeeds.
- Preserved protected transitions as server-enforced UI routes. The operator approves one exact
  proposal digest and issues a single-use reviewer handoff; the distinct reviewer page loads zero
  WebMCP tools and renders immutable measurement, attributable agent opinion, policy verdict, and
  bound pending memory as separate records.
- Added a real one-click judge-mode Playwright journey covering startup denial, proposal staging,
  immediate capability withdrawal, exact-action approval, allowlisted sandbox execution,
  independently generated evidence, pending-review quarantine, separate reviewer certification,
  reviewed recurrence, and persisted authority commits. The suite also checks desktop/reviewer
  accessibility and 390px layout containment.
- Verification passed: Ruff, strict mypy, all 251 Python tests, 10 browser tests, 4 native Chromium
  WebMCP tests, and 2 full judge-mode tests. Axe reported zero serious or critical findings on the
  completed operator and reviewer pages; security-header assertions cover CSP, frame denial,
  nosniff, Origin-Agent-Cluster, and WebMCP Permissions-Policy. Desktop and constrained screenshots
  were visually inspected, and the participant approved the Live-story checkpoint.

### Item 7 — pinned receipt core (implementation checkpoint; live KMS gate open)

- Verified the frozen algorithm profile against RFC 8785, RFC 7638, RFC 8037, RFC 9864, and the
  current AWS KMS `GetPublicKey`/`Sign` documentation. The production adapter accepts only
  `ECC_NIST_EDWARDS25519`, `SIGN_VERIFY`, `ED25519_SHA_512`, and `MessageType=RAW`; deprecated
  `EdDSA`, prehashed Ed25519, ECDSA, RSA, and local-key fallback paths do not exist.
- Added migration 030 with receipt/release records, one active receipt per immutable ledger prefix,
  closed database status transitions, immutable prefix/release bindings, signed-material freeze,
  exact runtime grants, and direct cross-run/tenant constraints. A fresh database applied all
  migrations through 030 and all 24 Cockroach boundary tests passed: 61 exact grants, 17 rejected
  cross-boundary relationships, and 32 prohibited runtime operations.
- Implemented complete genesis-to-target ledger-prefix verification, RFC 8785 canonical manifests,
  exact 2 KiB/4 KiB bounds, RFC 7638 OKP thumbprints, fully specified compact `Ed25519` JWS,
  repository-pinned trust roots, signed predecessor key transitions, and local verification of the
  exact signature returned by KMS before a receipt can exist.
- Replaced guessable subject hashes with domain-separated HMAC-SHA-256 pseudonyms under a required
  server-held key of at least 256 bits. Neither raw subject nor pseudonym key enters the manifest.
- Added 26 focused canonicalization, ledger, manifest, key-registry, JWS, KMS-contract, tamper,
  build-mismatch, and privacy tests. The deterministic manifest is exactly 2,030 bytes and its KMS
  signing input is exactly 2,862 bytes.
- The repository-pinned registry remains intentionally empty and production preflight fails closed
  because no real receipt KMS key or frozen release ID is configured in this workspace. No live-KMS
  pass or completed item-7 claim is recorded. Combined branch coverage is 95.65%; the 100% release
  coverage gate remains open for the adversarial-matrix item rather than being misrepresented.

### Item 8 — independent authority bundle (core checkpoint; external proof gate open)

- Implemented the one-way digest graph frozen by the spec: canonical auxiliary evidence, signed
  evidence-index digest, compact manifest, Ed25519 JWS, outer checksum file, and an externally
  recorded domain-separated bundle digest. Deterministic ZIP creation fixes order, timestamp,
  permissions, UTF-8 flags, and compression; strict extraction rejects extra, duplicate, traversal,
  symlink, special, oversized, and malformed members.
- Added a network-free Node verifier using built-in crypto only. It checks the exact file set and
  bounds, duplicate JSON keys, RFC 8785 byte equality, external bundle digest, repository-pinned
  JWK and RFC 7638 thumbprint, frozen RFC 9864 JWS header, Ed25519 signature, evidence index,
  ledger chain, transition/capability/actor/channel rules, tenant/release bindings, separation of
  duties, causal object bindings, disposition, policy content, claims, and evaluation version. It
  returns bounded stable error codes and never obtains trust from the bundle itself.
- Closed a proof-level causal gap by binding the live journey's proposal, execution, observation,
  policy verdict, assessment, memory, and review into transition-specific composite hashes. The
  full judge-journey test recomputes those hashes from persisted evidence; signed-but-policy-invalid
  actor, capability, causal, policy, and disposition vectors are rejected semantically.
- Added a write-once private S3 adapter with exact object keys, `If-None-Match`, SHA-256 transport
  checksums, mandatory KMS encryption evidence, mandatory version IDs, and retry reconciliation
  only for an existing object with the identical bundle digest. Added a credential-free public
  route that serves only signed, synthetic, explicitly public receipts after fetching the exact
  recorded S3 version and revalidating the ZIP/checksum/bundle digest.
- Extended migration 030 with immutable receipt requests, closed lease/delivery/dead-letter states,
  public-synthetic constraints, and required object-version evidence. Real Cockroach verification
  passes all 24 boundary tests with 64 exact grants and 36 prohibited-operation denials. A separate
  real-database test proves lease claim, failure retry, failed-to-pending reset, atomic signed+
  delivered finalization, idempotent replay, bounded backoff, explicit publication, and terminal
  dead-letter behavior.
- At this checkpoint the Independent-proof gate remained open. Fixed published vector directories,
  complete receipt enqueue wiring at reviewer disposition, and the human-readable signed authority-
  chain projection were subsequently completed below. The remaining open boundary is the complete
  production material loader/finalizer exercised against live KMS and versioned S3. Item 8 remains
  unmarked, and storage/signing mocks are not represented as live external evidence.

### Item 8 — independent bundle continuation

- Reviewer disposition now commits the governed memory, completed workflow, final composite-bound
  authority event, deterministic pending receipt, and immutable `receipt_requested` row in the same
  transaction. In-memory and browser journeys assert the same behavior; no receipt is requested
  before independent review.
- Moved causal verification ahead of manifest construction and therefore ahead of KMS signing. A
  valid signature can no longer be requested over unrelated proposal/execution/observation/verdict/
  assessment/memory/review digests. Both Python construction and the independent Node verifier
  enforce the exact same transition-specific bindings.
- Added an authenticated human-readable receipt projection and visible control-room panel. Pending,
  failed, and signed states use distinct language; the download remains hidden until the database
  identifies a signed, synthetic, explicitly public, exact-version bundle. The UI repeats the
  receipt's proof limitations rather than presenting cryptographic integrity as external truth.
- Published one deterministic valid vector and 14 deterministic tampered vectors under
  `artifacts/authority-vectors/`. Generation is byte-identical across two runs (tree digest
  `361ff279f85bd81622ac1a2dcc77f4cc42d3499d5865c984f54a319f1dca3ab9` over canonical relative-path
  and content-digest pairs), and the committed verifier
  reports all 15 exact expected codes. The vector signer is test-only and explicitly not a
  production trust root; production retains no local signing fallback.
- Hardened the Cockroach receipt-request boundary so it locks the ledger head and independently
  reloads the exact committed review event before enqueue. A fabricated in-process event object
  with the real head hash but altered content is rejected; the exact event creates the receipt and
  request atomically in the same authority transaction.
- Corrected the native WebMCP assessment test to evolve its mocked capability manifest through the
  same authoritative states as the mocked operator actions. This removes a test-only withdrawal
  race without retrying or weakening real lifecycle semantics; the complete native suite passed
  twice consecutively.
- Checkpoint verification passed: Ruff, strict mypy over 31 source files, the full Python suite
  against CockroachDB, 10/10 browser tests, 2/2 judge-mode journeys, 4/4 native Chromium lifecycle
  tests, and all 15 fixed offline-verifier vectors with their exact expected result codes.

### Item 8 — immutable production finalizer checkpoint

- Added the production receipt material loader and finalization worker. It claims one immutable
  request, reloads the exact genesis-to-review Cockroach prefix and current head, verifies the
  frozen run/release identity, independently recomputes assessment, policy-verdict, and memory
  digests, verifies disposition against governed memory state, and constructs policy/evaluation/
  claim evidence before KMS is allowed to sign.
- Made retry output byte-stable by deriving the asserted signing time from the immutable receipt-
  request creation timestamp. The resulting Ed25519 signature and deterministic ZIP can be safely
  reconciled with the same write-once S3 key if a worker loses its database lease after upload.
- Added the no-fallback production composition and `recallops-receipt-worker` CLI. Startup requires
  the repository-pinned trust registry, exact KMS release key, versioned private S3 bucket/key,
  canonical release artifacts, and a canonical base64url pseudonym key of at least 256 bits.
- A real Cockroach integration proof now completes request claim → immutable material load → local
  Ed25519 KMS-boundary signing → deterministic bundle validation → versioned archive result →
  atomic signed/public receipt and delivered request. A subsequent post-review assessment mutation
  is detected and rejected rather than signed.
- Full functional verification passed with Ruff, strict mypy over 32 source files, the complete
  Python/Cockroach suite, 4/4 native Chromium tests, and all 15 verifier vectors. The first honest
  full branch-coverage measurement is 92.57% (287 statements and 148 partial branches remain), so
  the 100.00% item-10 gate remains red; no exclusions, threshold changes, or rounded claim were used.
- The remaining item-8 external boundary is unchanged: run the same production worker against the
  release-pinned AWS KMS key and versioned private S3 bucket, then download and independently verify
  that exact live object version. Local emulation is not represented as live AWS proof.

### Item 8 — live independent-proof gate (complete)

- Fixed a release-path defect discovered by the live gate: generated `evaluation-case.jcs.json`
  did not carry its evaluation version, so the strict production document loader would reject it.
  The generator now binds that version explicitly and a regression assertion prevents recurrence.
- Added a reproducible live-proof runner that performs the complete operator/agent/reviewer journey
  against a fresh Cockroach database, starts the no-fallback production receipt worker, requires an
  actual startup signing probe, downloads through an unauthenticated route, extracts with the strict
  ZIP reader, and invokes the network-free Node verifier. It emits no database URL, secret value,
  raw subject, or tenant identifier.
- Built committed source `0ce35d4bbf7fe6519037c981bea6442010125fb2` and pushed it to the
  immutable ECR repository as digest
  `sha256:02842785eb4d0339a3f6e81c656c6802c394f32203d4cc85e37fe00bcd353cb6`.
  This is an intermediate external-boundary proof image, not the final frozen submission release.
- Live receipt `65df9b6d-390f-548e-ac0a-5a37fb130c99` binds seven accepted authority events and bundle
  digest `76314ee2d1cdad8cf7aaaad99db1d5254b92478744b7dff3383ef6270d0c762d`.
  S3 version `OTVF8uUF_8RjdEoFzHDkv7K7.OJltR66` is customer-KMS encrypted, bucket-key enabled,
  and compliance-locked until 2026-09-12. The credential-free application route returned the same
  recorded digest, and the independent verifier returned `VERIFIED` with event count seven.
- `artifacts/aws/live-item8/` preserves the downloaded ZIP, strict extracted file set, canonical
  bounded proof record, and reproduction notes. This proves the external KMS/S3 boundary; it does
  not turn either final release gate green or claim external truth, physical-person presence,
  trusted time, or signer completeness.
- The final independent-proof gate passed 475/475 combined tests against fresh CockroachDB with
  5,360/5,360 statements and 1,192/1,192 branches (100.00%), 15/15 exact verifier vectors, the
  downloaded live bundle verification, 10/10 browser tests, 4/4 native Chromium tests, tracked and
  item-owned Ruff, strict mypy, all CloudFormation lint, and a clean diff check.

### Item 9 — generated evidence and dual-gate core (external statement gate open)

- Added a deterministic 12-case governed-retrieval benchmark and nine bounded WebMCP agent cases.
  Similarity-only and governed selection consume the identical candidate arrays and deterministic
  tie-break. The measured local result is 11/12 unsafe similarity-only selections versus 0/12
  governed unsafe selections, 2 versus 0 pending-memory leaks, 3/3 correct abstentions, and a
  recommendation change only after independent review. Results are explicitly synthetic and make
  no production incident-rate claim.
- Added a 12-claim registry with claim-specific live routes, workflow event types, test paths,
  evaluation cases, receipt fields, raw artifacts, and an exact regeneration command. Enriched all
  180 frozen requirements without marking any verified: each remains `implemented` until item 10
  derives its status from complete assurance artifacts.
- Implemented independent Live proof and Assurance gate derivation. Missing, failed, duplicate,
  stale-SHA, stale-image, or mismatched artifacts keep their gate red, and release readiness is the
  strict intersection. Two clean-directory generations are byte-identical in automated tests.
- Added an acyclic release-statement payload plus KMS-signing and repository-pinned verification.
  The public `/v1/release` projection compares database evidence to the running source, image,
  policies, and evaluation version, then verifies the exact signed gate digests. Completing the
  demo no longer changes a readiness badge; local evidence remains visibly pending.
- Hardened the external evidence boundary so an attestation manifest cannot make either gate green
  unless every referenced artifact is a present regular file beneath an explicit trusted root and
  its bytes match the declared SHA-256 digest. Absolute paths, traversal, duplicate paths, missing
  files, and tampered bytes fail generation. Added a one-shot release-statement command that checks
  canonical payload bytes, preflights the repository-pinned Ed25519 KMS key, signs the acyclic gate
  statement, verifies the compact JWS locally, and refuses to overwrite an existing result.
- Fixed a real concurrent registration weakness found by repeated native-client testing: a tool
  lifecycle controller is reserved before awaiting browser registration, preventing duplicate
  registrations during simultaneous authoritative refreshes. Native assessment readiness now waits
  for completed registration rather than merely observing an intermediate tool name.
- The committed local evidence identity deliberately uses an all-zero image digest and unpinned
  placeholder key thumbprint, so both gates and release readiness are false. The final KMS-signed
  statement can only be produced after the immutable image and AWS key exist; this external proof
  is not claimed or replaced with a local signer.
- Item-9 live proof binds source `c76320666d4447bef64f5919b3cdeb715bd5e637` to immutable ECR
  digest `sha256:b2e0f0a0abdf515891a415fbbd9e0b0096c272c4621c296f4751ccdd15ec1fad`.
  Two clean generations were byte-identical. The live KMS signer produced a locally verified
  release-statement JWS with digest
  `c841979023f7e579eaafe6aed6eeed61ce0fe43693da67dc861a612246bdfea3`.
  The signed statement truthfully records both gates and `release_ready` as false until their
  mandatory exact-image evidence exists. The three frozen release documents and signed statement
  are stored as versioned SSE-KMS objects; the statement version is
  `8dGI7armYplxKylYK7IQpiO4Cd9Rvn1N` under 14-day S3 Object Lock COMPLIANCE retention.

### Item 10 — complete local automated assurance (manual/external gates remain open)

- Closed every reachable production line and branch without coverage exclusions or threshold
  reduction. The exact CI sequence on a freshly migrated CockroachDB database reports 5,288 of
  5,288 statements and 1,172 of 1,172 branches covered, with zero missed lines and zero partial
  branches. The enforced `fail_under = 100` gate and `coverage report --fail-under=100` both pass;
  a Cobertura XML report is generated for CI retention.
- Added focused boundary suites for API exception translation and transactional WebMCP
  idempotency, receipt finalization classification and retry behavior, receipt-outbox faults,
  canonical receipt/key-transition validation, archive and public-download corruption, release
  status, CLI failures, session expiry, ledger faults, workflow conflicts, and direct Cockroach
  relationship/grant boundaries. The exact CI test sequence passes 415 unit/API tests plus 28 real
  CockroachDB integration tests and the covered CLI paths.
- Removed a WebMCP idempotency time-of-check/time-of-use gap by making the authoritative locked
  transaction the sole replay/conflict decision point. Exact replay remains permitted after state
  advancement, while first execution still requires the matching authoritative workflow epoch and
  a reused key with different input fails closed.
- Corrected receipt-worker exception classification so dependency unavailability retries,
  malformed immutable material terminates, and signing failures remain retryable. This matters
  because the receipt error hierarchy also derives from `ValueError`; the more specific classes
  are now handled before the generic material-validation case.
- Expanded safety-critical mutation testing to every test family that exercises `evidence.py`,
  `service.py`, and `store.py`, including API, sessions, lifecycle, sandbox, resilience, and
  retrieval. The unmodified 70% CI gate passes at 73.95%: 1,493 of 2,019 mutants killed, 526
  survived, zero untested, skipped, suspicious, timeout, or interrupted mutations. This is stated
  separately from 100.00% structural coverage and is not rounded or presented as 100% mutation
  coverage.
- Final local assurance passed: Ruff on all repository-owned Python, strict mypy over 35 source
  files, 10/10 browser tests, 2/2 first-time-judge journeys, 4/4 native Chromium WebMCP lifecycle
  tests, zero serious/critical axe findings in the exercised journeys, 15/15 independent authority
  vectors with exact expected codes, the 149/149 + 16/16 + 15/15 trace validator, the synthetic
  policy evaluation, npm and Python dependency audits with zero known vulnerabilities, both AWS
  CloudFormation templates under `cfn-lint`, and Docker Compose validation.
- Item 10 remains deliberately unmarked because its acceptance also requires dated manual
  screen-reader/keyboard evidence and the supported ChatGPT site-tool client, plus release-bound
  artifacts with no `implemented`/stale requirements. Those observations cannot be manufactured
  from this local workspace. Items 7–9 likewise remain open only at their declared external
  KMS/S3/frozen-release boundaries; their local cryptographic and deterministic cores are covered
  by the results above.

### Item 11 — hardened local image checkpoint (AWS deployment gate open)

- Reduced the Docker build context from 619 MB to 2.026 MB by excluding local mutation, coverage,
  evidence, and media-production workspaces. None of those paths is part of the runtime image, and
  no participant-owned media file was changed or deleted.
- The first read-only-container smoke test correctly failed before release because `rfc8785` was
  present in `uv.lock` and the development environment but absent from both exported pip lock
  files. Regenerated `requirements.lock` and `requirements-dev.lock` from the frozen uv lock and
  added a dedicated CI production-image job so dependency-boundary drift must now fail before
  release.
- The corrected image builds from both digest-pinned base images and starts under the intended ECS
  security profile: numeric user `65532:65532`, read-only root filesystem, all Linux capabilities
  dropped, `no-new-privileges`, and a bounded no-exec temporary filesystem. The real `/health`
  endpoint returns `{"status":"ok"}` from that container, and the OCI revision label exactly
  matches the supplied full Git source revision.
- This remains local image evidence only. The local image ID is not represented as an ECR manifest
  digest, and item 11 remains unmarked. The AWS session in this workspace is expired, so immutable
  ECR push/scan, KMS signing, versioned S3 publication, ECS deployment, public URL checks,
  six-hour monitoring, and manual ChatGPT site-tool acceptance still require renewed external
  authority and direct observations.

### Item 12 — WebMCP judge packet reconciliation (final URLs/assets pending)

- Re-fetched the authenticated official Devpost submission requirements, four 5-point judging
  criteria, registration relationship, and key dates on 2026-08-29. The account is registered; the
  official submission deadline is 2026-09-03T20:00:00Z. The form requires a working WebMCP URL,
  public repository, sub-three-minute public YouTube video with audio, Existing-project disclosure,
  exact tested clients, AI-tool disclosure, and the remaining entrant-confirmed fields.
- Replaced tracked legacy CockroachDB-hackathon copy with a coherent WebMCP packet: README, final
  Devpost copy, judge guide, evidence index, submission checklist, video runbook/production notes,
  proof card, and complete challenge provenance. No tracked judge surface advertises the stale AWS
  URL, old video, obsolete form IDs, or false “not started” milestone status.
- The packet now leads with Capability Sculpting, exactly four tools, visible authority transfer,
  identical-input impact evidence, the verified-evidence/reviewer recurrence, independently
  verifiable receipt, exact local assurance counts, and explicit proof limitations mapped to the
  official WebMCP Leverage, Execution, Potential Impact, and Creativity & Ambition criteria.
- The initial reconciliation preserved the participant-owned untracked `devpost-submission.md`,
  thumbnail, subtitles, and video helpers unchanged. On the participant's explicit next
  prepare-submission pass, reconciled the private draft to the official WebMCP fields while retaining
  the useful problem, architecture, proof, and limitation material. The thumbnail remains unchanged
  and provisional; the stale CockroachDB/AWS subtitle files remain unchanged and are explicitly
  excluded from the WebMCP recording until replaced.
- Item 12 remains unmarked until the frozen live URL, exact two-client results, manual accessibility
  record, public video URL, final screenshots, entrant-confirmed form answers, and verified Devpost
  project page exist. Preparing these files does not submit anything to Devpost.

### Item 7 — pinned receipt core and standalone Free Plan foundation (complete)

- Replaced the obsolete Cognito/shared-task public template with a no-signup judge-session topology
  and separate API, evidence-outbox, receipt-finalizer, and one-shot migration task/execution roles.
  The API can only read exact finalized bundle versions; only the receipt task can call the exact
  Ed25519 key, and only `kms:Sign` is constrained to `ED25519_SHA_512`.
- Added a separate foundation stack for the immutable ECR repository, non-exportable
  `ECC_NIST_EDWARDS25519` receipt key, customer-managed evidence encryption key, generated HMAC
  secrets, and a private versioned S3 bucket with KMS encryption, public-access blocking, TLS-only
  policy, and 14-day compliance-mode Object Lock. The signing and encryption keys are retained with
  the evidence so stack deletion cannot silently destroy later verification. The CloudFormation
  execution policy is bounded to
  RecallOps-named resources in `us-east-1`.
- Added a fail-closed AWS account preflight that requires `FREE` + `ACTIVE`, at least USD 50 of
  remaining credits, at least 14 days before expiration, and a provably standalone account. Added
  root bootstrap and GitHub OIDC foundation workflows; neither principal has receipt-signing
  permission. The initial trust-root helper accepts only the frozen Ed25519 profile and refuses
  replacement without an explicit signed transition.
- Replaced local-only production receipt materials with exact S3 version/digest pins and injected
  canonical trust registries for both the API readiness verifier and receipt worker. Added
  idempotent release-artifact upload reconciliation and customer-managed KMS encryption for the
  legacy evidence outbox when configured.
- Verification passed: tracked Ruff, strict mypy, CloudFormation lint for all three templates,
  focused AWS bootstrap tests, 475/475 combined unit/API/fresh-Cockroach tests, 5,359/5,359
  application statements and 1,192/1,192 branches (100.00%), 10/10 browser tests, 4/4 native
  Chromium WebMCP tests, and 15/15 offline authority vectors. Browser concurrency is now fixed at
  the same two-worker contract locally and in CI after an eight-worker host-saturation run exposed
  timeout variance.
- Added 23 focused AWS boundary tests that parse the CloudFormation and IAM documents and fail on
  weakened immutability, key durability, role separation, signing authority, bundle access,
  ingress topology, bootstrap counts, retired-account references, organization mutation, or broad
  identity mutation. The refreshed templates pass those tests and CloudFormation lint locally.
- Live AWS validation passed in standalone account `158363272009`: both identity policies have zero
  Access Analyzer findings, both templates pass the service-side validator, and the foundation is
  `CREATE_COMPLETE` and `IN_SYNC` with zero drifted resources. The repository now pins live KMS
  thumbprint `VIqQfWwrVJ8OqkQu974E2c8zdd0xw1f2W4YFkgEQCTE`; startup performed a real
  `ED25519_SHA_512`/`RAW` signature and locally verified the returned 64-byte signature. Live checks
  confirmed immutable/scanned ECR, enabled symmetric-key rotation, private KMS-encrypted versioned
  S3, 14-day compliance Object Lock, full public-access blocking, a $50 cost budget, and the
  fail-closed standalone `FREE`/`ACTIVE` plan gate with $120 credits and card spending disallowed.
- Two failed foundation attempts produced useful negative evidence before success. The first exposed
  an omitted `GetRandomPassword` permission; the second exposed an ECR policy rejected by the live
  service. Both rolled back. The first attempt's two exact retained keys were scheduled for deletion
  on 2026-09-05; `RetainExceptOnCreate` now prevents future create-rollbacks from orphaning keys.
  The corrected templates and IAM policies carry regression tests for every discovered boundary.

### Item 10 — public ingress compatibility finding

- Live HTTP API requests reached the internal ALB through the private VPC Link but were rejected
  with HTTP 400 before reaching the healthy API task. AWS documents that Application Load
  Balancer `strictest` desync mitigation rejects requests whose classification is not fully
  compliant, while `defensive` routes compliant requests and permits ambiguous requests with
  connection safeguards. API Gateway's VPC Link request form triggered that compatibility edge.
- The public template now pins `routing.http.desync_mitigation_mode=defensive`, retains invalid
  header dropping, preserves the single API Gateway → VPC Link → internal ALB ingress path, and
  has a structural regression test for both attributes. This is the narrow AWS-supported
  compatibility setting; it does not expand network reachability or any RecallOps application,
  identity, tenant, evidence, authority, or receipt boundary.
- Added a public-only Playwright acceptance suite with no local web server. It drives the deployed
  operator and independently authenticated reviewer sessions, proves dynamic tool withdrawal,
  preserves an intentional agent/policy disagreement, waits for the production receipt worker,
  downloads the credential-free version-bound authority bundle, runs serious/critical Axe checks
  on both roles, records page errors, captures both views, and checks constrained-width overflow.
- The first real governed journey exposed two production-only least-privilege defects. Supporting
  activity namespacing violated the database's 64-hex rate-limit key constraint, and a no-op
  `ON CONFLICT DO UPDATE` on the memory parent row caused CockroachDB to require reverse-FK read
  authority on `memory_events`. The fix hashes the complete rate-limit namespace and uses
  insert-or-read with exact memory-digest equality. The API role remains unable to read governance
  events; a conflicting outcome memory now fails closed instead of being overwritten or reused.
- The next live reviewer transition exposed CockroachDB's reverse-foreign-key read requirement for
  parent updates. Migration 031 keeps that authority out of the API credential: direct API updates
  and event inserts are revoked, and a dedicated non-login `recallops_governor` owns one
  `SECURITY DEFINER` lifecycle routine. The function re-enforces the complete transition policy and
  writes state plus audit event atomically. Its owner has no schema-create authority; API-only
  execute and no-PUBLIC-execute are verified from live database metadata. A fresh database applied
  migrations 001–031, all 29 integration tests passed, and the combined suite passed 479 tests with
  5,392/5,392 statements and 1,206/1,206 branches (100.00%).
- The first deployed definer run then exposed a client-side locking read that still requested
  `UPDATE` before calling the function. The preliminary read is now non-locking; the definer
  acquires the authoritative `FOR UPDATE` lock and revalidates every policy condition itself.
  A regression assertion prevents `FOR UPDATE` from returning to the API-side query.
- The subsequent receipt request exposed the same pattern on immutable `authority_events`.
  Receipt creation still locks the mutable ledger head, but reads the append-only terminal event
  under the same serializable transaction without requesting forbidden event-update authority.
  Direct event mutation remains denied and a query-shape regression test preserves both facts.
- CockroachDB then required queue-read authority for `ON CONFLICT DO NOTHING` on
  `receipt_requests`. That authority remains withheld. The receipt request is part of the single-use
  reviewer transition and its serializable transaction, so it now uses a plain insert: transaction
  retries remain safe, while any committed duplicate fails closed instead of being silently
  accepted. The API still cannot inspect or mutate the worker's private queue.
- The live finalizer then proved that reusing the legacy evidence-outbox database credential was
  an invalid separation boundary. Migration 032 introduces a dedicated non-login
  `recallops_receipt` role with only the evidence-chain reads and receipt-state updates required to
  verify and finalize a bundle, while revoking every receipt privilege from `recallops_outbox`.
  The receipt ECS execution role and task now consume a distinct Secrets Manager URL; structural
  tests fail if either worker is wired to the other's credential.
- A fresh migration-032 database passed the complete 480-test suite with exactly 5,392/5,392
  tracked statements and 1,206/1,206 branches covered (100.00%). A direct database integration
  probe executed every receipt-material read and both allowed queue/receipt updates under
  `SET ROLE recallops_receipt`, then proved reciprocal worker isolation: the outbox role cannot
  read receipt evidence and the receipt role cannot read the evidence outbox.
- The immutable managed record for `webmcp-rc1` was retained rather than deleted or rebound after
  the security fix. The canonical repository trust registry now explicitly authorizes the same
  pinned KMS Ed25519 key for the successor `webmcp-rc2`; live proof requires that a requested
  release resolve to exactly one active pinned key, so no wildcard or fallback trust was added.
- The first `webmcp-rc2` public browser run produced a valid signed receipt, but its verifier
  repeatedly reloaded the page and interrupted the page's asynchronous receipt restoration before
  sampling it. The trace itself showed the restored signed receipt. The live test now polls the
  authenticated receipt endpoint to completion, performs one reload, and separately requires the
  UI to restore `SIGNED`; the exact public rerun passed both the full journey (24.1 seconds) and
  narrow viewport. `webmcp-rc2` remains immutable, while `webmcp-rc3` names the final candidate
  containing this stronger proof harness.
- The clean mutation campaign discarded the prior incremental cache and evaluated all 2,051
  generated mutants: 1,519 killed, 532 survived, and zero untested, skipped, suspicious, timed out,
  interrupted, or crashed. The genuine score is 74.06%, independently distinct from the exact
  5,392/5,392 statement and 1,206/1,206 branch coverage result.
- The deployed `webmcp-rc3` journey passed both public Playwright cases, produced a credential-free
  signed receipt bundle, and verified offline with seven authority events under the release-pinned
  KMS Ed25519 public key. Native Chromium 151 separately proved real `document.modelContext`
  discovery, annotations, closed proposal schema, state-driven withdrawal, stale-handle rejection,
  reload convergence, zero reviewer tools, and deterministic reset with no page errors.
- Thirteen independently hashed release artifacts now pass: all eight Assurance requirements and
  five of six Live Proof requirements. The generated gate is deliberately
  `ASSURANCE_COMPLETE=true`, `LIVE_PROOF_COMPLETE=false`, with exactly
  `chatgpt_site_tools` missing. Native Chromium is not accepted as a substitute for the required
  direct ChatGPT desktop Site Tools observation.
- Reconciled every public-facing tool name and capability table with the implemented four-tool
  contract: `inspect_incident`, `propose_mitigation`, `record_postcheck_assessment`, and
  `recall_reviewed_memory`. The submission copy now describes the deployed AWS candidate and exact
  assurance counts without converting missing ChatGPT, monitoring, or video proof into a green
  claim.
- The `webmcp-rc5` public journey then exercised a deliberately fail-closed release boundary: its
  receipt request became `RECEIPT_MATERIAL_INVALID` because the exact rc5 identity had not been
  registered in `release_evidence_records`. The failed request and immutable earlier rc1–rc3
  records were preserved; no record was deleted, rebound, or manually edited to manufacture a
  pass.
- Replaced that manual deployment assumption with an atomic release bootstrap in the one-shot
  migration task. Seven identity values are all-or-none and schema-validated before migrations;
  the task creates only a `pending`/`pending` record, exact retries are idempotent, conflicting
  release-ID reuse fails closed, and Cockroach serialization retries are bounded and use fresh
  connections. The module has 100.00% statement and branch coverage. A real CockroachDB concurrency
  test proved that two simultaneous registrations produce exactly one insert plus one verified
  retry, and that a different source SHA cannot rebind the identity.
- The final deployment protocol is now two phase: first update the digest-pinned stack with all
  public/worker services at zero; run migrations and independently query the exact immutable
  record; only then enable the API and receipt worker under the same release identity. This removes
  the request-before-bootstrap race without granting the migrator proof-gate or signing authority.
- Added the missing six-hour external monitor as a credential-free GitHub Actions workflow. It runs
  the complete public browser journey, verifies the downloaded receipt bundle offline, compares
  release identity before/bundle/after, retains evidence for 14 days, and fails the workflow on any
  drift. It has repository read permission only and therefore cannot mutate AWS, the database, or
  either proof gate. The frozen source is resolved from the explicit `webmcp-rc8-source` tag rather
  than copied into a self-referential build file.
- The first clean-run monitor attempt failed closed before browser setup because `git rev-list`
  does not support `--verify`. No smoke artifact or gate update was produced. The corrected workflow
  resolves the annotated tag to a commit with `git rev-parse --verify <tag>^{commit}`; rc7 remains an
  immutable failed candidate and rc8 is the successor rather than rewriting published history.

### Item 10 — direct ChatGPT client finding and fail-safe recovery

- Official ChatGPT Linux desktop `26.825.41651`, using GPT-5.6 Terra with high reasoning, discovered
  exactly `inspect_incident` and `propose_mitigation` on `webmcp-rc8`. It invoked both tools,
  rejected the incompatible higher-similarity candidate, staged proposal
  `97734ef6-b1f9-4fcb-a138-900dca334ab9`, and then exposed exactly one read tool and zero write tools
  while the page showed `AWAITING_OPERATOR_APPROVAL` and `HUMAN_OPERATOR`. The earlier Sol attempt
  that was denied browser access is retained in the partial observation rather than omitted.
- The operator approval attempt failed closed with `valid CSRF token required`. Root cause: creating
  a new ChatGPT Work chat recreated the built-in browser tab, preserving the secure HttpOnly
  operator cookie while correctly discarding the tab-bound synchronizer token from session storage.
  The old token cannot be reconstructed and the failed proposal was not approved or executed.
- Added a narrow recovery state: when an operator cookie is restored without its tab-bound CSRF
  token, RecallOps labels the session read-only, disables every protected operator control, hides
  the protected logout path, and offers a fresh isolated judge scenario. It does not recover,
  authorize, reset, or mutate the old run. A browser regression removes the token, reloads the page,
  and proves all protected controls remain disabled.
- Verification passed after the fix: tracked Ruff and strict mypy; 494 Python tests including the
  real CockroachDB boundary suite; exactly 5,427/5,427 tracked statements and 1,216/1,216 branches
  covered (100.00%); 10/10 browser tests; and 4/4 native Chromium WebMCP tests. The direct ChatGPT
  protocol remains incomplete and `passed: false` until a successor immutable release completes the
  whole operator, observer, agent-assessment, reviewer, and recurrence journey with captured media.
- `webmcp-rc9` deployed the recovery fix and passed both public Playwright journeys, but the
  credential-free bundle failed the independent verifier with `E_CANONICAL`. The signed bundle was
  canonical; the repository trust registry had gained a single trailing newline during the rc9
  release-ID edit. Because the offline verifier requires exact RFC 8785 bytes, it correctly rejected
  the registry before signature verification. rc9 remains an immutable failed candidate.
- Added a repository-level regression that compares the committed trust registry byte-for-byte to
  its canonical encoding before loading it. The registry is now written without a trailing newline,
  and the dedicated receipt suite passes. `webmcp-rc10` is the successor candidate; no rc9 image,
  source tag, release record, receipt, or failed smoke evidence was overwritten.
- The official ChatGPT Site Tools journey on deployed `webmcp-rc10` completed the protected
  operator approval, labeled sandbox execution, immutable observation, agent assessment,
  independent reviewer certification, and post-review recurrence. ChatGPT correctly rejected the
  incompatible 0.94-similarity known failure, and server state proved the reviewer surface exposed
  zero WebMCP tools throughout certification.
- The same acceptance run falsified one remaining product claim: independent review replaced the
  selected evidence authority with the newly certified local memory, but the bounded remediation
  action remained unchanged. The run and screenshots are preserved as rc10 evidence; rc10 is not
  promoted as the final release and its history is not rewritten.
- The rc11 correction computes the exact pre-review governed counterfactual by excluding only the
  newly reviewed memory from the otherwise identical admissible candidate set. It reports evidence-
  authority change and bounded-action change as separate facts, displays both selected memory IDs,
  and explicitly states when authority changes while the action remains stable. This strengthens
  the causal proof without forcing an artificial action change or weakening any policy boundary.
- A complete official ChatGPT desktop rc11 run then succeeded with GPT-5.6 Terra High in one
  isolated chat/browser context. The agent rejected the 0.94 incompatible failed candidate,
  respected explicit transmission confirmations, staged but did not approve the proposal, assessed
  only immutable observation `6d0fb337…`, left the memory pending, exposed zero agent tools on the
  separate reviewer page, and performed the final recurrence read-only. It selected reviewed local
  evidence `d853baaa…` over exact pre-review authority `00478b4c…`, reported authority change `yes`,
  and separately reported bounded-action change `no`. The contemporaneous observer log is retained
  under `artifacts/manual/rc11/`.
- The same work preserved four real fail-closed observations rather than hiding them: invalid
  tab-local CSRF denied approval, an invalid single-use reviewer handoff denied certification, a new
  browser context without authority synchronized to `SYNC_UNAVAILABLE` with every tool withdrawn,
  and Sol High stopped after security-review timeouts and a stale read-only handle without inferring
  a result. None changed protected state.
- One recovery-label polish defect remains: after reloading a pending-review operator page, the
  handoff issuer may revert to the generic `Activate as reviewer` label even though judge-mode
  behavior still issues a separate single-use reviewer handoff. The authority boundary remains
  server-enforced, but the label should be made state-derived before the final frozen release.
- The successful Terra run is supporting manual evidence, not yet the final ChatGPT gate: it lacks
  an uncut/time-continuous capture and focused Site Tools recent-activity screenshots. The gate stays
  fail-closed until those media artifacts are hashed and validated against rc11 or a successor.
