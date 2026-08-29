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
