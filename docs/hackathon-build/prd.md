# RecallOps Product Requirements Document

## Product Summary

RecallOps is an incident co-control room for an SRE, a visiting WebMCP agent, an authenticated
operator, an independent reviewer, and the application policy that mediates between them. It lets
the agent investigate an incident, prepare a bounded mitigation, assess verified evidence, and
recall reviewed experience. It withholds approval, sandbox execution, evidence governance, and
scenario reset from the agent.

The defining product behavior is **Capability Sculpting**: the tools available to the visiting
agent change as authoritative workflow state moves the next decision between agent, operator,
measurement system, and reviewer. Tool withdrawal is visible in the page and enforced even if a
stale or guessed action is attempted.

The public judge journey uses two occurrences of one deterministic checkout-latency incident. The
first produces governed learning. The second proves that the new memory can affect a recommendation
only after verified measurement and independent review.

## Product Principles

1. **Protected authority is withheld, not requested back.** The product does not rely on an agent
   promising not to approve, execute, review, or reset.
2. **Similarity discovers; policy determines eligibility.** A highly similar known failure or
   incompatible memory cannot become a recommendation merely because it ranks well.
3. **Measurements, opinions, and policy decisions remain distinct.** An agent assessment cannot
   manufacture or rewrite an observation, and a reviewer cannot relabel the policy verdict.
4. **Review governs reuse.** No newly observed outcome influences future incidents until an
   independently authorized subject certifies it.
5. **Failure is a product state.** Missing evidence, stale authority, unsupported clients, and
   dependency outages fail closed and explain the legitimate recovery path.
6. **Live proof and assurance are separate 100% gates.** Every material claim must be visible in the
   deployed experience and supported by reproducible, build-bound evidence.
7. **Claims remain inside their evidence boundary.** The demo proves a governed WebMCP workflow in
   an isolated operational sandbox. It does not claim production remediation safety, physical human
   presence, or prevention of general browser automation.

## Target Users And Participants

### Incident commander / operator

An SRE responsible for deciding whether the exact proposed action may proceed in the isolated
checkout sandbox. The operator needs concise incident context, exact proposal binding, a clear next
action, and confidence that approval cannot drift to a different proposal.

### Independent reviewer

A subject distinct from the operator who decides whether completed evidence may influence future
recall. The reviewer needs immutable measurements, separate agent and policy conclusions,
provenance, compatibility context, and clear certify/quarantine/reject choices.

### Visiting WebMCP agent

An agent operating through ChatGPT's in-app browser or native Chrome WebMCP. It needs a small,
state-appropriate tool surface with bounded inputs and outputs, explicit rejection reasons, and
clear denials when the next decision belongs to another authority.

### Hackathon judge

A first-time evaluator who must understand the problem within ten seconds, complete the workflow
without signup or hidden setup, see what is novel, and reproduce the assurance claims if desired.

## Desired User Outcomes

- The operator receives useful agent preparation without surrendering authorization authority.
- The reviewer can govern future reuse without changing what was measured or what policy decided.
- The agent can distinguish similarity from eligibility and can learn only from reviewed evidence.
- The judge can watch capabilities appear and disappear, see a concrete unsafe baseline prevented,
  complete the workflow repeatedly, and connect every scored claim to raw proof.

## Core User Journey

1. The judge opens a stable public entry and starts a fresh isolated scenario without signup.
2. The operator room immediately shows `checkout-latency-42`, the rejected high-similarity known
   failure, current authority owner, currently available agent tools, and a copyable agent prompt.
3. The visiting agent inspects the incident. The shared page shows the resulting bounded evidence
   and activity event.
4. The agent proposes the exact allowlisted mitigation. The proposal capability is withdrawn and
   the page visibly transfers authority to the operator.
5. The operator reviews and approves the exact proposal, then applies it to the isolated checkout
   sandbox through a separate protected action.
6. The product independently observes the sandbox. It displays immutable before/after measurements
   and a versioned policy verdict.
7. Only now can the agent record its bounded assessment. The resulting memory remains pending and
   excluded from recall.
8. The operator opens the workflow-bound reviewer handoff. A distinct reviewer certifies the
   evidence without being able to alter it.
9. The judge opens `checkout-latency-43`. The newly reviewed memory is now eligible and changes the
   recommendation.
10. The judge verifies the authority chain in context or downloads the complete proof bundle for
    offline verification.

## Epics And User Stories

### Epic 1: Immediate judge orientation

#### Story 1.1 — Enter a working scenario

As a judge, I want to enter a working incident room immediately so that I can evaluate the product
before reading setup instructions.

Acceptance criteria:

- The public entry requires no account creation, credentials, terminal command, manual workflow ID,
  or role configuration.
- Starting a scenario opens a fresh isolated workflow and does not expose another judge's state.
- The first meaningful view contains real scenario data rather than an empty dashboard or splash
  page.
- The room identifies the scenario as a synthetic checkout sandbox and does not imply production
  infrastructure access.
- If a new scenario cannot be allocated, the page explains the bounded availability problem and a
  safe retry path; it does not reuse an unrelated active workflow.

#### Story 1.2 — Understand the room in five seconds

As a first-time judge, I want the first viewport to explain the incident and authority model so that
I know what to watch.

Acceptance criteria:

- Without scrolling, the judge can identify what failed, what the agent can do now, who owns the
  next decision, which evidence is trusted, and the next judge action.
- The high-similarity incompatible known failure is visible with its similarity and plain-language
  rejection reasons.
- A copyable prompt tells the visiting agent to investigate and prepare without authorizing or
  executing.
- The Capability Inspector and Activity Rail are visible or immediately reachable without leaving
  the room.
- The operator identity and role remain visible for the duration of the operator journey.

### Epic 2: Bounded agent investigation

#### Story 2.1 — Inspect authoritative incident context

As a visiting agent, I want a bounded incident snapshot so that I can help without receiving
unrestricted logs, credentials, or unrelated tenant data.

Acceptance criteria:

- `inspect_incident` is available for every non-expired workflow state in which inspection is safe.
- Its result identifies the incident, current workflow meaning, current authority owner, and bounded
  operational evidence.
- External incident and historical text is marked untrusted in both the tool result and page.
- The result contains no credentials, session material, unrestricted logs, raw embeddings, or data
  belonging to another tenant or workflow.
- Calling the tool updates the same page the operator sees and appends an attributable activity
  event.

#### Story 2.2 — Distinguish similarity from eligibility

As an operator or judge, I want to see why an attractive memory was rejected so that I can verify
that policy—not similarity alone—controls reuse.

Acceptance criteria:

- Candidate evidence presents similarity separately from eligibility.
- An incompatible, pending, quarantined, rejected, revoked, expired, cross-tenant, or known-failed
  candidate cannot be shown as a recommended remediation.
- Rejection reasons are bounded, machine-readable in proof details, and understandable in the
  default view.
- If no memory is eligible, the product explicitly abstains from a memory-backed recommendation.
- An ineligible memory cannot reappear under a softer label such as advisory or contextual evidence
  to influence the recommendation.

#### Story 2.3 — Resist instructions embedded in evidence

As an operator, I want untrusted incident text to remain data so that it cannot alter the agent's
authority or the workflow.

Acceptance criteria:

- Instructions found in incident or memory text cannot add tools, change roles, advance state,
  override eligibility, or supply protected-action arguments.
- When untrusted instructions are ignored, the product can show a concise explanatory proof event
  without reproducing unsafe or excessive content.
- Bounded evidence remains useful for diagnosis despite its untrusted designation.

### Epic 3: Capability-sculpted proposal

#### Story 3.1 — Prepare one bounded mitigation

As a visiting agent, I want to stage a specific mitigation proposal so that the operator can review
useful prepared work without giving me execution authority.

Acceptance criteria:

- `propose_mitigation` appears only while the incident is accepting a proposal.
- The tool accepts only the bounded service/version/symptom context and rationale needed for the
  allowlisted scenario.
- A successful proposal visibly identifies the exact incident, evidence basis, action, proposal
  digest, expiry status, and current authority owner.
- Repeating the same accepted request cannot create multiple live proposals.
- The agent cannot use proposal text to change the executable action or authorize it.

#### Story 3.2 — Watch capability withdrawal

As a judge, I want to see proposal capability disappear at the protected boundary so that WebMCP's
role in the product is unmistakable.

Acceptance criteria:

- Immediately after proposal creation, `propose_mitigation` moves from **Available to agent** to
  **Withdrawn**.
- The interface states that an unresolved proposal now requires the human operator.
- The authority owner visibly changes from agent to operator.
- A stale callback, repeated invocation, or guessed call after withdrawal is denied and cannot
  create or replace a proposal.
- The denial returns bounded current-state and allowed-next-action guidance without revealing
  sensitive policy or endpoint details.

### Epic 4: Exact operator authorization and sandbox action

#### Story 4.1 — Approve the exact proposal

As an operator, I want to approve the proposal I actually reviewed so that authorization cannot
drift to changed evidence or action.

Acceptance criteria:

- Only the operator sees approval and rejection controls.
- The approval view shows the human-readable action and exact bound incident/proposal identifiers
  before confirmation.
- Approval of an expired, replaced, reset, stale, cross-workflow, or already-resolved proposal is
  denied.
- Approval never automatically applies the sandbox action; the next protected step remains
  visibly distinct.
- Repeated or concurrent approval attempts yield one authoritative result and reconcile all open
  views to it.

#### Story 4.2 — Apply only the approved sandbox action

As an operator, I want to apply the approved mitigation to an isolated operational sandbox so that
the demo produces real state change without production risk.

Acceptance criteria:

- The apply control appears only after valid approval and only to the operator.
- The confirmation states that the target is the isolated checkout sandbox and previews the exact
  approved action.
- The product cannot accept arbitrary commands, user-supplied measurements, or a different action
  under the approved proposal.
- A retry or double-click cannot repeat an already-recorded sandbox mutation.
- The activity rail distinguishes agent proposal, operator approval, sandbox application, and
  system observation as different actors and events.

### Epic 5: Verified postcheck and attributable assessment

#### Story 5.1 — Observe outcome independently

As an operator or judge, I want the product to measure the sandbox after action so that an agent
cannot invent success.

Acceptance criteria:

- The page shows bounded before/after telemetry, observation identity, collection status, and
  policy verdict after measurement succeeds.
- Measurements are presented as immutable evidence bound to the current workflow, proposal, and
  sandbox action.
- The policy verdict is visibly identified as independent of the later agent assessment.
- No assessment capability or memory exists before a valid observation exists.
- The product never labels operator attestation or agent-provided numbers as verified telemetry.

#### Story 5.2 — Fail closed when observation is unavailable

As an operator, I want missing measurement to stop the learning workflow so that absence of evidence
cannot become evidence of success.

Acceptance criteria:

- Observation failure produces a clear `POSTCHECK_UNAVAILABLE` product state.
- `record_postcheck_assessment` remains absent, and no memory is created.
- Only the operator sees retry or reset recovery actions.
- Observation retry does not repeat the completed sandbox mutation.
- **Verify evidence** for the failure shows that no observation, assessment, or memory write was
  accepted.

#### Story 5.3 — Record agent opinion without rewriting policy

As a visiting agent, I want to interpret a verified observation so that my reasoning is retained as
an attributable opinion rather than treated as measurement truth.

Acceptance criteria:

- `record_postcheck_assessment` appears only after the bound verified observation is ready.
- The agent supplies only a bounded classification and concise rationale for that observation.
- The resulting view shows immutable observation, agent assessment, and policy verdict as three
  separate layers.
- Agreement and disagreement are both preserved; the agent cannot modify the policy verdict.
- A stale, mismatched, cross-workflow, repeated, or invalid assessment creates no additional memory.
- A valid assessment creates at most one memory in `PENDING_REVIEW`, visibly excluded from recall.

### Epic 6: Independent evidence governance

#### Story 6.1 — Handoff to a distinct reviewer

As an operator, I want a safe reviewer handoff so that evidence cannot be activated by the same
authority that operated the incident.

Acceptance criteria:

- The operator can open or copy a short-lived reviewer link bound to only the current workflow.
- The reviewer page shows a persistent reviewer identity/role banner and no operator controls.
- The reviewer subject differs from the operator and assessment submitter for that evidence.
- Expired or invalid reviewer links reveal no review data and offer a safe recovery path.
- The product claims authenticated subject separation, not proof that two physical people used the
  sessions.

#### Story 6.2 — Review evidence without rewriting it

As a reviewer, I want to inspect and disposition the complete evidence package so that future recall
is governed without changing history.

Acceptance criteria:

- The review view shows compatibility context, immutable measurements, agent assessment, policy
  verdict, agreement status, provenance, and exact memory digest.
- Observation, assessment, and policy fields are read-only.
- **Certify** makes the policy-defined positive or negative evidence admissible.
- **Quarantine** retains the evidence for investigation while keeping it non-retrievable.
- **Reject** permanently excludes that evidence version while retaining its audit record.
- Each decision requires a bounded reason code and concise reviewer note.
- The reviewer cannot relabel policy-classified failure as success or vice versa.

#### Story 6.3 — Revoke or expire previously reviewed evidence

As a reviewer, I want unsafe or obsolete evidence removed from future recall without erasing history.

Acceptance criteria:

- An authorized reviewer can revoke certified evidence through a protected secondary flow.
- Revocation immediately prevents future recall but does not alter earlier decisions or receipts.
- Revocation appends a new attributable event with reason and effective status.
- Expired or superseded evidence remains historically inspectable and is clearly non-retrievable.
- The operator or assessment submitter cannot review or revoke their own evidence.

### Epic 7: Review-gated recurrence

#### Story 7.1 — Keep pending evidence out of retrieval

As an operator, I want unreviewed outcomes excluded so that the system cannot learn authority from
its own unverified experience.

Acceptance criteria:

- Before reviewer certification, the pending memory is absent from agent recall results and marked
  excluded in the page.
- Refresh, duplicate tabs, stale tool references, or direct guessed requests cannot retrieve it.
- Quarantined, rejected, revoked, expired, incompatible, and cross-tenant memories are also absent.
- The activity rail identifies review—not agent assessment—as the event that changes admissibility.

#### Story 7.2 — Reuse certified evidence on a compatible recurrence

As an incident commander, I want reviewed evidence to improve a later compatible incident so that
the governance workflow produces operational value.

Acceptance criteria:

- `checkout-latency-43` is visibly a later compatible occurrence, not a reset of the first incident.
- `recall_reviewed_memory` appears only after compatible reviewed evidence exists.
- The newly certified successful memory becomes eligible and changes the recommendation relative to
  the pre-review state.
- The recall result exposes why the evidence is compatible and reviewed.
- Certified negative evidence appears only as a warning or ranking penalty and is never returned as
  a recommended remediation.

### Epic 8: Visible authority and evidence proof

#### Story 8.1 — Understand current capability and authority

As any participant, I want a live Capability Inspector so that I can tell what the agent may do and
who owns the next transition.

Acceptance criteria:

- The inspector lists currently discoverable tools, withdrawn tools with reasons, and protected
  operations that are never agent tools.
- It identifies current workflow meaning, authority owner, and synchronization status.
- It updates after agent, operator, system, and reviewer events without requiring a page reload.
- Its display is consistent with the authoritative result after refresh or concurrent changes.
- The inspector never presents browser visibility alone as proof of server authorization.

#### Story 8.2 — Follow the chronological authority handoff

As a judge, I want a chronological Activity Rail so that I can understand the causal workflow
without opening developer tools.

Acceptance criteria:

- Events identify actor class, action, outcome, readable time, and exact UTC time on demand.
- Agent, operator, reviewer, system, denial, and policy events have redundant text and visual labels.
- Replayed or denied attempts are distinguishable from committed state transitions.
- Every material committed or denied event has an expandable **Verify evidence** action.
- The rail preserves chronology through refresh and does not fabricate missing historical events.

#### Story 8.3 — Verify the authority receipt

As a security-minded judge, I want a verifiable record of the workflow so that I can evaluate the
authority claims independently.

Acceptance criteria:

- The room renders a compact chain from evidence through proposal, approval, execution,
  observation, assessment, policy, and review.
- Each chain node opens a human-readable binding before optional raw technical details.
- The proof bundle is downloadable without credentials and contains the signed manifest, complete
  ordered event chain, public key, checksums, evaluation material, and verifier instructions.
- The page states exactly what the receipt proves and what it does not prove.
- A deterministic offline verification path accepts the valid bundle and rejects published tampered
  vectors.

### Epic 9: Recovery, replay, and degraded operation

#### Story 9.1 — Reconcile stale or concurrent views

As a participant using multiple tabs or refreshing mid-flow, I want the page to recover to committed
state so that stale UI cannot create conflicting authority.

Acceptance criteria:

- Refresh at every workflow stage restores authoritative state and the correct capability set.
- Simultaneous valid attempts result in one committed outcome and clear reconciliation elsewhere.
- Repeated proposals, approvals, sandbox applications, assessments, reviews, revocations, and resets
  do not produce duplicate side effects.
- Reset, expiry, proposal replacement, or state advancement invalidates prior action references.
- The product never silently transfers approval intent from an expired or replaced object.

#### Story 9.2 — Remain safe when dependencies fail

As a judge, I want understandable degraded behavior so that an outage cannot masquerade as success.

Acceptance criteria:

- Before authoritative state loads, no authority-bearing control is enabled.
- Synchronization failure produces a read-only degraded state with retry and stale-data labeling.
- Database, measurement, signing, or evaluation failure identifies the unavailable proof component
  and cannot mark the corresponding completion gate complete.
- Error messages are actionable but do not reveal secrets, internal queries, stack traces, or
  sensitive policy details.
- Recovery never substitutes a client-side or cached mutation for an unavailable server action.

#### Story 9.3 — Handle unsupported WebMCP honestly

As a judge using an unsupported client, I want a precise explanation so that I do not mistake a
compatibility issue for a working WebMCP integration.

Acceptance criteria:

- The room remains inspectable and labels WebMCP support status clearly.
- No fake or simulated agent tool calls replace missing WebMCP capability.
- Protected UI actions retain normal authorization and cannot be used as evidence of an agent call.
- The judge guide identifies the two tested clients and the supported recovery path.

### Epic 10: Accessible cross-client experience

#### Story 10.1 — Complete the flow with assistive technology

As a keyboard or screen-reader user, I want the full judge journey to remain operable and
understandable.

Acceptance criteria:

- Every control, evidence drawer, role handoff, and recovery path is keyboard operable.
- Focus order follows the visible workflow; focus moves automatically only when needed to prevent
  disorientation after a state transition.
- Important state changes announce concise summaries without flooding assistive technology.
- Meaning never depends only on color, animation, position, or an unlabeled icon.
- Reduced-motion preferences preserve every state change and proof cue without required animation.

#### Story 10.2 — Work in both judge clients

As a judge, I want the same coherent experience in ChatGPT's in-app browser and native Chrome
WebMCP.

Acceptance criteria:

- Material incident, capability, activity, control, and evidence content fits the constrained
  in-app browser without horizontal scrolling.
- Panels stack predictably while preserving incident → capability → activity comprehension.
- Tool names, schemas, availability, results, and state transitions are behaviorally consistent in
  both tested clients.
- Client-specific limitations are disclosed precisely and do not change security claims.
- The final deployed release is exercised end to end in both clients during acceptance.

### Epic 11: Dual-gate proof and impact

#### Story 11.1 — Compare governed retrieval with a fair baseline

As a judge, I want a reproducible counterfactual so that the claimed prevented harm is concrete.

Acceptance criteria:

- Similarity-only and RecallOps evaluation use the same versioned query, candidate pool, similarity
  values, and deterministic tie-breaking.
- The baseline algorithm and every synthetic case are published.
- The headline case shows similarity-only selecting the incompatible known failure while RecallOps
  rejects it before ranking.
- Results report counts with denominators for unsafe top selections, pending-memory leakage,
  abstention, incompatibility rejection, and recommendation changes after review.
- Results are labeled synthetic and do not claim unmeasured production incidents prevented or time
  saved.

#### Story 11.2 — Trace every scored claim

As a judge or evaluator, I want each claim tied to live and reproducible evidence so that neither
surface depends on trust in the submission text.

Acceptance criteria:

- Every scored claim has a stable ID linked to its rubric category, live page/state, workflow event,
  automated test, raw evaluation case, and receipt field where applicable.
- One evidence index offers **View live proof**, **View raw evidence**, and **Reproduce** paths.
- The live page and artifacts identify the same source revision, deployed build, policy version,
  evaluation version, and receipt-key thumbprint.
- All evaluation cases and failures are published; a failing invariant keeps readiness incomplete.
- Any deployed-build change invalidates old completion status until both gates are regenerated.

#### Story 11.3 — See independent completion gates

As the project team or judge, I want live proof and assurance tracked separately so that strength in
one cannot hide weakness in the other.

Acceptance criteria:

- The product displays distinct **Live proof** and **Assurance** readiness states.
- **Live proof** completes only after the deployed two-occurrence journey and required client checks
  pass for the identified build.
- **Assurance** completes only after invariant evaluations, proof-bundle generation, and offline
  receipt verification pass for the same build.
- Overall submission readiness is complete only when both independent gates are complete.
- The UI never hardcodes a green state or preserves one after its underlying evidence becomes stale.

### Epic 12: Reliable public judging

#### Story 12.1 — Keep concurrent judge runs isolated

As a judge, I want my scenario unaffected by other visitors so that the live product behaves
deterministically during judging.

Acceptance criteria:

- Every run receives a bounded isolated workflow and sandbox namespace.
- Another visitor cannot view, advance, review, revoke, or reset that run.
- Scenario quotas, expiry, and payload limits control public abuse without weakening role or state
  authorization.
- Expiration preserves no stale authority and provides a clear way to start a new scenario.
- Public logs and proof bundles contain no bootstrap codes, session material, CSRF values, or
  sensitive headers.

#### Story 12.2 — Keep release proof coherent

As a project owner, I want one frozen release candidate across all submission surfaces so that judges
do not encounter contradictory evidence.

Acceptance criteria:

- Live deployment, final video, repository revision, proof bundle, benchmark results, public key,
  judge guide, and Devpost text identify the same release candidate.
- A concise judge guide provides entry, reviewer handoff, duration, tested clients, reset/recovery,
  simulation boundary, evidence index, and fallback video.
- Continuous checks cover the complete journey, reset, artifact download, and both target clients
  throughout the judging window.
- Any post-freeze change reopens both readiness gates and requires regenerated evidence.
- The fallback video demonstrates the frozen live release and is never presented as a substitute
  for the required accessible live app.

## Edge Cases And Required Responses

| Situation | Required user-visible behavior | Forbidden behavior |
| --- | --- | --- |
| No eligible memory | Explicit abstention plus bounded rejection reasons | Recommending or softly relabeling ineligible evidence |
| Prompt-like text in evidence | Mark untrusted and ignore authority-changing instructions | Treating content as policy or protected action input |
| Proposal expires after display | Disable action, refresh state, require fresh proposal | Applying prior approval to a new proposal |
| Two tabs approve simultaneously | One committed outcome; other tab reconciles | Duplicate approval effects or conflicting state |
| Sandbox request is repeated | Return recorded authoritative result | Repeat the mutation |
| Observation unavailable | Show fail-closed state, no assess tool, no memory | Accept agent or operator measurements as a substitute |
| Agent assessment disagrees | Preserve both assessment and policy verdict | Overwrite, average, or hide disagreement |
| Same subject attempts review | Explicit denial and distinct-reviewer requirement | Self-certification |
| Reviewer certifies a failure | Activate only as negative evidence | Relabel it as successful remediation |
| Certified memory is revoked | Stop future recall; append revocation event | Rewrite or delete historical receipt |
| Workflow reset | New workflow identity and invalidated old actions | Reusing old proposal, observation, or review authority |
| Unsupported browser | Honest compatibility state | Simulated WebMCP success |
| Authoritative service unavailable | Read-only degraded state | Cached or optimistic mutation |
| Judge session expires | Stable-entry recovery to a fresh run | Restoring expired authority |
| Concurrent judges | Isolated workflow and sandbox state | Shared mutable demo state |
| Build changes after evidence | Reopen both completion gates | Reusing stale green readiness status |

## Cross-Cutting Acceptance Standards

### Security and authority

- Protected operations are absent from the agent tool surface and denied when attempted through the
  agent channel.
- Every authority-bearing action is bound to authenticated subject, role, workflow, tenant, current
  state, current version/epoch, exact target object, and replay protection.
- Distinct reviewer-subject enforcement applies to certification, quarantine, rejection, and
  revocation.
- Cross-tenant, cross-workflow, stale, mismatched, expired, replayed, or unauthorized requests fail
  closed without partial success.

### Functional coherence

- The judge can complete the primary journey without documentation while documentation remains
  available for verification and recovery.
- Every displayed state has one clear authority owner and legitimate next step or terminal meaning.
- Page, agent tool results, activity history, review surface, and proof artifacts agree on the
  authoritative workflow outcome.
- Reset and refresh are safe at every stage.

### Accessibility and comprehension

- Plain-language meaning precedes protocol, cryptographic, and database terminology.
- Every state, role, outcome, and disabled action has a textual explanation.
- The complete journey satisfies keyboard, screen-reader, contrast, reduced-motion, responsive, and
  focus-management acceptance checks.

### Evidence quality

- Published results are generated from committed cases and commands, not manually entered claims.
- Raw results, failures, environment versions, browser versions, dates, data/policy versions, source
  revision, and generation instructions accompany summaries.
- The receipt verifier publishes positive and materially tampered cases.
- Proof wording states limitations as prominently as conclusions.

## What We Are Building

- The deterministic two-occurrence checkout judge journey.
- Exactly four state-aware WebMCP tools and all protected human/system transitions needed by that
  journey.
- Separate operator and reviewer experiences with safe anonymous judge bootstrap and run isolation.
- Real allowlisted server-side sandbox mutation and independently measured telemetry.
- Disagreement-preserving evidence, review-gated positive/negative recall, quarantine, rejection,
  revocation, expiry, and supersession behavior.
- Capability Inspector, Activity Rail, progressive evidence drawers, authority-chain receipt view,
  and dual-gate readiness status.
- Complete accessibility, refresh, concurrency, degraded-state, and target-client behavior.
- Versioned impact benchmark, claim registry, downloadable proof bundle, offline verifier, judge
  guide, and frozen-release evidence.

## What We Would Add With More Time

These items are deliberately excluded from the hackathon release because they dilute the scored
causal story or require a different risk claim:

- Production infrastructure adapters, real production credentials, or autonomous production
  remediation.
- Additional services, incident types, organizations, user profiles, or generalized workflow
  authoring.
- Enterprise identity-provider onboarding beyond the isolated judge identity model.
- Multi-region signing, external trusted timestamping, transparency-log anchoring, post-quantum
  hybrid signatures, or formal verification.
- General browser-automation controls or physical-human-presence verification.
- Open-ended agent tools, arbitrary shell execution, unrestricted log access, or policy override.
- Additional demo narratives, chat surfaces, dashboards, and decorative visual scope.

## Submission Proof Points

### WebMCP Leverage

- The visiting agent acts on the same incident state shown to the human.
- Tool discovery changes with authoritative state through visible registration and withdrawal.
- Correct annotations, bounded schemas/results, untrusted content treatment, cancellation, and stale
  invocation denial are exercised in both target clients.
- Protected authority is genuinely absent from the WebMCP surface and rejected by the server.

### Execution

- A judge enters without signup, understands the product immediately, completes a polished journey,
  and can reset or recover without hidden setup.
- The live path uses real isolated server-side state change and independent measurement.
- Concurrency, refresh, role separation, accessibility, degraded states, and cross-client behavior
  are part of the product rather than repository-only claims.

### Potential Impact

- A fair published baseline selects the high-similarity incompatible known failure; RecallOps
  rejects it before ranking.
- Pending evidence never leaks into recall, and a compatible recurrence changes only after review.
- Exact synthetic benchmark counts and denominators demonstrate prevented unsafe selections,
  correct abstention, governed reuse, and zero accepted invariant violations across committed cases.

### Creativity And Ambition

- Capability Sculpting makes the website an active authority governor rather than a static tool
  catalog or chat wrapper.
- Visible authority handoff, three-layer evidence, independent review, governed recurrence, and a
  verifiable receipt form one connected causal loop.
- The memorable product moment is the proposal tool disappearing precisely when human authority
  begins.

## Demo Acceptance

- The working product appears within the first 10–15 seconds.
- The final edit runs approximately 2:40–2:50 and remains below the three-minute limit.
- The video shows the rejected unsafe shortcut, agent proposal, visible capability withdrawal,
  operator action, independent observation, agent assessment, reviewer certification, compatible
  recurrence, and one compact fail-closed proof.
- The video stays in the product; source code and extended test output remain linked evidence.
- The final spoken line is: **“Similarity can discover experience. Only reviewed evidence earns
  authority.”**

