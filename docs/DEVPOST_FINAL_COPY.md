# Devpost final copy — The WebMCP Challenge

This is the tracked paste-ready draft. Replace bracketed fields only with evidence from the frozen
deployed release. Nothing in this file has been sent to Devpost.

## Title

RecallOps — The Incident Co-Control Room

## Tagline

The website gives agents tools to investigate and prepare—then withdraws capabilities exactly where
human authority must begin.

## One-line summary

RecallOps demonstrates **Capability Sculpting**: a WebMCP incident room whose authoritative state
continuously changes what its visiting agent can do as control moves between agent, operator,
application, and reviewer.

## Problem

Operational agents often mistake semantic similarity for permission. The closest historical fix may
target the wrong service version, have a known failed outcome, belong to another tenant, or contain
unreviewed experience. Asking an agent to “be careful” does not create an authority boundary, and an
agent that can approve its own proposal or promote its own memories can turn one unverified outcome
into future operational authority.

## Solution

RecallOps is one surgical human-agent workflow. The agent can inspect an incident and at most three
policy-evaluated candidate decisions, stage an exact mitigation proposal, assess a server-created
postcheck, and recall compatible evidence only after certification. It cannot approve the proposal,
apply the simulator action, activate memory, switch role, or override policy. Those protected
transitions remain server-enforced UI actions for distinct operator and reviewer identities.

The application derives its WebMCP registry from authoritative workflow state. When the agent stages
a proposal, `propose_mitigation` is withdrawn. Only after exact human approval, an allowlisted
simulation, and an immutable observation does `record_postcheck_assessment` appear. The agent submits
an attributable assessment, while the backend independently computes the policy verdict. The new
memory remains `PENDING_REVIEW` and retrieval-ineligible until an independent reviewer decides its
disposition.

## Why WebMCP is essential

This is not a chatbot with a static tool list. WebMCP lets the website and visiting agent collaborate
over the same incident state while the website retains control of the capability surface. Native
`document.modelContext.registerTool` registrations are lifecycle-bound with separate
`AbortController`s, reconciled against server epochs, and withdrawn on state changes. Stale callbacks
and guessed protected operations fail server-side even if a client retained old JavaScript state.

The page makes protocol behavior judge-visible through a Capability Inspector and chronological
Activity Rail. Judges can watch authority move without opening DevTools.

## What humans and agents can now do together

The agent rapidly investigates bounded evidence and prepares a precise, digest-bound proposal. The
operator owns authorization and attests only the isolated simulator action. The application owns
measurement and policy evaluation. The agent interprets—but cannot invent—the observation. A
different reviewer governs whether the experience may influence a future incident. The resulting
Authority Receipt links evidence, proposal, approval, observation, assessment, policy verdict, and
review in one independently verifiable chain.

## Four WebMCP tools

1. `inspect_incident` — bounded, read-only incident, workflow, and at most three candidate decisions;
   similarity is separate from eligibility and rejection codes are machine-readable.
2. `propose_mitigation` — proposal-only mutation bound to incident, evidence, idempotency key, and
   action hash; it cannot approve or execute.
3. `record_postcheck_assessment` — appears only after server-created evidence; accepts an observation
   ID plus attributable opinion and can create only a pending-review memory.
4. `recall_reviewed_memory` — read-only compatible recurrence; absent until certified evidence is
   admissible and immediately withdrawn when governance no longer permits reuse.

## Human-only operations

Approve/reject proposal, attest the simulator action, certify/quarantine/reject/revoke memory, role
handoff, and policy override are never WebMCP tools. Separation of duties is enforced by authenticated
subjects and database/API invariants, not by hiding buttons. The claim is deliberately scoped to
WebMCP-mediated authority; RecallOps does not claim to prevent general browser automation or prove
physical-person independence.

## Demonstrated impact

The headline synthetic case uses one identical candidate set. Similarity-only retrieval selects
`mem_47` at `0.94`, even though it is version-incompatible and has a known failed outcome. RecallOps
rejects it before ranking and selects reviewed compatible `mem_12` at `0.81`.

Across the committed 12-case governed benchmark, similarity-only retrieval makes 11 unsafe selections
and leaks two pending memories; RecallOps makes zero unsafe selections, leaks zero pending memories,
and produces all three expected abstentions. These are deterministic synthetic policy-regression
results—not production incident-rate or universal-safety claims.

## Execution and proof

The no-signup judge flow is isolated per run and deterministic. It covers successful recurrence,
observation unavailability, stale tools, replay/idempotency, separate reviewer authority, refresh,
reset, and constrained layout. Candidate-bound assurance currently reports:

- 480 Python tests, including real CockroachDB integration and direct managed-database probes;
- 100.00% Python statement and branch coverage: 5,392/5,392 statements and 1,206/1,206 branches;
- 74.06% mutation score: 1,519/2,051 killed, with zero untested mutations or timeouts;
- 10/10 browser, 2/2 judge-journey, and 4/4 native Chromium WebMCP tests;
- 2/2 public browser tests and a distinct native Chromium 151 live lifecycle proof;
- 15/15 exact independent-verifier outcomes across one valid and 14 materially tampered bundles;
- zero known vulnerabilities in the production and development lock audits.

The receipt signature proves integrity and policy consistency of the supplied authority chain. It does
not prove external truth, physical presence, trusted time, or completeness against a compromised
signer. The product states those limitations next to the proof.

## How Codex was used

OpenAI Codex helped convert the frozen product requirements into transactional and protocol
boundaries, implement the WebMCP lifecycle, red-team authority paths, expand tests, identify real
TOCTOU and production-lock defects, verify coverage and mutations, and generate deterministic
evidence. Claims were accepted only when backed by executable checks or explicit external proof;
the remaining ChatGPT Site Tools observation stays red rather than being inferred from Chromium.

## Links

- Live URL: `https://6n4hjbd6xh.execute-api.us-east-1.amazonaws.com`
- Public repository: `https://github.com/milos-plavsic/recallops`
- Demo video: `[REPLACE_WITH_PUBLIC_YOUTUBE_URL_UNDER_3_MINUTES]`
- Judge guide: `https://github.com/milos-plavsic/recallops/blob/main/docs/JUDGE_GUIDE.md`
- Evidence index: `https://github.com/milos-plavsic/recallops/blob/main/docs/EVIDENCE_INDEX.md`
- Existing-project comparison: `https://github.com/milos-plavsic/recallops/compare/cee362c5ce3cb3bb44c63a4c1ba80b558881d21c...main`

## Exact testing instructions for judges

1. Open the live URL; no signup or credentials are required.
2. Start the deterministic judge scenario for `checkout-latency-42`.
3. In ChatGPT's in-app browser or WebMCP-enabled Chrome, ask the agent to find a safe response and
   stage it without authorizing or executing anything.
4. Confirm `mem_47` is visible but rejected for `SERVICE_VERSION_MISMATCH` and
   `KNOWN_FAILED_OUTCOME`, while `mem_12` remains eligible.
5. After staging, confirm `propose_mitigation` disappears and authority changes to operator.
6. Use the operator controls to approve the exact proposal and attest the labeled simulation.
7. Confirm `record_postcheck_assessment` appears only after the server-created observation; let the
   agent record its assessment and confirm the memory is `PENDING_REVIEW`.
8. Open the purpose-bound reviewer handoff. Confirm the reviewer page exposes zero WebMCP tools and
   activate the memory as the distinct reviewer.
9. Confirm `recall_reviewed_memory` appears only after review; invoke it and verify the compatible
   `checkout-latency-43` selected evidence authority changes, while the UI separately reports whether
   the bounded action changed.
10. Download the Authority Receipt and run the documented network-free verifier if desired.

## Official form answers requiring entrant confirmation

- Submitter Type (28249): `[CONFIRM INDIVIDUAL/TEAM/ORGANIZATION]`
- Country (28250): `[CONFIRM COUNTRY]`
- Organization (28251): `[BLANK UNLESS APPLICABLE]`
- App Status (28252): `Existing`
- Existing update (28253): use the challenge-period extension and provenance comparison above.
- Live URL (28254): `https://6n4hjbd6xh.execute-api.us-east-1.amazonaws.com`
- Testing instructions (28255): use the exact sequence above.
- Public repository (28256): `https://github.com/milos-plavsic/recallops`
- Tested clients (28257): `Chromium 151.0.7922.108 with WebMCP enabled on 2026-08-30; add the direct
  ChatGPT desktop Site Tools result only after the separate manual protocol passes.`
- AI tools (28258): `OpenAI Codex` plus only tools actually used.
- Learning (28259): `[CONFIRM NONE/MODERATE/SIGNIFICANT]`
- Career AI value (28260): `[CONFIRM YES/NO]`

## Closing line

**Similarity can discover experience. Only reviewed evidence earns authority.**
