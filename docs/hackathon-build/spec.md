# RecallOps Technical Specification

## Overview

This specification is the technical translation of [`prd.md`](prd.md). It is intentionally
conservative in product scope and exhaustive in boundaries. A requirement is implemented only when
the deployed behavior and its build-bound assurance evidence both pass. The implementation must not
substitute a weaker mechanism because it is easier to demo, and it must not add product surface that
is absent from the PRD.

RecallOps remains a modular monolith:

- one Python/FastAPI application process for HTTP APIs and static assets;
- one browser-native JavaScript control room using the imperative WebMCP API;
- one CockroachDB system of record for incidents, memories, authority state, sessions, and ledger;
- one isolated in-process checkout sandbox and deterministic observation provider;
- one existing outbox worker for S3 evidence export and receipt signing work;
- one AWS deployment boundary using HTTP API, private VPC integration, internal ALB, and ECS
  Fargate;
- one offline Node.js verifier using only built-in runtime modules plus repository code.

The visiting agent comes from ChatGPT's built-in browser or the tested Chrome WebMCP client. The
live judge path does not depend on an embedded model, model API, external production account, or
arbitrary command executor.

## Normative Language And Translation Rules

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative in this document.

1. Every PRD story maps to at least one owning component, interface, persisted invariant, and
   verification case in the traceability matrix.
2. Browser tool presence is a user-agent capability signal, not authorization. Server validation is
   mandatory for every state-changing call.
3. Product-visible claims use only evidence generated for the exact deployed source revision and
   image digest.
4. Existing legacy behavior may remain outside judge mode, but judge mode MUST return `410 Gone`
   for any legacy endpoint that bypasses verified evidence or the protected authority flow.
5. No new WebMCP tools may be added without first changing the frozen PRD and repeating scope
   review. The tool count is exactly four.
6. The deterministic sandbox is the only execution target. Production execution interfaces remain
   disconnected and are not implemented by this build.

## Existing Baseline And Required Delta

### Reuse without redesign

- `FastAPI`, Pydantic domain models, strict request validation, and structured errors.
- CockroachDB with serializable transactions and bounded whole-transaction retry.
- Composite tenant foreign keys and separate migration/API/outbox database roles.
- Eight-state WebMCP workflow, monotonic epoch, capability manifest, and CAS transitions.
- Judge-session cookie, CSRF, exact-Origin, role, channel, and tenant enforcement.
- Exact proposal-digest approval and one allowlisted checkout sandbox mutation.
- Immutable execution, observation, policy verdict, and agent assessment records.
- Imperative WebMCP registration with lifecycle-bound `AbortController` objects.
- Playwright, native Chromium WebMCP tests, strict mypy/Ruff, branch-aware coverage, and real
  CockroachDB verification.

### Required PRD delta

- Create a fresh isolated judge run before proposal rather than creating the incident inside the
  proposal tool.
- Bind operator and reviewer sessions to that run and tenant; generate a short-lived reviewer
  handoff only for the pending memory.
- Implement the fourth tool, `recall_reviewed_memory`, as a read-only recurrence query.
- Complete certify/quarantine/reject/revoke/expiry/supersession semantics.
- Add the authoritative event ledger, receipt signer, bundle exporter, offline verifier, and
  tampered vectors.
- Add the claim registry, fair counterfactual benchmark, dual readiness gates, and release binding.
- Complete the Capability Inspector, Activity Rail, evidence drawers, accessible reviewer surface,
  concurrent-run isolation, and both-client acceptance evidence.
- Deploy judge-session mode without Cognito login friction and preserve the stable public entry.

## Stack

| Layer | Choice | Boundary and rationale |
| --- | --- | --- |
| Runtime | Python 3.12 | Preserve current typed runtime and pinned build; no language rewrite. |
| HTTP application | FastAPI + Uvicorn | Existing API/static delivery and dependency injection; one process boundary. |
| Validation | Pydantic v2 | Reject unknown or out-of-range inputs before domain logic. |
| Database | CockroachDB + psycopg 3 pool | One serializable source of truth; retry complete authority transactions. |
| Browser | Standards-based HTML/CSS/JavaScript | No SPA runtime; progressive enhancement and smallest failure surface. |
| Agent interface | Imperative `document.modelContext.registerTool()` | Dynamic registration and cancellation are core product behavior. |
| Sandbox | Deterministic in-process checkout simulator | Real server-side state mutation through one exact allowlist, no shell. |
| Evidence storage | Versioned private S3 bucket | Durable downloadable bundles; signatures provide integrity, not availability. |
| Receipt signing | AWS KMS Ed25519 | Non-exportable managed private key and offline-verifiable public key. |
| Deployment | AWS HTTP API → VPC Link → internal ALB → ECS Fargate | Reuse deployed boundary, throttling, immutable image, and private origin. |
| Browser tests | Playwright + native Chrome WebMCP + axe-core | Functional, lifecycle, responsive, and accessibility evidence. |
| Offline verifier | Node.js ESM with built-in `crypto`, `fs`, and `assert` | One command after repository checkout; no runtime network dependency. |

## Current Primary Documentation

- [WebMCP Community Group draft](https://webmachinelearning.github.io/webmcp/)
- [Chrome WebMCP overview](https://developer.chrome.com/docs/ai/webmcp)
- [Chrome WebMCP tool security](https://developer.chrome.com/docs/ai/webmcp/secure-tools)
- [Chrome WebMCP evaluations](https://developer.chrome.com/docs/ai/webmcp/evals)
- [Chrome DevTools WebMCP panel](https://developer.chrome.com/docs/devtools/application/webmcp)
- [OpenAI site tools in ChatGPT](https://help.openai.com/en/articles/20001423-using-site-tools-in-the-chatgpt-desktop-app)
- [CockroachDB transaction fundamentals](https://www.cockroachlabs.com/docs/stable/developer-basics.html)
- [AWS KMS key specifications](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html)
- [AWS KMS `Sign`](https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html)
- [AWS KMS `GetPublicKey`](https://docs.aws.amazon.com/kms/latest/APIReference/API_GetPublicKey.html)
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html)
- [RFC 9864 fully specified JOSE algorithms](https://www.rfc-editor.org/rfc/rfc9864.html)
- [RFC 8037 Ed25519 JWK representation](https://www.rfc-editor.org/rfc/rfc8037.html)
- [RFC 7638 JWK Thumbprints](https://www.rfc-editor.org/rfc/rfc7638.html)

Version-sensitive WebMCP and client behavior MUST be rechecked against these primary sources before
the release freeze. The final evidence records the browser build and spec revision/commit used.

## Architecture

### Trust boundaries

1. **Untrusted incident/history text:** may influence bounded analysis, never authority, role,
   capability, or executable parameters.
2. **Browser/WebMCP boundary:** the page exposes four tools; browser registration can become stale
   and therefore never authorizes a server mutation.
3. **Session boundary:** role-specific opaque cookies select operator or reviewer authority; raw
   session values are stored only as hashes.
4. **HTTP boundary:** exact Origin, content type, size, schema, role, channel, tenant/run binding,
   CSRF where applicable, and rate limits are enforced before domain mutation.
5. **Transaction boundary:** domain write, workflow transition, epoch increment, and accepted
   authority event commit together under serializable isolation.
6. **Sandbox boundary:** action text is never executed; one server constant maps one action ID and
   digest to deterministic state mutation.
7. **Observer boundary:** the observer resolves an immutable execution and creates measurements;
   agent/operator payloads cannot supply telemetry.
8. **Review boundary:** reviewer disposition changes admissibility only, not observation,
   assessment, policy verdict, or historical events.
9. **Signing boundary:** KMS authenticates the canonical manifest and event-chain digest; it does
   not establish external truth, human physical presence, or completeness against a compromised
   signer.
10. **Deployment boundary:** only the digest-pinned container and exact release evidence may claim
    readiness.
11. **Activity boundary:** persisted tool invocations and browser lifecycle observations explain
    the judge-visible chronology but never authorize a transition, enter the authority hash chain,
    or strengthen a receipt claim.

### Component topology

The browser loads same-origin static assets and exchanges a judge bootstrap for role-specific,
run-bound sessions. Browser WebMCP callbacks invoke same-origin HTTP endpoints. FastAPI derives
identity and run context from opaque sessions, validates state through the workflow policy, and
executes domain changes through one transaction coordinator. CockroachDB is authoritative. The
outbox worker exports finalized evidence and signs compact receipts with KMS. S3 holds versioned
bundles. The browser displays only verified release/readiness records matching its own build.

No browser-to-database, browser-to-KMS, browser-to-S3-write, agent-to-sandbox, or reviewer-to-policy-
mutation path exists.

## Authoritative Workflow And Capability Policy

### States

| State | Authority owner | Discoverable tools | Allowed next transition |
| --- | --- | --- | --- |
| `INVESTIGATING` | `AGENT` | `inspect_incident`, `propose_mitigation` | Agent stages exact proposal |
| `AWAITING_OPERATOR_APPROVAL` | `HUMAN_OPERATOR` | `inspect_incident` | Operator approves/rejects |
| `APPROVED_AWAITING_EXECUTION` | `HUMAN_OPERATOR` | `inspect_incident` | Operator applies sandbox action |
| `OBSERVING_POSTCHECK` | `SYSTEM` | `inspect_incident` | Observer records result/unavailable |
| `POSTCHECK_READY` | `AGENT` | `inspect_incident`, `record_postcheck_assessment` | Agent records assessment |
| `POSTCHECK_UNAVAILABLE` | `HUMAN_OPERATOR` | `inspect_incident` | Operator retries/reset |
| `PENDING_REVIEW` | `HUMAN_REVIEWER` | `inspect_incident` | Reviewer dispositions evidence |
| `REVIEWED` | `GOVERNED_MEMORY` | `inspect_incident`; conditionally `recall_reviewed_memory` | Read-only recurrence or protected revocation |

`recall_reviewed_memory` is present in `REVIEWED` only when the source memory is active/certified,
unexpired, unsuperseded, compatible with the fixed recurrence, and belongs to the run tenant.
Quarantine or rejection still completes the workflow but exposes only `inspect_incident`.
The reviewer page loads no WebMCP registry script and registers zero tools; its controls are
ordinary protected reviewer UI operations only.

### Legal transitions

- `INVESTIGATING → AWAITING_OPERATOR_APPROVAL`: WebMCP agent proposal only.
- `AWAITING_OPERATOR_APPROVAL → APPROVED_AWAITING_EXECUTION`: operator approval only.
- `AWAITING_OPERATOR_APPROVAL → INVESTIGATING`: operator rejection, proposal expiry, or safe
  replacement; old proposal binding becomes unusable.
- `APPROVED_AWAITING_EXECUTION → OBSERVING_POSTCHECK`: operator sandbox application only.
- `OBSERVING_POSTCHECK → POSTCHECK_READY`: system observation and verdict commit.
- `OBSERVING_POSTCHECK → POSTCHECK_UNAVAILABLE`: system records collection failure with no evidence
  object.
- `POSTCHECK_UNAVAILABLE → OBSERVING_POSTCHECK`: operator retry using the existing execution.
- `POSTCHECK_READY → PENDING_REVIEW`: WebMCP assessment and pending memory commit.
- `PENDING_REVIEW → REVIEWED`: distinct reviewer certify/quarantine/reject.
- Any active state → inactive generation: operator demo reset; no old transition may target the new
  generation.

Revocation, expiry, and supersession are memory-admissibility events after `REVIEWED`; they do not
rewrite the completed workflow or earlier receipt. Revocation produces a successor receipt.

### Transition guard

Every transition MUST atomically validate:

- authenticated session hash and expiry;
- run ID and derived tenant;
- actor subject and exact required role;
- request channel (`webmcp`, `ui`, or `system`), never accepted from agent arguments;
- active run generation, workflow ID, expected state, and expected epoch;
- exact proposal, execution, observation, memory, and/or prior-event digest required by the step;
- idempotency key bound to canonical request digest;
- separation of duties for every review action;
- legal target state and capability-policy version.

The server returns an idempotent recorded result when the key and complete binding match. Reusing a
key with different data returns conflict. A serialization retry reruns the whole closure with no
external side effect inside it.

## WebMCP Tool Contracts

### Common registration contract

- Use the imperative `document.modelContext.registerTool(tool, {signal})` API only.
- Feature-detect `document.modelContext?.registerTool`; install no polyfill in production.
- One registration `AbortController` owns each active registration. Aborting its signal withdraws
  the tool. Because permitted client builds may differ on whether withdrawal also interrupts an
  execution that already began, RecallOps MUST NOT depend on either outcome or treat withdrawal as
  transactional cancellation/rollback.
- Every callback has the current draft signature `async execute(inputObject, options)`. It passes
  `options.signal` to `fetch` and stops nonessential follow-up work when that invocation signal is
  aborted. The callback never reads a non-standard `agent.signal` property.
- Registration and invocation controllers MUST be separate objects. Server idempotency and state/
  epoch guards, not cancellation, determine whether a state-changing request committed.
- Tool names and schemas are immutable for the page/release. The reconciler never rapidly replaces
  a withdrawn tool with a different schema under the same name; `inspect_incident` remains
  registered across safe states instead of being churned on every transition.
- Reconciliation is generation-guarded: late registration promises from an old manifest are
  aborted and cannot enter the active registry map.
- The page omits `exposedTo`; exposure remains the browser default. Response headers set
  `Permissions-Policy: tools=(self)` and `Origin-Agent-Cluster: ?1`.
- Tool names/parameter names remain under 30 characters, descriptions under 500 characters,
  parameter descriptions under 150 characters, and each text result under 1,500 characters.
- Every schema sets `additionalProperties: false`, bounds every string/array, and has no free-form
  tenant, actor, run, channel, endpoint, command, metric, policy, or authority fields.
- After an aborted mutation callback, the client immediately reconciles authoritative state before
  enabling any action; it never claims the request was rolled back merely because `fetch` aborted.
- Tool results are `{content:[{type:"text",text:<bounded JSON string>}]}` and contain no secrets.

### `inspect_incident`

Annotation: `readOnlyHint: true`, `untrustedContentHint: true`.

Input:

```json
{"type":"object","properties":{},"additionalProperties":false}
```

Output fields: `incident`, `workflow`, `authority_owner`, `available_tools`, up to three candidate
summaries, eligibility/rejection codes, trusted-field labels, untrusted-field labels, and build/
policy versions. It MUST NOT return raw logs, embeddings, credentials, session/run secrets, or
cross-tenant identifiers.

Implements PRD: 1.2, 2.1, 2.2, 2.3, 8.1, 9.3.

### `propose_mitigation`

Annotation: `readOnlyHint: false`, `untrustedContentHint: true`.

Input:

```json
{
  "type": "object",
  "properties": {
    "service": {"type":"string","minLength":1,"maxLength":80},
    "service_version": {"type":"string","minLength":1,"maxLength":80},
    "symptom": {"type":"string","minLength":3,"maxLength":500},
    "rationale": {"type":"string","minLength":3,"maxLength":500}
  },
  "required": ["service","service_version","symptom"],
  "additionalProperties": false
}
```

The server compares service/version/symptom to the stored run incident; mismatch fails. It derives
tenant, run, workflow, exact allowlisted action, proposal digest, expiry, and idempotency context.
The optional rationale is untrusted explanatory text and cannot alter the action.

Output fields: `proposal_id`, `proposal_digest`, bounded diagnosis/rationale, exact action display
name, risk class, expiry, `requires_human_approval: true`, next authority owner, and new epoch. It
contains no executable command string.

Implements PRD: 3.1, 3.2, 4.1, 9.1.

### `record_postcheck_assessment`

Annotation: `readOnlyHint: false`, `untrustedContentHint: true` because the result includes
agent-authored rationale.

Input:

```json
{
  "type": "object",
  "properties": {
    "observation_id": {"type":"string","format":"uuid"},
    "classification": {"type":"string","enum":["recovered","not_recovered","inconclusive"]},
    "rationale": {"type":"string","minLength":3,"maxLength":1000}
  },
  "required": ["observation_id","classification","rationale"],
  "additionalProperties": false
}
```

The server resolves the observation from the current run and checks exact observation/workflow/
digest binding. The agent cannot submit metrics, verdict, outcome score, memory state, or reviewer.

Output fields: bounded assessment, independent policy verdict, agreement flag, pending memory ID/
digest/state, `retrievable: false`, and reviewer requirement.

Implements PRD: 5.1, 5.2, 5.3, 7.1.

### `recall_reviewed_memory`

Annotation: `readOnlyHint: true`, `untrustedContentHint: true`.

Input:

```json
{"type":"object","properties":{},"additionalProperties":false}
```

This tool evaluates the immutable `checkout-latency-43` recurrence fixture against current active
reviewed memory. It MUST NOT create or mutate an incident, memory, policy, or workflow. Incidental
audit logging does not affect recommendation state.

Output fields: recurrence incident summary, up to three eligible/rejected candidates, selected
reviewed memory and compatibility/review reasons, baseline recommendation, governed recommendation,
and policy version. Certified negative evidence may only appear as a rejection/warning penalty.

Implements PRD: 6.2, 6.3, 7.1, 7.2, 11.1.

### Registry reconciliation

The client fetches a server-issued, session-bound capability manifest at startup, after every tool/UI
result, on focus/visibility change, and by conditional polling while the room is active. Use `ETag`
from `(run_generation, workflow_epoch, memory_governance_version, policy_version)` to avoid payload
churn. No WebSocket/SSE infrastructure is added.

Reconcile algorithm:

1. Increment local reconciliation generation.
2. Fetch and validate bounded manifest.
3. Abort registrations absent from the manifest.
4. Await new registrations one at a time; abort them if generation changed while awaiting.
5. Commit the local map only for the current generation.
6. Render the server manifest, not the local registry map, as authority truth; separately display
   registration errors.

The manifest shape is fixed: `run_id`, `run_generation`, `workflow_id`, `state`, `epoch`,
`authority_owner`, `available_tools`, `withheld_tools[{name,reason_code}]`,
`protected_operations`, `memory_governance_version`, `capability_policy_version`, `build_sha`, and
`etag`. `protected_operations` always contains approval, proposal rejection, sandbox application,
observation retry, reviewer-handoff issuance, certification, quarantine, rejection, revocation,
role change, policy override, and reset. None may appear in `available_tools`.

## HTTP API Contracts

### Common headers and identity

- All mutation requests require `Content-Type: application/json` and exact public `Origin`.
- Channel is derived only from the server route/dependency: `/v1/webmcp/*` is `webmcp`,
  `/v1/operator/*` is `operator_ui`, `/v1/reviewer/*` is `reviewer_ui`, and observation is an
  in-process `system` call. No client-supplied channel header is accepted.
- State-bearing calls require `If-Match: "<run-generation>:<workflow-epoch>"` rather than accepting
  a free-form epoch in agent arguments.
- UI protected mutations require `X-CSRF-Token` matching the role session. WebMCP-authorized
  proposal/assessment never receive the UI CSRF token.
- Idempotency uses `Idempotency-Key` generated once before the fetch and retained through retry.
- Cross-run or cross-tenant resources return `404`; authenticated but wrong-role/channel calls
  return `403`.

### Error envelope

```json
{
  "error": {
    "code": "STALE_WORKFLOW_EPOCH",
    "message": "The workflow advanced. Current state was restored.",
    "retryable": false,
    "current_state": "AWAITING_OPERATOR_APPROVAL",
    "authority_owner": "HUMAN_OPERATOR",
    "event_id": "optional-denial-audit-id"
  }
}
```

Status mapping: `400` malformed semantic input, `401` invalid/expired session, `403` role/channel/
Origin/CSRF denial, `404` bound object unavailable, `409` stale state/digest/replay conflict, `410`
legacy judge-mode endpoint or reset generation, `412` `If-Match` mismatch, `422` schema error, `428`
missing precondition, `429` quota/rate limit, and `503` dependency unavailable with bounded
`Retry-After` where safe.

### Judge-run and session endpoints

#### `POST /v1/judge/runs`

Unauthenticated same-origin JSON scenario allocation. Exact Origin, API Gateway throttling, and
application active-run/client quotas limit abuse. Atomically creates a unique run ID, unique
synthetic tenant, source incident, `INVESTIGATING` workflow, seeded benchmark memories, operator
subject, and operator session. Returns run summary, CSRF token, expiry, and source incident; sets
`__Host-recallops_operator` (`Secure; HttpOnly; SameSite=Strict; Path=/`).

#### `POST /v1/operator/reviewer-handoff`

Requires operator cookie, CSRF, Origin, exact memory digest, and a closed purpose enum. Purpose
`initial_review` requires current `PENDING_REVIEW`; purpose `revocation` requires currently certified,
unexpired, unsuperseded, unrevoked evidence. Creates a single-use random reviewer code stored only
as SHA-256, bound to run/workflow/memory/purpose and short expiry. Returns a URL with code in
fragment. No initial-review link exists before pending review, and no revocation link exists before
certification. Issuing a handoff grants no disposition authority to the operator.

#### `POST /v1/judge/reviewer-exchange`

Consumes fragment code after removing it from browser history. Creates distinct reviewer subject
and sets `__Host-recallops_reviewer` with the same cookie properties. Returns reviewer CSRF and
bounded review context. Operator and reviewer cookies coexist; reviewer routes read only the
reviewer cookie, operator/WebMCP routes read only the operator cookie.

#### `POST /v1/operator/run/reset`

Requires operator cookie/CSRF/Origin and current generation. Marks the old run inactive, revokes
both role sessions/handoffs, advances generation, and returns a fresh entry URL. It never rewrites or
deletes old authority evidence synchronously.

### Agent endpoints

- `GET /v1/webmcp/incident`: bounded inspection for current operator run.
- `POST /v1/webmcp/proposal`: exact-match incident proposal; `INVESTIGATING` only.
- `POST /v1/webmcp/assessment`: exact observation assessment; `POSTCHECK_READY` only.
- `GET /v1/webmcp/recurrence`: reviewed recurrence query; eligible `REVIEWED` only.
- `GET /v1/webmcp/capabilities`: manifest with ETag; readable by current operator session.
- `POST /v1/webmcp/activity`: optional bounded registration/withdrawal/cancellation observation
  batch; never changes workflow or counts toward readiness.

The browser callbacks hide URL, run, tenant, actor, channel, epoch, digests, and idempotency plumbing
from tool input schemas.

### Operator endpoints

- `GET /v1/operator/run`: complete bounded operator snapshot.
- `POST /v1/operator/proposal/decision`: approve or reject exact current proposal.
- `POST /v1/operator/sandbox-execution`: apply exact approved action once.
- `POST /v1/operator/postcheck/retry`: retry observation from immutable execution, never action.
- `POST /v1/operator/reviewer-handoff`: issue bound reviewer exchange.
- `POST /v1/operator/run/reset`: invalidate run generation and authority.

### Reviewer endpoints

- `GET /v1/reviewer/evidence`: immutable review packet for reviewer-bound workflow/memory.
- `POST /v1/reviewer/disposition`: `certify`, `quarantine`, or `reject` with reason code/note.
- `POST /v1/reviewer/revocation`: protected secondary flow for currently active evidence.

The server derives the policy-defined positive/negative meaning. No review request contains an
outcome score, classification override, policy override, tenant, operator, or agent identity.

### Evidence and release endpoints

- `GET /v1/evidence/events`: bounded paginated activity for current run; cursor is opaque and
  run-bound.
- `GET /v1/evidence/events/{event_id}`: human-readable event plus safe raw binding.
- `GET /v1/evidence/receipt`: receipt status and authority-chain summary.
- `GET /v1/evidence/bundle`: authenticated status/download for the current run or `202` while
  pending.
- `GET /public/evidence/{receipt_id}/authority-bundle.zip`: credential-free, immutable download
  only after a synthetic judge receipt is signed, finalized, release-bound, and explicitly marked
  public. Unknown, pending, failed, non-synthetic, or superseded receipt IDs return `404`.
- `GET /v1/release`: build/policy/evaluation/key identity and independent live/assurance states.
- `GET /v1/claims`: claim registry entries for the exact release.

Public release/claim endpoints expose no run/session data. Per-run evidence requires the
corresponding operator or reviewer session until finalized. The finalized synthetic judge bundle
MUST expose the credential-free immutable URL above so the PRD's downloadable-proof requirement is
not dependent on cookies; the bundle itself contains only pseudonymous, allowlisted proof fields.

### Request and response records

All input models use Pydantic `extra="forbid"`. Actor, role, tenant, run, channel, and policy version
are always derived.

| Endpoint | Request body | Success record |
| --- | --- | --- |
| start run | `{}` | `RunSnapshot` and operator CSRF/session expiry |
| WebMCP proposal | exact service/version/symptom, optional rationale | `ProposalView`, manifest |
| proposal decision | decision, proposal digest, reason code, note | decision record, manifest |
| sandbox execution | proposal digest | execution, observation/verdict or failure manifest |
| observation retry | execution digest | observation/verdict, manifest |
| WebMCP assessment | observation ID, classification, rationale | assessment/verdict/memory, manifest |
| reviewer handoff | memory digest, `initial_review` or `revocation` purpose | fragment URL and expiry |
| reviewer disposition | decision, memory digest, reason code, note | disposition, receipt status, manifest |
| reviewer revocation | memory digest, reason code, note | revocation and successor receipt status |
| recurrence | none | `RecurrenceView` |
| reset | expected run generation | inactive run snapshot and fresh-entry URL |

`RunSnapshot` contains safe run/scenario identity, incident, workflow manifest, candidate views,
role, expiry, receipt/readiness status, and no session secrets. `ProposalView` contains proposal ID/
digest, action ID/display label, evidence digest list, risk, expiry, and status. `ReviewPacket`
contains immutable observation, assessment, verdict, compatibility, provenance, memory digest, and
allowed dispositions. `RecurrenceView` contains occurrence 43, baseline/governed choices, candidate
decisions, and versions. Every response is size-bounded and stable-versioned.

All UI mutation bodies set `additionalProperties=false`. Digest fields match exactly 64 lowercase
hex characters; IDs are canonical UUID strings; notes are normalized Unicode strings of 0–280
characters and are never interpreted as commands. Decision/reason combinations are closed enums:

- proposal decision: `approve` or `reject`; rejection reason is one of
  `UNSAFE`, `INSUFFICIENT_EVIDENCE`, `WRONG_TARGET`, `OTHER_BOUNDED`;
- reviewer disposition: `certify`, `quarantine`, or `reject`, constrained by the immutable policy
  outcome; reason is one of `EVIDENCE_ACCEPTED`, `NEEDS_INVESTIGATION`, `INVALID_BINDING`,
  `INSUFFICIENT_EVIDENCE`, `POLICY_CONFLICT`, `OTHER_BOUNDED`;
- revocation: reason is one of `NEW_CONTRADICTORY_EVIDENCE`, `POLICY_CHANGE`,
  `COMPATIBILITY_INVALIDATED`, `DATA_QUALITY`, `OTHER_BOUNDED`.

`OTHER_BOUNDED` requires a nonempty note; other codes permit an optional note. Certification is
rejected for an inconclusive policy verdict. No request accepts target tenant, run, workflow,
subject, role, action descriptor, policy classification, evidence values, expiry, timestamp, or
success flag from the browser.

### Canonical digest profiles

All significant-data hashes use RFC 8785 canonical JSON and an ASCII domain separator followed by a
zero byte. No digest is computed from display strings alone.

- `proposal-v1`: run/generation, tenant, incident/content digest, ordered evidence digests, action
  ID/descriptor digest, risk, policy versions, created/expiry timestamps.
- `execution-v1`: proposal digest, action ID/descriptor digest, actor subject, idempotency binding,
  simulator version, before/after state, execution timestamp.
- `observation-v1`: execution/proposal digests, source/provider version, window, bounded metrics,
  observed timestamp.
- `assessment-v1`: observation digest, agent subject, classification, rationale digest, timestamp.
- `verdict-v1`: observation digest, classification, ordered checks passed/failed, policy version,
  timestamp.
- `memory-v1`: source incident, observation/assessment/verdict digests, policy-defined outcome,
  compatibility/review policy versions, creation timestamp.
- `review-v1`: memory digest, reviewer subject, decision/reason-code/note digest, previous
  governance version, timestamp.
- `idempotency-v1`: derived run/workflow context plus canonical route-specific request body.

Digest comparison uses exact lowercase hex and constant-time comparison where attacker-controlled.
Changing any significant field produces a new digest and invalidates prior approval/review binding.

## Data Model And Database Boundaries

### Existing tables retained

`incidents`, `memories`, `approvals`, `sandbox_executions`, `postcheck_observations`,
`postcheck_policy_verdicts`, `postcheck_assessments`, `memory_events`, `webmcp_workflows`,
`judge_sessions`, `evidence_outbox`, and the migration ledger remain authoritative. Existing
composite tenant relationships and runtime-role restrictions remain mandatory.

### Migration 027 — judge runs and role handoff

#### `judge_runs`

- `run_id UUID PRIMARY KEY`
- `tenant_id STRING UNIQUE NOT NULL`
- `generation INT8 NOT NULL CHECK (generation > 0)`
- `scenario_version STRING NOT NULL`
- `source_incident_id UUID NOT NULL`
- `status STRING CHECK (status IN ('active','completed','reset','expired'))`
- `operator_subject STRING NOT NULL`
- `build_sha STRING NOT NULL`
- `capability_policy_version STRING NOT NULL`
- `created_at`, `expires_at`, `finalized_at`, `reset_at` timestamps
- composite FK `(source_incident_id, tenant_id) → incidents(id, tenant_id)`

Each run derives a tenant identifier such as `judge_<base32 run id>`; client input never supplies
it. `UNIQUE (run_id, tenant_id)` becomes a composite reference target.

#### `judge_sessions` additions

- `run_id UUID NOT NULL`
- `session_role STRING CHECK ('operator','reviewer')`
- `session_generation INT8 NOT NULL`
- composite FK `(run_id, tenant_id) → judge_runs(run_id, tenant_id)`
- unique live role subject within `(run_id, session_role, subject)`

Only session hashes and CSRF hashes persist. The API never logs or returns cookie values.

#### `review_handoffs`

- `code_hash STRING PRIMARY KEY` (64 lowercase hex)
- `run_id`, `tenant_id`, `workflow_id`, `memory_id`, `memory_digest`
- `purpose CHECK ('initial_review','revocation')`
- `issued_by_subject`, `expires_at`, `consumed_at`, `revoked_at`
- composite run, workflow, and memory/tenant foreign keys

A transaction consumes exactly one unexpired code. Reuse returns a generic invalid/expired result.

### Migration 028 — complete memory governance

- Add `rejected` to memory state and `certify`, `reject` to governance action while retaining legacy
  `activate` only for non-judge compatibility.
- Add `memory_digest`, `governance_policy_version`, `expires_at`, `superseded_at`, and `revoked_at`.
- Require `valid=false` for pending/quarantined/rejected/superseded/revoked/expired disposition and
  `valid=true` only for active certified evidence.
- Extend `memory_events` with `reason_code`, `memory_digest`, `workflow_epoch`, `run_id`, and
  `event_id` reference.
- Enforce replacement memory in the same tenant/service, active state, and compatible policy before
  supersession.

Expiration is a retrieval predicate and explicit ledger event when materialized. Historical rows
remain immutable and inspectable.

### Migration 029 — authority event ledger

#### `authority_ledger_heads`

- `(run_id, tenant_id) PRIMARY KEY`
- `last_sequence INT8 NOT NULL`
- `last_event_hash STRING NOT NULL`
- `last_receipted_sequence INT8 NOT NULL DEFAULT 0`
- `closed BOOL NOT NULL DEFAULT false`
- `ledger_version STRING NOT NULL`
- `updated_at TIMESTAMPTZ NOT NULL`

#### `authority_events`

- `event_id UUID PRIMARY KEY`
- `run_id`, `tenant_id`, `sequence`, `recorded_at`
- `event_type`, `outcome` (`accepted`, `denied`, `observed`)
- `actor_subject`, `actor_role`, `channel`
- `workflow_id`, `epoch_before`, `epoch_after`, `state_before`, `state_after`
- `capabilities_before JSONB`, `capabilities_after JSONB`
- `object_type`, `object_id`, `object_digest`
- `reason_code`, bounded `display_summary`
- `policy_version`, `build_sha`
- `previous_event_hash`, `event_hash`
- unique `(run_id, sequence)` and composite run/tenant FK

The canonical event payload contains all fields except `event_hash`. It uses strings for timestamps,
digests, and any value that could exceed the I-JSON safe integer range. `event_hash` is:

```text
SHA-256("recallops-authority-event-v1" || 0x00 || previous_event_hash_bytes ||
        0x00 || RFC8785(canonical_event_payload))
```

For every accepted authority transition, the implementation locks the ledger head, validates the
expected predecessor, writes domain rows, workflow CAS update, event, and head update in the same
serializable transaction. A failure rolls back all of them. Denials append a separate observational
event only after the business mutation has failed; their presence is evidence, not the source of
the denial guarantee. Read-only tool invocations are browser/client activity and do not enter this
authority ledger. A receipt binds an immutable ledger prefix through a target sequence; a later
revocation extends the chain and produces a successor receipt rather than modifying the prefix.

#### `activity_observations`

- `activity_id UUID PRIMARY KEY`
- `run_id`, `tenant_id`, `workflow_id`, `recorded_at`
- `source CHECK ('webmcp','browser','server')`
- `actor_subject`, `activity_type`, `tool_name`, `outcome`, bounded `display_summary`
- optional `authority_event_id` or `object_digest`, neither conferring authority
- `build_sha`, `client_instance_id_hash`
- composite run/tenant/workflow foreign keys and index on
  `(run_id, recorded_at, activity_id)`

Successful and rejected read-only WebMCP endpoint calls create bounded `webmcp` observations using
the server-derived pseudonymous agent subject. Browser registration/withdrawal/cancellation events
may be posted through one bounded, rate-limited batch endpoint and are labeled `browser`; their
absence cannot affect domain state, authorization, readiness, or receipt validity. The Activity
Rail merges authority events and observations by database `recorded_at` then event UUID, preserves
that deterministic order across refresh, and visually distinguishes supporting observations from
hashed authority events. Observation logging has no foreign-key or trigger path capable of changing
workflow, proposal, execution, memory, review, receipt, or release rows.

### Migration 030 — receipts and release evidence

#### `authority_receipts`

- `receipt_id UUID PRIMARY KEY`
- `run_id`, `tenant_id`, `ledger_head_hash`, `ledger_last_sequence`
- `manifest_digest`, `bundle_digest`, `jws_compact`
- `key_thumbprint`, `signing_algorithm`, `receipt_policy_version`
- `source_sha`, `image_digest`, `evaluation_version`
- `status CHECK ('pending','signed','failed','superseded')`
- `s3_version_id`, `created_at`, `signed_at`, bounded `failure_code`
- unique active receipt per `(run_id, ledger_head_hash, receipt_policy_version)`

#### `release_evidence_records`

- immutable release ID, source SHA, image digest, capability/receipt/evaluation versions;
- live-proof artifact digest/status and assurance artifact digest/status;
- client versions/dates and S3 object versions;
- KMS-signed canonical release statement, digest, and timestamps.

The live application displays green only when the release record exactly matches its injected
source SHA and image digest and both independently generated statuses are passing.

### Runtime roles

- `recallops_migration_owner`: schema/migrations only; not available to application containers.
- `recallops_api`: exact SELECT/INSERT/UPDATE needed for domain, run, session, workflow, ledger, and
  receipt-status rows plus INSERT/SELECT on bounded activity observations; no schema, role,
  cluster, arbitrary DELETE, or unrelated-table access.
- `recallops_outbox`: lease/update outbox, read finalized run event/receipt material, invoke only the
  exact KMS key, and write only the run/release S3 prefixes.
- `recallops_cleanup`: scheduled judging-data retention task with only the documented cleanup entry
  point and no serving role. If CockroachDB cannot enforce the intended row-limited cleanup safely,
  cleanup remains migration-owner operated rather than granting broad runtime DELETE.

Database verification MUST enumerate exact grants, prohibited operations, and direct cross-run,
cross-tenant, cross-workflow, and cross-incident relationship attempts.

## Authority Receipt And Proof Bundle

### Finalization boundary

Reviewer disposition commits the completion authority event, captures that event's sequence as the
receipt target, and enqueues `receipt_requested` in the same transaction. It does not call KMS
inside the database transaction. The outbox worker:

1. claims the request idempotently;
2. reads the exact immutable ledger prefix through the captured target sequence;
3. verifies the chain and policy before signing;
4. builds a compact manifest and complete bundle;
5. signs the JWS input using KMS;
6. verifies the returned signature locally against the pinned public JWK and exact signing input;
7. writes versioned S3 objects;
8. records signature, bundle digest, and S3 version transactionally;
9. marks the request delivered.

KMS/S3 failure leaves governed domain state intact but Assurance incomplete and receipt retryable.
The UI says proof generation is pending/failed; it never fabricates a receipt.

The receipt proves the supplied accepted authority history through its target sequence. Denial logs
and browser activity are supporting observations and are not claimed to be a complete record of
every attempted interaction. Revocation or supersession appends later events and produces a
successor receipt referencing the prior receipt and prefix.

### Compact manifest schema

The RFC 8785-canonical manifest is deliberately under 2 KiB and contains:

- `receipt_version`, `receipt_policy_version`, `capability_policy_version`;
- `run_id`, `tenant_id_hash`, `scenario_version`;
- `workflow_id`, final state/disposition, first/last epoch;
- `ledger_first_hash`, `ledger_head_hash`, event count;
- proposal, execution, observation, assessment, policy-verdict, memory, and review digests;
- operator/reviewer pseudonymous subjects and separation result;
- source SHA, deployed image digest, evaluation version, claim-registry digest;
- evidence-index digest, signing time as an asserted string, expiry/supersession fields;
- key thumbprint and algorithm identifiers.

It contains no incident text, rationale, metrics, email, cookie/session material, bootstrap code, CSRF
value, IP address, or database credential.

### JWS/KMS profile

- KMS key spec: `ECC_NIST_EDWARDS25519`.
- Key usage: `SIGN_VERIFY`.
- AWS signing algorithm: `ED25519_SHA_512`.
- `MessageType`: `RAW`.
- JOSE protected header: `alg=Ed25519`, `kid=<RFC7638 thumbprint>`,
  `typ=recallops-authority-receipt+jws`, and integer `v=1`.
- Payload: exact RFC 8785 bytes of the compact manifest.
- KMS message: the complete ASCII JWS signing input
  `base64url(protected) + "." + base64url(payload)`; it MUST remain ≤4096 bytes.
- Signature: raw KMS Ed25519 signature, base64url without padding.
- The verifier allowlists only the fully specified RFC 9864 `Ed25519` JOSE identifier; deprecated
  polymorphic `EdDSA` is rejected even if the signature bytes would otherwise verify.
- No RSA/ECDSA/local-key fallback. Unsupported key/region/algorithm fails deployment preflight.

`GetPublicKey` returns DER SubjectPublicKeyInfo. Release tooling verifies key spec, usage, and signing
algorithm, extracts the raw Ed25519 public key, emits `{"kty":"OKP","crv":"Ed25519","x":...}`,
and computes `kid` using RFC 7638. The JWK and thumbprint are committed to the verifier's trusted-key
registry before release freeze. A key supplied only inside a downloaded bundle is never a trust
anchor.

### Bundle layout

```text
authority-bundle/
├── manifest.jcs.json
├── receipt.jws
├── public.jwk.json
├── events.ndjson
├── evidence-index.jcs.json
├── policy/
│   ├── capability-policy.json
│   └── receipt-policy.json
├── evaluation/
│   ├── case.json
│   └── result.json
├── release.json
├── claims.json
├── checksums.sha256
└── README.md
```

Every NDJSON line is an independently RFC 8785-canonical event. The canonical evidence index maps
every auxiliary evidence path (events, policies, evaluation, release identity, claims, and public
JWK) to its SHA-256 digest; the signed receipt manifest contains the digest of that index. After the
manifest and JWS exist, `checksums.sha256` covers every file except itself, and `bundle_digest` is
the domain-separated SHA-256 of the checksum file bytes. This order has no circular digest. S3
object version and bundle digest are recorded in the database and signed release evidence.

The bundle's `release.json` is the already-frozen source/image/policy/evaluation/key identity only;
it contains no receipt signature, bundle digest, S3 version, readiness result, or value derived from
this bundle. The separately generated KMS-signed release statement may bind the completed bundle
digest and readiness artifacts, but it is stored outside the authority bundle it references. This
separation is mandatory and is covered by a digest-graph acyclicity test.

### Offline verifier

`node tools/verify-authority-bundle.mjs <bundle-directory>` MUST perform, in order:

1. strict file allowlist and size limits;
2. outer checksum and recorded bundle-digest verification when release metadata is supplied;
3. JSON parse with duplicate-key rejection before object construction;
4. RFC 8785 canonical byte equality for manifest/events/index/policies/claims;
5. exact public-JWK match against the repository-pinned trusted-key registry, then RFC 7638
   thumbprint and protected-header allowlist validation;
6. Ed25519 JWS verification using Node built-in `crypto`;
7. signed evidence-index digest and every indexed auxiliary-file digest verification;
8. event sequence, predecessor hash, event hash, and ledger-head verification;
9. legal state/epoch/capability/channel/role transition verification;
10. exact proposal→approval→execution→observation→assessment→verdict→review bindings;
11. distinct operator/reviewer subject verification;
12. final memory disposition/retrievability verification;
13. release/source/image/evaluation/claim digest verification;
14. a bounded pass/fail report and nonzero exit code on any failure.

The verifier does not call RecallOps, AWS, S3, KMS, a time server, or the network. Published tampered
vectors alter each material binding, reorder/delete/duplicate events, change policy/tool sets,
replace the key, change the disposition, and corrupt the signature. Every vector MUST fail for the
expected reason code.

## Judge Run Isolation And Session Security

### Run allocation

- `POST /v1/judge/runs` creates a cryptographically random UUID and unique synthetic tenant. Because
  this operation affects no pre-existing user authority, exact Origin, JSON-only request handling,
  gateway throttling, and application quota are the anti-abuse boundary; no decorative launch-CSRF
  mechanism is added.
- Source incident and required seed memories are copied from immutable versioned fixtures in the
  same transaction; they are never shared mutable rows across runs.
- A configurable active-run ceiling and per-client launch window bound resource use.
- Active run TTL is long enough for the demo and short enough to invalidate abandoned authority.
- Scenario fixture version is immutable for a run.

### Role-specific sessions

- Operator and reviewer use different random 256-bit opaque cookies and different cookie names.
- Cookie values exist only in browser cookie storage; hashes persist in CockroachDB.
- `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, and `__Host-` prefixes are mandatory in the
  public deployment.
- CSRF tokens are distinct per role session, returned once after exchange, held only in memory or
  sessionStorage, and accepted only by that role's protected UI routes.
- Exact Origin is checked on all state-changing requests; CORS does not allow foreign origins.
- Reviewer exchange codes use at least 256 bits, fragment delivery, single consumption, short TTL,
  constant-time hash comparison, and rate limiting.
- Session lookup always returns run/tenant/role/subject/generation; client headers cannot override
  any of them.
- WebMCP routes authenticate the operator page session, then derive actor role `agent` and an
  attributable pseudonymous agent subject from that session plus run. This attributes the browser
  agent channel without claiming independent model authentication. Operator UI actions retain the
  operator subject. The reviewer must differ from both.

### Abuse and retention

- HTTP API throttling and WAF provide outer rate control; application quotas protect scenario
  allocation and evidence downloads.
- Payload and response limits exist at gateway, ASGI middleware, Pydantic schema, and proof-bundle
  generation.
- Public data is synthetic. Access logs exclude query strings, cookies, authorization, CSRF,
  fragments, request bodies, and proof contents.
- CloudWatch logs expire after 30 days. Judge role sessions/handoffs expire automatically.
- A scheduled, separately authorized retention task removes expired synthetic run data and S3
  bundles after the documented judging/evidence window; cleanup is tested on disposable data.

## Browser Application Architecture

### State model

The browser stores only non-authoritative display state: current manifest, safe IDs, role view,
pending request state, and last ETag. Cookies remain HttpOnly. SessionStorage may hold role CSRF and
non-secret display IDs, never tenant authority or receipt trust. On reload, the page discards local
assumptions and fetches the role/run snapshot.

### Visual regions

- `IncidentEvidencePanel`: incident 42/43, candidate eligibility, proposal, metrics, assessment,
  verdict, review and recurrence results.
- `CapabilityInspector`: server state, authority owner, available/withdrawn/never-exposed tools,
  registration health, and synchronization status.
- `ActivityRail`: paginated authoritative events plus clearly labeled local registration events.
- `ProtectedActionPanel`: one state-appropriate operator or reviewer action at a time.
- `EvidenceDrawer`: human-readable binding first, safe raw record and claim links second.
- `AuthorityChain`: compact receipt nodes and bundle/offline verification actions.
- `ReadinessBadge`: separate Live proof and Assurance states from build-matched release evidence.
- `PromptCard`: one copy action for the exact primary prompt: “Investigate checkout-latency-42,
  reject ineligible history, and stage the safest eligible mitigation. Do not approve, execute,
  retry evidence collection, review memory, change roles or policy, or reset the scenario.”

Local WebMCP registration events MUST NOT be rendered as authoritative server events. The rail marks
their source as `BROWSER`; accepted/denied authority events come from the server ledger.
The initial viewport MUST answer incident, current capability, authority owner, trusted evidence,
and next action without scrolling. Disabled actions retain a textual missing-prerequisite reason.

### Accessibility contract

- Native semantic headings, landmarks, lists, buttons, dialogs, details/summary, tables, and status
  regions before ARIA supplementation.
- One `aria-live=polite` summary region for material state changes; rapid events coalesce.
- No automatic focus on routine polling. After a protected action, focus moves to the new state
  heading only when the prior control disappears.
- Dialog focus is trapped and restored; Escape closes non-destructive drawers, not committed action
  confirmation.
- Actor/outcome/state use text plus icon/shape; contrast and focus indicators satisfy WCAG 2.2 AA.
- `prefers-reduced-motion` removes positional animation while retaining explicit changed-state text.
- At narrow widths panels stack Incident → Capability → Protected action → Activity → Proof; no
  material horizontal scroll.
- Readable relative times are paired with exact UTC timestamps in accessible expandable text.

### Security headers and rendering

- `Content-Security-Policy`: default-src/self, script/style/img/connect/frame/object/base/form limits
  narrowed to required same-origin behavior; no unsafe inline/eval.
- `Permissions-Policy: tools=(self)` and unnecessary powerful features disabled.
- `Origin-Agent-Cluster: ?1`, `X-Content-Type-Options: nosniff`, strict referrer policy, frame
  denial, and HSTS on public HTTPS.
- All dynamic text renders through `textContent`/safe DOM construction. No untrusted `innerHTML`.
- Fragment bootstrap is removed with `history.replaceState` before exchange and never sent as
  referrer.
- Origin-trial token, if required for the frozen Chrome version, is configured as public deployment
  metadata and validated in the live smoke test.

## Sandbox, Observation, And Policy

### Exact action allowlist

The only executable identifier is `checkout.reduce_concurrency_and_recycle.v1`. The application
stores its canonical parameter-free action descriptor and SHA-256 digest. Proposal output may show
a human label but never becomes an executable command. Sandbox execution accepts no command,
arguments, shell text, URL, resource name, metric, or policy override.

### Execution semantics

- One execution row per source incident and unique run-bound idempotency key.
- Approval proposal digest, workflow proposal digest, request binding, and action descriptor digest
  must match.
- Preparing deterministic before/after simulator state occurs outside the database transaction only
  if it is pure; persistence and workflow transition occur atomically.
- A replay with identical complete binding returns the recorded execution. A different binding
  conflicts.

### Observation semantics

- Observation provider accepts only the recorded `SandboxExecution` object.
- Observation digest binds run/tenant/incident, execution ID/digest, proposal digest, source,
  provider version, window, before/after metrics, and observed timestamp.
- Deterministic policy evaluates only immutable observation fields and records checks passed/failed
  plus policy version.
- Failure records only the workflow transition and bounded failure code. It creates no observation,
  verdict, assessment, or memory.
- Retry resolves the immutable execution and cannot call sandbox mutation.

### Memory outcome semantics

- Policy verdict—not agent classification—sets positive (`recovered`), negative
  (`not_recovered`), or unusable (`inconclusive`) outcome semantics.
- Assessment/policy agreement is derived and displayed, never used to bypass review.
- Certified positive evidence may rank as a recommendation subject to compatibility/freshness.
- Certified negative evidence retains full penalty and can only disqualify/warn.
- Inconclusive evidence cannot be certified for positive/negative retrieval; reviewer may quarantine
  or reject it.

## File Structure

Only files needed to satisfy the PRD are added or changed. Existing unrelated evaluation,
deployment, and evidence files remain untouched unless the checklist explicitly regenerates them.

```text
recallops/
├── src/recallops/
│   ├── api.py                    # Composition root and legacy-route judge-mode retirement
│   ├── api_errors.py             # Bounded stable HTTP error codes/envelopes
│   ├── auth.py                   # Role-cookie authentication, Origin/CSRF/channel guards
│   ├── config.py                 # Bounded settings and release/signing configuration
│   ├── domain.py                 # Pydantic public/domain records and governance enums
│   ├── workflow.py               # State graph, capability policy, CAS coordinator
│   ├── judge_runs.py             # Run allocation, isolation, quota, reset, retention model
│   ├── sessions.py               # Operator/reviewer sessions and handoff repositories
│   ├── sandbox.py                # Exact allowlist simulator, observer, deterministic verdict
│   ├── service.py                # Incident/retrieval/proposal/evidence/governance use cases
│   ├── store.py                  # In-memory and Cockroach repositories/transactions
│   ├── ledger.py                 # Canonical authority event and transactional hash chain
│   ├── receipts.py               # Manifest, JWS input, KMS signer, bundle builder
│   ├── release_evidence.py       # Claim registry and dual-gate build matching
│   ├── evaluation.py             # Governed and similarity-only deterministic evaluators
│   ├── outbox.py                 # Receipt/evidence delivery with lease/idempotency
│   ├── static/
│   │   ├── index.html            # Operator room and stable public start shell
│   │   ├── reviewer.html         # Role-exclusive review surface
│   │   ├── app.js                # Bootstrap and top-level composition only
│   │   ├── api-client.js         # Same-origin requests, ETag, errors, abort reconciliation
│   │   ├── room-state.js         # Non-authoritative browser state and snapshot refresh
│   │   ├── webmcp.js             # Four definitions and generation-safe registry reconciler
│   │   ├── render.js             # Safe DOM rendering for room/rail/inspector/drawers
│   │   ├── accessibility.js      # Focus/live-region/reduced-motion behavior
│   │   └── styles.css            # Responsive control-room design and semantic states
│   └── py.typed                  # Typed-package marker
├── migrations/
│   ├── 027_judge_runs.sql        # Runs, session/run binding, reviewer handoffs
│   ├── 028_memory_lifecycle.sql  # Certify/reject/revoke/expiry/supersession fields/checks
│   ├── 029_authority_ledger.sql  # Ledger heads/events, activity observations, constraints
│   └── 030_receipts_release.sql  # Receipt and release-evidence records/grants
├── evaluation/
│   ├── webmcp_cases.json         # Prompt/tool/order/argument cases
│   ├── governed_benchmark.json   # Versioned fair baseline/RecallOps candidate cases
│   ├── expected_invariants.json  # Exact zero-violation and functional expectations
│   └── README.md                 # Dataset meaning and synthetic-claim boundary
├── artifacts/
│   ├── release/                  # Generated frozen-release evidence (not hand-edited)
│   └── authority-vectors/        # Valid and tampered fixed receipt bundles
├── evidence/
│   ├── claims.json               # Stable claim registry with live/raw/reproduce links
│   └── manifest.json             # Generated artifact digests and release binding
├── tools/
│   ├── verify-authority-bundle.mjs # Network-free Node verifier
│   └── trusted-receipt-keys.json   # Release-scoped pinned JWKs and explicit transitions
├── scripts/
│   ├── generate-webmcp-evals.py  # Deterministic cases/results and summaries
│   ├── generate-authority-vectors.py # Valid/tampered proof fixtures
│   ├── capture-chatgpt-client.md # Manual ChatGPT acceptance protocol and evidence fields
│   ├── capture-native-webmcp.mjs # Native Chrome lifecycle/DevTools evidence
│   ├── smoke-live.mjs            # Frozen live-path smoke and artifact download
│   └── package-release-evidence.py # Existing packager extended for dual gates
├── tests/
│   ├── test_judge_runs.py        # Isolation, quotas, reset, role-session lifecycle
│   ├── test_workflow.py          # Full state/capability transition matrix
│   ├── test_ledger.py            # Atomic chain, ordering, denial, concurrency, finalization
│   ├── test_receipts.py          # JCS/JWS/KMS adapter/bundle and boundary claims
│   ├── test_release_evidence.py  # Dual-gate/build mismatch behavior
│   ├── test_retrieval.py         # Positive/negative/rejected/expired recurrence
│   ├── test_api.py               # Exact API/auth/error/idempotency contracts
│   ├── integration/
│   │   └── test_database_boundaries.py # Real Cockroach grants/FKs/transactions/replays
│   ├── browser/
│   │   └── recallops.spec.ts     # Complete operator/reviewer/accessibility/responsive flow
│   └── webmcp-native/
│       └── native.spec.ts        # Native discovery/invocation/withdrawal/cancellation
├── infra/aws/
│   └── public-demo.yaml          # Judge auth, KMS key, S3, API/ECS/alarms/retention task
├── docs/
│   ├── JUDGE_GUIDE.md            # One-page frozen-release judge path
│   ├── EVIDENCE_INDEX.md         # Claim-to-proof navigation
│   ├── THREAT_MODEL.md           # Updated exact claims/residual risks
│   ├── WEBMCP_PROVENANCE.md      # Baseline and post-August-25 dated work
│   └── hackathon-build/
│       └── spec.md               # This normative implementation contract
├── package.json                  # Pinned Playwright/axe scripts only
├── pyproject.toml                # Existing strict Python tool/dependency policy
└── Dockerfile                    # Existing digest-pinned non-root read-only runtime
```

Files are split only where ownership/testability requires it. This is not permission to create a
new framework or service layer for every heading.

## Data Flow

### Flow A — start and inspect

1. Judge loads `/`; static shell displays simulation and client support boundary.
2. Same-origin launch POST allocates unique run/tenant, fixture memory, source incident, workflow,
   operator session, and genesis ledger event atomically.
3. Operator cookie selects the run; snapshot returns state/candidates/capability manifest.
4. Browser reconciler registers `inspect_incident` and `propose_mitigation`.
5. Agent inspection GET derives run from cookie, persists a bounded supporting observation, and
   returns the bounded snapshot. The read-only call does not append or authorize authority state.

### Flow B — proposal and authority handoff

1. Agent calls `propose_mitigation` with bounded incident values.
2. Callback attaches internal channel, ETag/epoch, and stable idempotency key.
3. Server exact-matches stored incident, computes one action/proposal digest, validates state, and
   commits proposal + transition + ledger event.
4. Response contains new epoch/authority. Client aborts proposal registration before rendering the
   protected operator action.
5. Any stale callback reaches server with old epoch and receives `412/409`; no proposal changes.

### Flow C — approval, sandbox, and observation

1. Operator page shows exact proposal/action/digest and sends CSRF-protected approval.
2. Approval and transition commit with the ledger event.
3. Separate operator confirmation applies the one allowed sandbox action.
4. Execution persistence and transition to observation commit once.
5. Observer collects deterministic telemetry outside the authority transaction from the immutable
   execution object.
6. Success commits observation + verdict + transition + event together. Failure commits only
   `POSTCHECK_UNAVAILABLE` + failure event.
7. Retry reuses execution, never calls sandbox mutation.

### Flow D — assessment and independent review

1. `POSTCHECK_READY` manifest registers assessment tool.
2. Agent submits observation ID/classification/rationale; server resolves immutable evidence.
3. Assessment + policy-derived pending memory + transition + event commit atomically.
4. Assessment tool is withdrawn; pending memory retrieval predicates remain false.
5. Operator generates exact memory-bound reviewer handoff.
6. Reviewer exchanges code to a distinct role cookie and reads immutable packet.
7. Reviewer disposition + memory event + workflow completion + authority event + receipt outbox
   request commit atomically.

### Flow E — receipt and recurrence

1. Outbox verifies finalized ledger, builds/signs bundle, writes S3, and records receipt.
2. Browser polls receipt status and displays authority chain only from signed build-matched data.
3. For certified active evidence, capability manifest registers `recall_reviewed_memory`.
4. Recall evaluates immutable occurrence 43 against reviewed memory without domain mutation.
5. UI shows baseline versus governed recommendation and exact raw benchmark case link.

### Flow F — refresh, concurrency, and reset

1. Every page load starts from role cookie → run snapshot, not sessionStorage.
2. ETag/epoch preconditions serialize user-visible state; Cockroach serializable retry handles
   database contention.
3. Idempotency returns the single accepted result for identical replay.
4. Reset marks run inactive and revokes sessions/handoffs in one transaction; stale tools fail.
5. Starting again creates a new run/tenant/generation; no prior approval carries forward.

## Components And Responsibilities

### Browser WebMCP Registry

Implements: PRD 2.1–3.2, 5.3, 7.2, 8.1, 9.1, 9.3, 10.2.

Owns only the four definitions, feature detection, per-tool registration controllers, execution
signals, output budgets, and generation-safe reconciliation. It does not own workflow policy,
identity, authority, or protected actions.

### Browser Control Room

Implements: PRD 1.1–1.2, 4.1–5.3, 6.1–8.3, 9.1–10.2, 11.3, 12.1.

Owns safe presentation, progressive evidence disclosure, role-exclusive actions, accessible state
announcements, and server reconciliation. It never derives authorization from disabled buttons.

### Authentication And Judge Run Service

Implements: PRD 1.1, 4.1–4.2, 6.1, 6.3, 9.1, 12.1.

Owns isolated run allocation, subject/session/handoff lifecycle, quota, role-cookie selection,
Origin/CSRF enforcement, run generation, reset, and expiry. It never accepts client identity or
tenant assertions.

### Workflow Policy And Transaction Coordinator

Implements: PRD 3.1–3.2, 4.1–5.3, 6.2, 7.1, 8.1, 9.1.

Owns state graph, capability derivation, authority owner, epoch CAS, channel/role rules, and atomic
composition of domain/ledger changes. It exposes no generic transition endpoint.

### Retrieval And Proposal Service

Implements: PRD 2.1–3.1, 7.1–7.2, 11.1.

Owns tenant/service filtering before ranking, compatibility, review-state exclusion, negative
penalty, abstention, exact action mapping, proposal digest, and the fair baseline evaluator. It
cannot approve or execute.

### Sandbox And Observation Service

Implements: PRD 4.2, 5.1–5.2, 9.2.

Owns the exact action allowlist, deterministic mutation, immutable execution, independent
observation, policy verdict, unavailability, and retry without re-execution. It has no shell,
production client, external target selector, or agent-controlled metric input.

### Memory Governance Service

Implements: PRD 5.3, 6.1–7.2.

Owns pending creation, certify/quarantine/reject/revoke/supersede/expiry rules, subject separation,
reason codes, policy-defined outcome semantics, and retrieval admissibility. It cannot rewrite
evidence layers.

### Authority Ledger

Implements: PRD 8.2–8.3, 9.1, 11.2.

Owns canonical event schema, chain head locking, accepted-event atomicity, denial observations,
finalization, and safe activity projections. It is evidence of supplied history, not an external
truth oracle.

### Receipt And Evidence Exporter

Implements: PRD 8.3, 9.2, 11.2–11.3, 12.2.

Owns JCS manifest, Ed25519 JWS, public JWK, complete bundle, S3 version, offline vectors, and proof
status. Signing failure cannot change domain outcome or produce a green Assurance gate.

### Evaluation And Release Evidence

Implements: PRD 10.2, 11.1–11.3, 12.2 and Demo Acceptance.

Owns versioned cases, identical baseline inputs, exact counts/denominators, claim registry,
cross-client records, source/image binding, and independent gates. It never hand-writes measured
results.

## External APIs And Dependencies

### WebMCP and browser clients

- Depend only on the current imperative API surface used by the W3C Community Group draft:
  `document.modelContext.registerTool(tool, {signal})`.
- Do not depend on nonstandard `provideContext`, `clearContext`, or name-based unregistration.
- Test Chrome's required origin trial/flag and ChatGPT site-tool availability separately.
- Treat the WebMCP draft as version-sensitive; record exact client builds and dates.

### CockroachDB

- Use default `SERIALIZABLE`; do not downgrade authority transactions to `READ COMMITTED`.
- `run_serializable` retries the whole pure database closure only for retryable `40001` conditions,
  with bounded attempts/deadline/jitter.
- External observation, KMS, and S3 calls never execute inside a retryable transaction.
- Migrations remain ordered, checksum-locked, one transaction/file, and migration-owner only.

### AWS KMS

- Task/outbox role gets `kms:Sign` and `kms:GetPublicKey` only on the exact receipt key.
- IAM condition restricts signing algorithm to `ED25519_SHA_512` where supported.
- Key rotation is explicit: new public JWK/thumbprint and signed predecessor transition; never
  silently replace the pinned key for an existing release.
- CloudTrail records KMS calls but is not presented as part of the receipt's cryptographic proof.

### AWS S3

- Bucket remains private, TLS-only, encrypted, versioned, and public-access blocked.
- Outbox role writes only documented release/run prefixes and reads only what verification needs.
- Public judge downloads are served through bounded application endpoints or time-limited delivery,
  never a writable/public bucket policy.

### AWS deployment

- Use immutable ECR image digest, non-root UID, read-only root filesystem, dropped capabilities,
  ECS deployment rollback, private task subnets without public IPs, internal ALB, HTTP API
  throttling, WAF, Secrets Manager, and CloudWatch.
- Public demo template uses `RECALLOPS_AUTH_MODE=judge`; Cognito resources are not on the judge path.
- KMS/public-key/release inputs are deployment parameters whose values are exposed only when safe.
- Desired count may exceed one because all authority state is in CockroachDB; no in-process run
  state may be required for correctness.

## AI Usage

RecallOps does not call an AI model in the required live path. ChatGPT or the Chrome test agent is
the visiting agent and chooses/calls WebMCP tools. Deterministic reasoning and embeddings make the
judge path reproducible and remove provider availability from the core story.

Agent-dependent evaluations measure:

- correct tool choice from the user prompt;
- correct order under state-dependent discovery;
- valid bounded arguments;
- correct use of returned evidence;
- stopping at human authority and mid-chain failure;
- successful completion of the intended journey.

Deterministic tests cover all non-model state, authorization, binding, ranking, signing, and UI
behavior. No prompt or model result is used as proof that a protected transition is safe.

## Error Strategy

### Demo-critical failures

1. **Client tool registration fails:** show unsupported/failed status, register no substitute, keep
   UI read-only/protected behavior honest, and capture DevTools error.
2. **Observation fails:** enter `POSTCHECK_UNAVAILABLE`, expose no assessment, create no memory, and
   allow operator-only retry without execution.
3. **Receipt dependency fails:** preserve reviewed outcome, keep Assurance incomplete, show bounded
   retry/pending state, and never substitute an unsigned receipt.

### General handling

- Recoverable network errors retain the same idempotency key and reconcile before offering retry.
- `AbortError` is not reported as rollback; the client immediately fetches current manifest.
- State/digest conflicts refresh and explain current authority; they do not automatically resubmit.
- Validation errors identify bounded fields, not stack traces or internal objects.
- Unknown server errors use correlation ID, generic message, server-side structured log, and no
  false “no action executed” claim unless authoritative reconciliation proves it.

## Evaluation And Verification

### Deterministic test layers

1. Unit/property tests for schemas, canonicalization, hashes, transitions, ranking, expiry, and
   outcome semantics.
2. API tests for every endpoint, role/channel, Origin/CSRF, idempotency, error code, response budget,
   and legacy judge-mode denial.
3. Real CockroachDB tests for full authority transaction atomicity, concurrent CAS, unique keys,
   composite FKs, grants, immutable rows, and retry behavior.
4. Browser tests for complete flows, refresh each state, duplicate tabs, narrow view, keyboard,
   screen reader semantics, reduced motion, failures, proof drawers, and role exclusivity.
5. Native Chrome WebMCP tests for discovery, schemas, annotations, invocation, cancellation,
   withdrawal, stale callback rejection, registration failure, and DevTools-visible lifecycle.
6. Offline verifier tests for valid/tampered vectors and network independence.
7. Live release smoke for exact deployed image, full run, bundle, recurrence, reset, and both gates.

### Agent evaluations

Versioned prompts include intended success, wrong-tool, wrong-order, stale tool, protected-action
request, injected incident instructions, unavailable observation, disagreement, and no-eligible-
memory cases. Preserve raw prompt, visible tool inventory, predicted calls/arguments, outputs,
failures, client/model/version/date, source SHA, and evaluation version.

Agent evaluation success thresholds are frozen before the final run. Security invariants remain
binary zero-violation gates; probabilistic tool-choice metrics use counts/denominators and disclose
all failures rather than claiming certainty.

### Fair impact benchmark

- One immutable candidate dataset and query feed both algorithms.
- Similarity-only selects maximum semantic similarity with published deterministic tie-break.
- RecallOps filters policy-ineligible candidates before governed ranking.
- Report exact unsafe top selections, pending leakage, correct abstentions, compatibility rejection,
  negative penalties, and recurrence recommendation changes.
- Dataset/result/policy/source digests bind the live case to the raw artifact.
- All results are explicitly synthetic; no production incident/time/safety extrapolation.

### Claim registry and dual-gate derivation

`evidence/claims.json` is schema-validated and generated from committed claim definitions. Each
entry includes stable claim ID, rubric, bounded claim text, live route/state selector, workflow event
type, test IDs, evaluation case IDs, receipt fields, raw artifact paths, reproduction command, and
release identity. Link checking and digest checking fail on missing targets.

`LIVE_PROOF_COMPLETE` is derived only when the deployed journey, refresh/reset, public download,
accessibility smoke, native Chrome WebMCP record, and ChatGPT site-tool protocol pass for the exact
image. `ASSURANCE_COMPLETE` is derived only when deterministic/integration/security suites,
benchmark, ledger/receipt vectors, offline verifier, provenance, and artifact manifest pass for the
same image. A KMS-signed canonical release statement contains both booleans and their artifact
digests. That statement is generated outside any artifact it references, avoiding a digest cycle.
The UI treats it as supporting status; the downloadable offline evidence is the independent
verification path.

### Quality gates

- Ruff and strict mypy pass.
- Branch-aware Python coverage remains 100% for tracked application modules.
- Real CockroachDB integration and direct privilege/binding verifier pass.
- All Playwright and native WebMCP tests pass on frozen versions.
- Accessibility automated checks have zero serious/critical violations; keyboard/manual checks pass.
- All receipt tamper vectors fail with expected codes; valid vector passes.
- Dependency/container/IaC/SBOM checks bind to final image.
- `LIVE_PROOF_COMPLETE` and `ASSURANCE_COMPLETE` both match the same source/image release.

## Risks And Verification

| Risk | Technical boundary | Required verification |
| --- | --- | --- |
| Browser retains stale tool | AbortController + server epoch/digest | Race and stale callback native tests |
| Registry race flickers/wrong tool | generation-guarded reconcile | delayed registration fault test |
| Agent guesses protected API | role-cookie route + channel + CSRF/Origin | every protected endpoint via WebMCP |
| Injected incident controls agent | bounded untrusted fields and exact server derivation | adversarial content eval and API test |
| Approval drifts | exact proposal digest + state/epoch | replacement/expiry/reset mismatch tests |
| Action replay | execution uniqueness/idempotency | concurrent double-submit DB test |
| Missing evidence becomes success | no assess capability/object on failure | provider failure and direct DB absence probe |
| Agent rewrites measurements | assessment schema lacks metrics | unknown-field and mismatch tests |
| Reviewer rewrites verdict | disposition schema lacks classification | mutation attempts and immutable-row grants |
| Self-review | subject inequality in transaction | same-session/cross-cookie/direct SQL tests |
| Pending/rejected memory leaks | eligibility predicate before ranking | lifecycle retrieval matrix |
| Concurrent judges interfere | unique tenant/run/session binding | parallel end-to-end runs |
| Shared cookie changes role | distinct endpoint-selected cookies | mixed-cookie role-confusion tests |
| Hash chain omits committed transition | event/head/domain same transaction | fault injection at every write boundary |
| Receipt signs wrong build | manifest/release/image exact match | mismatch vectors and live status test |
| KMS algorithm mismatch | deployment preflight, no fallback | stub contract + live GetPublicKey/Sign proof |
| Compromised signer overclaim | explicit receipt limitation | copy/claim audit |
| S3/KMS outage fakes assurance | async outbox and false gate | dependency fault tests |
| Unsupported client fakes WebMCP | no polyfill, explicit state | unsupported-browser test |
| Refresh loses state | cookie-derived server snapshot | refresh every state |
| Accessibility regresses | semantic DOM + axe/manual protocol | wide/narrow/keyboard/screen-reader evidence |
| Release artifacts drift | freeze identity and reopened gates | change-SHA/image negative tests |

## Demo And Submission Flow

### Frozen demo sequence

1. Open stable judge URL; allocate isolated run.
2. Within ten seconds show incident 42 and rejected 0.94 known failure.
3. Agent inspects and proposes through native WebMCP.
4. Show proposal tool withdrawal and operator authority.
5. Approve exact digest, apply sandbox action, show independent telemetry/verdict.
6. Agent assesses; show pending memory excluded from recall.
7. Exchange reviewer handoff; certify with distinct reviewer.
8. Show signed receipt status and authority chain.
9. Agent recalls occurrence 43; show newly reviewed success changing recommendation.
10. Show one compact unavailable-observation case and offline verifier pass.

Target final cut is 2:40–2:50. The product remains onscreen; code and extended output are linked
evidence. The final spoken line is: **“Similarity can discover experience. Only reviewed evidence
earns authority.”**

### Release freeze

1. Clean commit and immutable image build.
2. Deploy image digest and record runtime build identity.
3. Run database grants/boundary verification.
4. Run deterministic, browser, native WebMCP, accessibility, and live smoke suites.
5. Complete manual ChatGPT built-in browser protocol and preserve site-tool activity.
6. Generate benchmark, claims, receipts, vectors, SBOM, and evidence manifest.
7. Set both gates only from matching artifacts.
8. Record video against that release.
9. Audit repository license, public URL, client disclosure, provenance, and submission copy.
10. Any change after step 6 invalidates both gates and repeats steps 2–9.

During the judging window, a scheduled external smoke job exercises start, inspect, proposal
withdrawal, operator action, observation, assessment, reviewer handoff/disposition, recurrence,
reset, and bundle download at least every six hours. It alerts on failure but cannot mutate release
evidence or force a gate green.

## Normative Requirement Inventory

The PRD is not summarized away by this specification. Its acceptance criteria remain normative and
receive stable derived identifiers in document order: `PRD-<story>-AC<n>`. There are exactly 149
story acceptance criteria:

```text
1.1:5  1.2:5  2.1:5  2.2:5  2.3:3  3.1:5  3.2:5  4.1:5  4.2:5
5.1:5  5.2:5  5.3:6  6.1:5  6.2:7  6.3:5  7.1:4  7.2:5  8.1:5
8.2:5  8.3:5  9.1:5  9.2:5  9.3:4  10.1:5  10.2:5  11.1:5
11.2:5  11.3:5  12.1:5  12.2:5
```

The 16 PRD edge-case rows are `EDGE-01` through `EDGE-16` in table order. The 15 cross-cutting
standards are `XSEC-01..04`, `XFUNC-01..04`, `XA11Y-01..03`, and `XEVID-01..04`. The eight
**What We Are Building** bullets are the closed product-scope allowlist; **What We Would Add With
More Time** and this specification's Explicit Non-Goals are the denylist.

The build checklist and final release evidence MUST contain a machine-readable trace record for
every identifier above with: verbatim requirement digest, owning component, enforcing interface or
stored invariant, positive test, at least one negative test where a forbidden behavior exists,
live-proof location, assurance artifact, source revision, and status. Story-level entries below are
navigation, not permission to collapse several acceptance criteria into one assertion. A criterion
may share a test, but it may not lack an explicit test assertion and evidence link. Unknown,
untested, waived, manually assumed, or stale criteria fail the relevant gate; no score-weighted
partial credit is used internally.

## PRD Epic Traceability Matrix

| PRD story | Owning technical boundary | Primary verification |
| --- | --- | --- |
| 1.1 Working scenario | Judge Run Service, run API | isolated start/expiry/quota E2E |
| 1.2 Five-second orientation | Control Room | first-viewport visual/accessibility assertion |
| 2.1 Incident inspection | inspect tool, bounded API | schema/output/privacy/native invocation |
| 2.2 Similarity vs eligibility | Retrieval Service | full lifecycle candidate matrix |
| 2.3 Untrusted instructions | Tool annotations, exact derivation | injection eval/API negative tests |
| 3.1 Bounded proposal | propose tool, Proposal Service | exact-match/schema/idempotency tests |
| 3.2 Capability withdrawal | Registry + Workflow Policy | native withdrawal/stale callback race |
| 4.1 Exact approval | Operator API + transaction guard | digest/expiry/concurrency tests |
| 4.2 Sandbox action | Sandbox allowlist | arbitrary-input/replay/direct DB tests |
| 5.1 Independent observation | Observer + Policy | binding/immutability/policy tests |
| 5.2 Observation unavailable | workflow failure state | no-object/no-tool/retry E2E |
| 5.3 Agent assessment | assessment tool + evidence model | disagreement/mismatch/duplicate tests |
| 6.1 Reviewer handoff | Handoff/session service | single-use/expiry/distinct-subject E2E |
| 6.2 Immutable review | Governance Service | read-only evidence/disposition tests |
| 6.3 Revoke/expire | Governance Service | recall removal/successor-event tests |
| 7.1 Pending exclusion | Retrieval predicates | pending/quarantine/reject/revoke matrix |
| 7.2 Compatible recurrence | recall tool + recurrence fixture | pre/post-review recommendation E2E |
| 8.1 Capability Inspector | manifest + renderer | per-state server/UI parity test |
| 8.2 Activity Rail | Authority Ledger + projection | chronology/denial/refresh tests |
| 8.3 Authority Receipt | Receipt Exporter + verifier | valid and tampered bundle vectors |
| 9.1 Stale/concurrent recovery | CAS/idempotency/reconcile | multi-tab and parallel transaction tests |
| 9.2 Dependency failure | fail-closed adapters/gates | DB/observer/KMS/S3 fault injection |
| 9.3 Unsupported client | feature detection/no polyfill | unsupported-browser E2E |
| 10.1 Assistive completion | semantic UI/accessibility module | axe + keyboard/screen-reader protocol |
| 10.2 Both clients | WebMCP contracts/release evidence | ChatGPT and native Chrome records |
| 11.1 Fair baseline | versioned benchmark/evaluator | reproducible exact cases/counts |
| 11.2 Claim tracing | claim registry/release identity | link/digest/completeness audit |
| 11.3 Dual gates | Release Evidence Service | mismatch/stale/build-change negatives |
| 12.1 Concurrent isolation | unique tenant/run/session | parallel public-run E2E and DB probes |
| 12.2 Frozen release | deployment/evidence pipeline | submission audit against one release ID |

## Explicit Non-Goals

- Production remediation, production credentials, or production telemetry trust.
- A general workflow engine, generic agent platform, embedded chatbot, or additional WebMCP tools.
- Agent approval/execution/review/reset/policy/role authority.
- Arbitrary shell, URL fetch, log access, model-selected infrastructure target, or user-supplied
  metrics.
- Browser-automation prevention, physical-person proof, trusted external timestamp, signer
  completeness proof, or universal agent safety.
- Blockchain/transparency anchoring, post-quantum hybrid signatures, formal methods, multi-region
  signing, or a new front-end framework.
- Performance/impact claims not produced by the committed evaluation.

## Specification Acceptance Gates

This specification is ready for checklist translation only when:

- all 30 stories, 149 acceptance criteria, 16 edge cases, and 15 cross-cutting standards are
  inventoried without omission or duplicate identifiers;
- all four tool schemas, annotations, lifecycle, and server routes are explicit;
- every protected transition names its identity/role/channel/state/epoch/digest/idempotency guard;
- state, session, run, evidence, memory, ledger, receipt, and release data have an authoritative
  storage and lifecycle;
- file ownership and all critical data flows are explicit;
- current primary documentation links support version-sensitive decisions;
- error, degraded, concurrency, refresh, accessibility, two-client, and release behaviors are
  testable;
- security claims and receipt limitations remain identical in strength and scope to the PRD;
- no product feature outside the PRD has entered the required build.
