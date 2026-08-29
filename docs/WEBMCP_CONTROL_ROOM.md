# RecallOps Incident Co-Control Room

## Product thesis

RecallOps demonstrates **Capability Sculpting**: a WebMCP pattern in which a website changes
its agent-facing capabilities as protected authority moves between the agent, application
policy, authenticated operator, measurement system, and independent reviewer.

The product does not rely on agent self-restraint for protected transitions. The agent may
investigate, propose, and assess. Operator approval, sandbox execution, evidence certification,
and reset remain server-authorized UI operations and are never WebMCP tools.

## Why WebMCP is essential

The browser page and visiting agent share one incident state. Agent tool calls update the same
interface the operator sees; protected human actions change the tools the agent can discover.
The UI makes each authority handoff visible through a capability inspector and chronological
activity rail.

Browser registration is least-authority defense in depth, not the final authorization boundary.
Every state-changing request must also be authorized from authenticated identity, tenant,
workflow state, epoch, channel, proposal or observation digest, and idempotency key on the server.

## Judge scenario

One scenario contains two occurrences:

1. `checkout-latency-42` produces governed evidence.
2. `checkout-latency-43` is a later compatible recurrence that proves safe reuse.

The initial incident includes a highly similar but version-incompatible known failure. RecallOps
rejects it before ranking, stages a bounded allowlisted mitigation, and withdraws proposal ability
while the operator owns the decision. A sandbox mutation produces independent telemetry. The agent
records an attributable assessment, deterministic policy records its own verdict, and the memory
remains unavailable until a different reviewer certifies it. Reviewed failures become negative
evidence; inconclusive evidence remains quarantined.

## WebMCP tool surface

Tool and parameter names remain short, descriptions and outputs are bounded, and external incident
content is marked untrusted.

### `inspect_incident`

- Page-lifetime, read-only tool.
- Returns a bounded incident, workflow, authority, and capability snapshot.
- Does not return credentials, unrestricted logs, or raw embeddings.
- Uses `readOnlyHint: true` and `untrustedContentHint: true`.

### `propose_mitigation`

- Available only while the workflow is `INVESTIGATING`.
- Accepts a bounded service, version, symptom, and optional rationale.
- Creates a proposal only; it cannot approve or apply the mitigation.
- Uses an internally attached workflow context and idempotency key.
- Is withdrawn after proposal creation.

### `record_postcheck_assessment`

- Available only in `POSTCHECK_READY` after a server-issued observation exists.
- Accepts a bounded classification and rationale; workflow and observation bindings are internal.
- Stores agent opinion separately from immutable measurement and deterministic policy verdict.
- Cannot activate memory.

### `recall_reviewed_memory`

- Available only after review.
- Returns policy-filtered positive or negative evidence for a compatible recurrence.
- Never returns pending, quarantined, invalid, revoked, expired, cross-tenant, or incompatible memory.
- Is read-only and marks returned historical/external text as untrusted.

## Protected operations

These operations are absent from the WebMCP surface and rejected by their server endpoints when the
request channel is WebMCP:

- Approve or reject proposal.
- Apply allowlisted sandbox mitigation.
- Retry observation collection.
- Certify, quarantine, or reject evidence.
- Reset the judge scenario.

Operator and reviewer subjects must differ. The server derives subject, tenant, role, channel, and
policy version rather than accepting them from agent arguments.

## Authoritative state machine

| State | Registered WebMCP tools | Transition authority |
| --- | --- | --- |
| `INVESTIGATING` | inspect, propose | Agent may submit a bounded proposal |
| `AWAITING_OPERATOR_APPROVAL` | inspect | Operator UI only |
| `APPROVED_AWAITING_EXECUTION` | inspect | Operator UI applies sandbox mitigation |
| `OBSERVING_POSTCHECK` | inspect | Measurement system only |
| `POSTCHECK_READY` | inspect, assess | Agent may record attributable opinion |
| `POSTCHECK_UNAVAILABLE` | inspect | Operator UI may retry or reset |
| `PENDING_REVIEW` | inspect | Reviewer UI only |
| `REVIEWED` | inspect, recall | Governed retrieval only |

Each state change advances a monotonically increasing workflow epoch. Mutations use atomic
compare-and-swap predicates and unique `(workflow_id, epoch)` and `(workflow_id, idempotency_key)`
constraints. A stale browser registration can therefore never authorize a stale server mutation.

## Evidence model

The system preserves three separate objects:

1. **Immutable observation**: measurements bound to workflow, proposal, sandbox execution,
   provider version, collection time, and digest.
2. **Agent assessment**: attributable bounded opinion bound to the observation digest.
3. **Policy verdict**: deterministic result from a versioned policy over the same observation.

Agreement and disagreement are retained. The policy verdict controls positive or negative outcome
semantics; review controls retrievability. Neither agreement nor disagreement bypasses review.

## Capability inspector and activity rail

The inspector shows the server state, authority owner, currently discoverable tools, withheld tools
with reasons, and protected operations that are never tools. The activity rail records calls,
state transitions, registration and withdrawal, protected human actions, observations, policy
verdicts, and review outcomes. It never presents client-side visibility as proof of server authority.

## Sandbox execution

The submission performs no production infrastructure mutation. The operator applies an allowlisted
action to a deterministic checkout simulator. The simulator changes real server-side state, and a
separate telemetry component measures the result. The UI labels this boundary prominently.

## Authentication

Judges receive separate operator and reviewer bootstrap links in judge-only testing instructions.
Each fragment code is exchanged once for a short-lived opaque `Secure`, `HttpOnly`, `SameSite=Strict`,
`__Host-` session cookie and removed from history. Only code hashes are stored. Reset rotates the
workflow and invalidates old workflow nonces and action hashes while stable judge bootstrap links
remain usable through judging.

Protected requests require CSRF tokens and Origin validation. Direct API requests without the
proper subject, role, tenant, state, epoch, and channel fail closed.

## Verifiable Authority Receipt

A compact RFC 8785-canonical manifest is signed as JWS with an AWS KMS asymmetric Ed25519 key. The
manifest binds the event-chain head, capability policy, ordered epochs, actor subjects and roles,
proposal, execution, observation, assessment, verdict, final disposition, source commit, deployed
image digest, and evaluation version. The complete event list is distributed beside it.

The public JWK is pinned in the offline verifier and identified by its RFC 7638 thumbprint. The
verifier checks signature, event chain, legal transitions, monotonic epochs, allowed tool sets,
channel authorization, subject separation, evidence bindings, and final disposition. Positive and
tampered fixed vectors are published.

The receipt proves that the signing key authenticated the supplied manifest and that its supplied
event chain satisfies the named policy. It does not prove physical human presence, external time or
measurement truth, completeness against a compromised signer, or arbitrary browser behavior.

## Security and failure invariants

- Browser tool withdrawal is backed by server state and epoch validation.
- Cancellation never claims transactional rollback; status is reconciled after aborted mutations.
- Protected endpoints reject WebMCP-channel requests.
- Cross-tenant, cross-workflow, stale, replayed, and mismatched evidence fails closed.
- Missing observations expose no assessment tool and create no memory.
- Invalid assessment calls create no memory.
- Reset creates a new workflow identity and invalidates stale capabilities.
- Tool outputs are concise, structured, and free of secrets.
- External and historical text is treated as untrusted content.

## Evaluation strategy

Evaluation covers state/tool conformance, tool choice and arguments, complete journeys, cancellation
races, stale calls, idempotency, authorization bypass, cross-tenant isolation, observation bindings,
assessment-policy disagreement, review gating, signed-receipt tampering, refresh at every state, and
both intended browser clients. Raw prompts, outputs, failures, browser versions, dates, dataset and
policy versions, source commit, and generation commands accompany summarized results.

## Three-minute story

1. Agent inspects and proposes while the UI shows the live capability set.
2. Proposal ability disappears; operator approves and applies the sandbox mitigation.
3. Telemetry produces a bound observation; assessment ability appears.
4. Agent assessment and independent policy verdict are shown separately.
5. Memory stays unavailable until a distinct reviewer certifies it.
6. A compatible recurrence uses the newly reviewed successful evidence; secondary evaluations show
   reviewed failures penalizing unsafe reuse.
7. Two compact fail-closed results and the offline receipt verifier provide supporting proof.

Closing line: **Similarity can discover experience. Only reviewed evidence earns authority.**

## Scope discipline

The build favors native WebMCP reliability, coherent product experience, security properties, and
judge-visible evidence. It does not add production mutations, blockchain anchoring, post-quantum
hybrid signatures, formal verification, multi-region signing, extra tools, or unrelated supply-chain
machinery unless the core experience is complete and verified first.
