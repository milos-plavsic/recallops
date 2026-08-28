# WebMCP Milestone 3 acceptance record

## Outcome

RecallOps now closes the proposal-to-evidence loop without granting protected authority to the
agent. An authenticated operator applies one exact, digest-bound action to an isolated deterministic
checkout simulator. A separate system authority collects immutable measurements and computes a
versioned verdict. Only then does the agent receive `record_postcheck_assessment`; its bounded,
attributable opinion is stored separately and can create only a `pending_review` memory.

This is a simulator mutation, not a production infrastructure action. The legacy manual execution
and outcome endpoints return `410 Gone` in judge mode, so judge sessions cannot bypass verified
evidence with operator-supplied measurements.

## Security invariants

- The simulator accepts one allowlisted action identifier and exact command digest. It never invokes
  a shell or interprets arbitrary agent text.
- Operator approval, sandbox execution, and observation retry require an authenticated operator,
  exact Origin and CSRF token in judge mode, UI channel, tenant, actor, workflow state, epoch, and
  proposal hash.
- Approval is persisted against the exact 64-hex proposal digest and cannot be overwritten.
- Execution, observation, policy verdict, and assessment rows are insert-only for the API database
  role. Replays must match their immutable binding or fail.
- Observation binds tenant, incident, execution ID, proposal hash, execution digest, metrics,
  source, window, and observation digest.
- The deterministic policy verdict—not agent opinion—sets memory outcome semantics. Agreement and
  disagreement remain visible; neither makes memory retrievable before independent review.
- Observation collection failure exposes no assessment tool and creates no observation or memory.
  Retry reuses the recorded execution and cannot repeat the simulator mutation.
- Every authority-bearing domain write and state transition shares one serializable transaction.
  Stale epochs and concurrent state changes fail closed.

## User-visible proof

The control room renders before/after simulator metrics, the independent policy verdict, the current
server capability set, withheld-tool reasons, and chronological agent/human/system activity. Native
WebMCP registration follows server state through lifecycle-bound `AbortController` registrations.
The assessment tool appears only in `POSTCHECK_READY` and is withdrawn after successful recording.

## Verification record

The final acceptance run must use the milestone commit and is recorded in
[`WEBMCP_PROVENANCE.md`](WEBMCP_PROVENANCE.md). The gate includes:

- strict Ruff and mypy checks over tracked source and tests;
- branch-aware Python coverage, including real CockroachDB migrations/integration and direct grant,
  foreign-key, and forbidden-operation probes, with a 100% threshold;
- deterministic unit and HTTP tests for allowlisting, digest binding, disagreement preservation,
  retry-without-reexecution, storage conflicts, stale epochs, wrong channels, and dependency/state
  races;
- Playwright judge-flow and accessibility checks;
- native Chromium WebMCP discovery, invocation, registration, withdrawal, and stale-callback checks.

Acceptance results on 2026-08-29: 196 Python tests passed (8 database tests skipped until the real
database phase), all 8 real CockroachDB integration tests then passed, branch-aware coverage reached
100%, all 8 Playwright judge-flow/accessibility tests passed, and all 3 native Chromium WebMCP tests
passed. The direct database verifier on CockroachDB CCL v26.2.1 confirmed 32 exact runtime grants,
11 composite cross-tenant relationship rejections, 17 forbidden runtime operations, and the
integration suite separately rejected a same-tenant cross-incident evidence rebind.

## Standards basis

The implementation follows the WebMCP imperative lifecycle model, OWASP transaction-authorization
guidance for server-side state sequencing and exact significant-data binding, OWASP CSRF guidance
for synchronizer tokens plus Origin validation, and CockroachDB whole-transaction retry guidance for
its default serializable isolation. These references justify design choices; the executable tests
and database probes prove this implementation.
