# RecallOps WebMCP Extension

RecallOps is an **Existing** project. The disclosed pre-challenge baseline is
`cee362c5ce3cb3bb44c63a4c1ba80b558881d21c`, dated 2026-08-18. The WebMCP Challenge period began
2026-08-25 at 19:00 UTC.

The challenge extension turns the existing incident-memory console into an Incident Co-Control Room.
Its governing pattern, **Capability Sculpting**, makes the browser tool surface a visible function of
workflow state while server policy remains the eventual security boundary.

## Canonical project records

- [Product, architecture, state machine, security invariants, demo, and score strategy](docs/WEBMCP_CONTROL_ROOM.md)
- [Sequenced implementation milestones and score gates](docs/WEBMCP_BUILD_PLAN.md)
- [Baseline disclosure and challenge-period evidence ledger](docs/WEBMCP_PROVENANCE.md)
- [Milestone 1 acceptance contract and verification results](docs/WEBMCP_MILESTONE_1.md)

## Current implementation

The frozen native imperative surface contains exactly four tools:

- `inspect_incident`: bounded, read-only incident and candidate evidence.
- `propose_mitigation`: stages an idempotent, digest-bound proposal but cannot approve or execute it.
- `record_postcheck_assessment`: records an attributable opinion about immutable server observation;
  it cannot submit measurements or a policy verdict and creates only pending review memory.
- `recall_reviewed_memory`: reads the compatible recurrence only while a certified, admissible memory
  exists.

The server-issued capability manifest is bound to run generation, workflow epoch, memory governance
version, capability policy, and build identity. Registrations use separate lifecycle-bound
`AbortController` instances, generation-safe reconciliation, conditional polling, stale-callback
server rejection, and bounded non-authoritative activity observations. Approval, rejection, sandbox
execution, observation retry, reviewer handoff, governance, role change, policy override, and reset
are never WebMCP tools.

The independent reviewer page loads no WebMCP registration code. Reviewer authority is a distinct,
single-use, purpose-bound session, and the three evidence layers remain immutable and separately
attributed even when the agent assessment disagrees with policy. Unsupported clients receive an
honest no-fallback state.

## Reproduce Milestone 1

```bash
uv run pytest
uv run ruff check src tests
uv run mypy
npm run test:browser
npm run test:webmcp:native
```

The final command requires Chrome or Chromium 149+ with WebMCP available; set
`WEBMCP_CHROMIUM_PATH` if it is not installed at `/snap/bin/chromium`.

## Scope boundary

The extension proves native discovery and invocation, state-specific withdrawal, current
`options.signal` cancellation, rapid-manifest race convergence, post-receipt reconciliation,
server-authoritative epochs, channel enforcement, idempotent proposal/assessment transactions,
independent review, disagreement preservation, revocation withdrawal, reviewed recurrence, live KMS
receipts, credential-free S3-backed bundle download, and offline pinned-key verification. It does not
claim that browser registration is an authorization boundary, that WebMCP prevents general browser
automation, or that receipt integrity proves external truth. Native Chromium acceptance is complete;
direct ChatGPT desktop Site Tools acceptance remains a separate release gate and is never inferred.
