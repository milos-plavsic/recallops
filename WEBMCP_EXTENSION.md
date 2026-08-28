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

Milestone 1 adds two native imperative tools:

- `inspect_incident`: bounded, read-only incident evidence.
- `propose_mitigation`: prepares a proposal through the existing incident API, but cannot approve or
  execute it. A successful mutating proposal withdraws this capability using `AbortController`.

Approval, sandbox execution, observation retry, review, and reset are intentionally never WebMCP
tools. The page includes a Capability Inspector and activity rail, falls back cleanly when WebMCP is
unavailable, and sends explicit origin-isolation and `tools=(self)` policy headers.

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

Milestone 1 proves native discovery, invocation, shared UI state, lifecycle withdrawal, bounded
contracts, progressive enhancement, and stale-callback rejection. It does not claim that the client
phase is the final authorization boundary. Server-authoritative epochs, channel enforcement,
sandboxed mutation, independent observation, reviewed recurrence, signed receipts, deployment, and
cross-client evaluation remain later milestones.
