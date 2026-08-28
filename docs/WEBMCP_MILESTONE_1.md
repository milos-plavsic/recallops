# Milestone 1 Acceptance Contract

**Status:** Complete and verified on 2026-08-28.

Milestone 1 proves that RecallOps is a native WebMCP website, not merely a REST application with a
planned integration.

## Required behavior

- The page feature-detects `document.modelContext` and degrades clearly when unavailable.
- `inspect_incident` is registered for the page lifetime.
- `propose_mitigation` is registered only while the page is investigating.
- Tool names, descriptions, parameter descriptions, schemas, annotations, and outputs are bounded.
- Agent-provided incident fields are validated and passed through the existing authenticated API.
- A tool-created proposal renders in the existing human console.
- Proposal creation withdraws the proposal tool and visibly transfers authority to the operator.
- Protected approval and execution endpoints remain absent from the tool surface.
- A cached proposal callback is rejected after authority has moved.
- Existing manual analysis remains functional.

## Required verification

- Browser-contract test with a WebMCP-compatible `modelContext` test double.
- Registration and annotation assertions.
- Invocation and shared-UI assertions.
- Abort-driven withdrawal and stale-callback assertions.
- Unsupported-browser status assertion.
- Existing accessibility and browser regressions.
- Python API/service regressions.
- Lint and type checks applicable to changed code.
- Runtime report for installed Chromium, explicitly distinguishing native runtime support from the
  contract test double.

## Verification record

| Check | Result |
| --- | --- |
| Python regression suite | `155 passed, 3 skipped` |
| Browser, accessibility, fallback, lifecycle, and stale-call suite | `7 passed` |
| Native WebMCP browser suite | `1 passed` |
| Ruff | Passed |
| Strict mypy | Passed; 20 source files checked |
| Whitespace/error audit | `git diff --check` passed |

The native suite ran against Chromium `151.0.7922.108` with the WebMCP feature enabled. It used the
browser's real `document.modelContext.registerTool`, `getTools`, and `executeTool` implementations to
discover both tools, invoke `propose_mitigation`, observe the shared UI update, and confirm that the
browser withdrew the tool after authority moved. Run it with:

```bash
npm run test:webmcp:native
```

`WEBMCP_CHROMIUM_PATH` may point to another Chrome 149+ executable. The ordinary Playwright suite
also supplies a deterministic API-contract harness so registration errors, annotations, unsupported
browsers, policy abstention, withdrawal, and captured stale callbacks remain reproducible in CI.

One real-browser test initially revealed that a retrieval abstention could produce a read-only
diagnostic while the client still claimed approval was required. The final implementation fails
closed: no mutating proposal is staged, authority remains in `INVESTIGATING`, and both initial tools
remain available.

## Non-claims

Milestone 1 does not claim the full eight-state workflow, protected sandbox execution, distinct judge
authentication, immutable postchecks, review-gated recall, signed receipts, or final cross-client
qualification. Those remain required by later milestones.
