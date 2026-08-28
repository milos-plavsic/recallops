# WebMCP Challenge Provenance

## Submission classification

RecallOps is an **Existing** project. Its incident-memory, retrieval, approval, execution-attestation,
outcome, review, AWS, CockroachDB, evaluation, and original judge-console functionality predate The
WebMCP Challenge submission period.

## Disclosed baseline

- Commit: `cee362c5ce3cb3bb44c63a4c1ba80b558881d21c`
- Commit date: 2026-08-18T18:48:20+02:00
- Challenge submission period start: 2026-08-25T19:00:00Z

The baseline must remain in repository history. The final submission will link the GitHub comparison
from this commit to the deployed final commit.

## Challenge-period work

Only additions after the challenge start are submitted for WebMCP judging. The planned challenge
extension comprises:

- Native `document.modelContext` tools.
- Capability Sculpting and visible tool lifecycle.
- Server-authoritative WebMCP workflow policy and stale-call rejection.
- Safe sandbox mutation and independent postcheck measurement.
- Separate agent assessment and deterministic policy verdict.
- Review-gated positive and negative memory recurrence.
- Complete signed Authority Receipt and offline policy verifier.
- WebMCP-specific evaluations and intended-browser test evidence.
- Updated deployment, documentation, video, and submission materials.

## Milestone evidence ledger

| Milestone | Status | Evidence |
| --- | --- | --- |
| 1. Native WebMCP vertical slice | Complete 2026-08-28 | `src/recallops/static/webmcp.js`; capability inspector; API security headers; 7 browser tests; native Chromium 151 test; 155 Python tests; Ruff and mypy passing |
| 2. Authoritative workflow policy | Not started | State/authorization tests and API contracts |
| 3. Sandbox action and evidence | Not started | Simulator and observation tests |
| 4. Review-gated recurrence | Not started | Separation-of-duties and retrieval tests |
| 5. Signed proof | Not started | JWS vectors and offline verifier |
| 6. Final evaluation/deployment | Not started | Live browser matrix, final image digest, video and submission audit |

This file records only verified work. Status and evidence links must be updated when their checks pass.

At the time Milestone 1 was completed, its changes were present in the working tree and had not yet
been committed. A dated challenge-period commit and baseline comparison URL must be added here before
submission; this statement intentionally avoids presenting uncommitted work as repository history.
