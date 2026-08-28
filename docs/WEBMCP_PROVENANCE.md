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
| 1. Native WebMCP vertical slice | Complete 2026-08-28 at `8998b9c` | `src/recallops/static/webmcp.js`; capability inspector; API security headers; 7 browser tests; native Chromium 151 test; 155 Python tests; Ruff and mypy passing |
| 2. Authoritative workflow policy | Core verified 2026-08-28 at `fa0110d`; final acceptance pending | Eight-state model; server epochs and manifests; CockroachDB CAS and retry tests; protected-channel rejection; 171 Python tests with integration; 7 browser tests; 2 native Chromium tests. Judge-session auth and atomic domain/workflow commits remain open. |
| 3. Sandbox action and evidence | Not started | Simulator and observation tests |
| 4. Review-gated recurrence | Not started | Separation-of-duties and retrieval tests |
| 5. Signed proof | Not started | JWS vectors and offline verifier |
| 6. Final evaluation/deployment | Not started | Live browser matrix, final image digest, video and submission audit |

This file records only verified work. Status and evidence links must be updated when their checks pass.

Milestone 1 is isolated in challenge-period commit
[`8998b9c`](https://github.com/milos-plavsic/recallops/commit/8998b9c). Its baseline comparison is
<https://github.com/milos-plavsic/recallops/compare/cee362c5ce3cb3bb44c63a4c1ba80b558881d21c...8998b9c>.

Milestone 2's authoritative core is isolated in challenge-period commit
[`fa0110d`](https://github.com/milos-plavsic/recallops/commit/fa0110d). Its incremental comparison is
<https://github.com/milos-plavsic/recallops/compare/8998b9c...fa0110d>. The evidence ledger keeps the
remaining acceptance work explicit rather than presenting the core increment as the final policy.
