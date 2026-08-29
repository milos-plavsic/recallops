# WebMCP Challenge Build Plan

## Priority

Security and functionality come first, followed by independent proof and judge-visible clarity.
Every addition must close a documented threat, have automated verification, and materially improve
one of the four judging criteria without putting the live demonstration at risk.

Judge-visible live proof and independently reproducible assurance are separate 100% completion
gates, not an effort tradeoff. Every material claim must work in the deployed judge path and map to
a build-bound test, trace, or verification artifact. Submission readiness requires both gates.

## Milestone 1: native WebMCP vertical slice

**Status: complete and verified on 2026-08-28.** See
[`WEBMCP_MILESTONE_1.md`](WEBMCP_MILESTONE_1.md) for the acceptance and browser evidence record.

Deliver the smallest real browser-agent loop before expanding the backend:

- Register `inspect_incident` for the page lifetime.
- Register `propose_mitigation` only while investigating.
- Add correct read-only and untrusted-content annotations.
- Keep schemas and returned data bounded.
- Route proposal execution through the existing authenticated incident API.
- Render agent results into the same console used by a human.
- Withdraw proposal capability after proposal creation.
- Display current capabilities and lifecycle events.
- Preserve existing non-WebMCP operation as a fallback.
- Verify registration, invocation, UI synchronization, withdrawal, stale callback rejection,
  unsupported-browser behavior, accessibility, and current regression tests.
- Record the pre-challenge baseline and post-start change provenance.

Milestone 1 deliberately reuses current incident idempotency and protected approval endpoints. The
full workflow epoch and channel authorization model is Milestone 2 and must replace the temporary
client-side phase guard before protected sandbox execution is introduced.

## Milestone 2: authoritative workflow policy

**Status: complete and verified on 2026-08-28.** Server-issued judge sessions and atomic
authority-bearing CockroachDB transactions complete the authoritative core. See
[`WEBMCP_MILESTONE_2.md`](WEBMCP_MILESTONE_2.md).

- Add the eight-state workflow and monotonic epoch.
- Derive tool capability manifests from server state.
- Validate state, epoch, tenant, channel, identity, and idempotency atomically.
- Reject protected transitions from the WebMCP channel.
- Add scoped operator/reviewer demo identities and safe reset.
- Test cancellation races and stale calls against the real server.

The implementation includes the state model, server capability manifest, compare-and-swap epochs,
browser reconciliation, safe reset invalidation, bounded CockroachDB retries, short-lived judge
sessions, CSRF and Origin enforcement, and one transaction boundary for every authority-bearing
domain mutation plus workflow transition. Development header authentication remains clearly
separate from judge mode and is not used as identity proof.

## Milestone 3: sandbox action and evidence

**Status: complete and verified on 2026-08-29.** See
[`WEBMCP_MILESTONE_3.md`](WEBMCP_MILESTONE_3.md).

- Add an allowlisted checkout simulator mutation.
- Bind operator approval to the exact proposal digest.
- Collect independent deterministic telemetry.
- Preserve immutable observation, agent assessment, and policy verdict separately.
- Add observation-unavailable and invalid-assessment failure paths.

## Milestone 4: review-gated recurrence

- Enforce different operator and reviewer subjects.
- Review positive, negative, and unusable outcomes.
- Expose recall only for reviewed evidence.
- Demonstrate a later compatible recurrence using the newly reviewed successful evidence.
- Preserve reviewed negative evidence and agent-policy disagreement as secondary evaluation paths.

## Milestone 5: signed proof

- Append and hash every authority-bearing event transactionally.
- Build the compact canonical manifest and complete evidence bundle.
- Sign with AWS KMS Ed25519 JWS.
- Publish a pinned public JWK, offline policy verifier, and positive/tampered vectors.
- Bind source commit, deployed image digest, and evaluation version.

## Milestone 6: evaluation, deployment, and submission proof

- Run WebMCP prompt, tool, state, journey, failure, and browser evaluations.
- Regenerate existing SBOM, deployment, and supply-chain evidence for the final image.
- Test the live deployment in ChatGPT's in-app browser and the permitted Chrome configuration.
- Record the sub-three-minute video from the final deployment.
- Complete the submission with an Existing-project disclosure and baseline-to-final comparison.

## Score gates

### WebMCP Leverage

Native tools, shared UI state, state-dependent discovery, lifecycle cancellation, annotations, and
real cross-client evaluations must all be visible and reproducible.

### Execution

The public judge path must require no setup beyond the supplied bootstrap links, survive reset and
refresh, explain errors, and produce the same result repeatedly.

### Potential Impact

Committed evaluations must show an attractive unsafe baseline decision being prevented and newly
reviewed successful evidence improving a later compatible incident. Secondary cases must prove that
reviewed failures penalize unsafe reuse. Only measured results may be published.

### Creativity and Ambition

Capability Sculpting, visible authority handoff, disagreement-preserving evidence, and a
policy-verifying signed receipt must form one coherent workflow rather than separate features.
