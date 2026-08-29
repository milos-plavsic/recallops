# RecallOps Hackathon Scope

## Project Name Candidates

1. **RecallOps — The Incident Co-Control Room** (selected)
2. RecallOps — Governed Operational Memory
3. RecallOps — Capability-Sculpted Incident Response

## One-Line Summary

RecallOps is a WebMCP incident co-control room that lets an agent investigate, prepare, assess,
and recall evidence while the website continuously withholds protected authority until an
authenticated operator, measurement system, or independent reviewer owns the next transition.

## Target User

The primary user is an SRE or incident commander who wants agent assistance without allowing an
agent to authorize remediation or silently turn unverified experience into future operational
authority. The secondary user is the independent reviewer responsible for certifying whether a
measured outcome may influence later incidents.

## Problem

Incident agents can retrieve semantically similar history and prepare plausible actions, but
similarity is not proof of compatibility or safety. A known failure can rank above a compatible
success, and an unreviewed outcome can become self-reinforcing memory. Prompted self-restraint is
not an authorization boundary. Agent-native operational sites need a server-enforced way to change
the agent's capabilities as workflow authority moves between participants, while retaining evidence
that the handoffs and bindings were valid.

## Core Workflow

1. The agent inspects `checkout-latency-42` and sees a bounded, untrusted incident summary.
2. Policy rejects an attractive but version-incompatible known failure before ranking eligible
   evidence.
3. The agent stages one exact allowlisted sandbox mitigation. The proposal tool is withdrawn and
   the authenticated operator becomes the authority owner.
4. The operator approves the exact proposal digest and applies it to an isolated server-side
   checkout sandbox. A separate system component measures the result.
5. Only after an immutable observation exists does the agent receive the assessment tool. Agent
   opinion and the independent versioned policy verdict remain separate, including disagreements.
6. The resulting memory remains unavailable until a different authenticated reviewer certifies or
   rejects it.
7. A later compatible recurrence, `checkout-latency-43`, proves that only reviewed positive or
   negative evidence affects recall.
8. The interface exposes the current capability set and chronological authority handoffs; an
   offline verifier checks the signed authority receipt and complete event chain.

## What We Are Building

### Dual-proof completion standard

Live proof and independent assurance are not competing percentages. They are two separate 100%
completion gates. Every material claim must be observable in the deployed judge path and backed by
a reproducible test, trace, or verification artifact. A polished interface cannot compensate for
weak assurance, and a rigorous artifact cannot compensate for a weak or inaccessible live product.
Work is sequenced by dependency and submission risk, not by reducing either acceptance threshold.

### Judge-visible product path — 100% required

- One deterministic, resettable incident scenario spanning governed learning and later recurrence.
- Four bounded WebMCP tools: `inspect_incident`, `propose_mitigation`,
  `record_postcheck_assessment`, and `recall_reviewed_memory`.
- An eight-state, server-authoritative workflow with monotonic epochs, atomic state transitions,
  idempotency, stale-call rejection, and lifecycle-bound browser registration cancellation.
- Distinct pre-provisioned operator and reviewer judge identities with short-lived secure sessions,
  CSRF and Origin enforcement, tenant isolation, exact digest binding, and separation of duties.
- A real server-side mutation in an isolated checkout sandbox through an exact allowlist—never a
  fake UI transition, production mutation, or arbitrary command facility.
- Immutable observation, attributable agent assessment, and deterministic policy verdict as three
  separately bound evidence layers.
- Review-gated positive and negative memory, with pending, incompatible, revoked, expired, and
  cross-tenant evidence excluded from retrieval.
- A capability inspector and activity rail that show what the agent can discover, what has been
  withdrawn, who owns authority, and why—without treating UI display as the authorization proof.
- A polished public HTTPS path requiring no signup, manual identifiers, terminal commands, or
  hidden setup, verified in both ChatGPT's in-app browser and native Chrome WebMCP.

### Independent assurance — 100% required

- A complete append-only authority event chain and compact RFC 8785-canonical receipt manifest.
- An Ed25519 JWS signature from an asymmetric managed key, pinned public JWK, offline verifier, and
  positive plus tampered fixed vectors.
- Verification of legal transitions, monotonic epochs, tool sets, channels, actor roles, separation
  of duties, proposal/execution/observation bindings, final disposition, source commit, deployed
  image digest, and evaluation version.
- State/tool conformance, authorization bypass, cross-tenant isolation, replay, cancellation race,
  refresh, idempotency, unavailable-observation, invalid-assessment, disagreement, review-gating,
  and tamper tests.
- Reproducible evaluation artifacts containing raw cases and failures, environment and browser
  versions, dataset and policy versions, source commit, commands, and measured summaries.
- Clear existing-project provenance identifying the pre-August-25 baseline and only the new WebMCP
  work judges should evaluate.

## What We Are Not Building

- Production infrastructure remediation or credentials.
- A generic agent platform, broad chatbot, multi-service incident suite, or more than the four
  workflow tools.
- Agent-accessible approval, sandbox execution, observation retry, review, role switching, policy
  override, or reset operations.
- Operator-entered measurements or claims that a simulator proves production-remediation safety.
- Browser-automation prevention, physical-human-presence proof, trusted external time, or claims
  that a signed receipt proves truth against a compromised signer.
- Blockchain anchoring, post-quantum hybrid signatures, formal verification, multi-region signing,
  or unrelated supply-chain machinery before the scored product path is complete.
- Visual flourishes, additional scenarios, or artifacts that weaken live reliability or cannot be
  shown or verified by judges.

## Inspiration and References

- The WebMCP Challenge's official rules, submission requirements, resources, and four equally
  scored judging criteria: WebMCP Leverage, Execution, Potential Impact, and Creativity & Ambition.
- WebMCP's imperative tool lifecycle, annotations, shared page state, cancellation, secure-tool,
  evaluation, and Chrome DevTools guidance.
- OWASP guidance for transaction authorization, significant-data binding, session security, CSRF,
  access control, and fail-closed design.
- CockroachDB serializable transactions, whole-transaction retries, constraints, and least-privilege
  database roles.
- RFC 8785 JSON Canonicalization, RFC 7515 JWS, RFC 8032 Ed25519, and RFC 7638 JWK thumbprints.

Primary references and the precise claims they support remain recorded in the repository threat
model, architecture, provenance, milestone acceptance records, and evidence index.

## Demo Path

The public video and live judge path use one story and show the product working in the first 10–15
seconds:

1. Show `checkout-latency-42`, the current tool set, and the dangerous high-similarity memory that
   policy rejects.
2. Let the agent inspect and propose. Show proposal withdrawal and human authority transfer.
3. Approve the exact digest and apply the allowlisted sandbox mutation. Show independently measured
   before/after telemetry.
4. Let the agent assess the bound observation. Show its opinion beside the policy verdict and the
   memory quarantined pending review.
5. Use the distinct reviewer identity to certify it. Emphasize that review never appears as a tool.
6. Open `checkout-latency-43` and show the newly reviewed negative or positive evidence changing
   the safe recommendation.
7. Close with two compact fail-closed results and a successful offline receipt verification. Keep
   code, provenance, and broader evaluation details in linked evidence rather than rushing them into
   the main narrative.

## Submission Story

### WebMCP Leverage

WebMCP is the product mechanism, not a wrapper: the page and visiting agent operate on the same
incident state, and authoritative state changes alter tool discovery through actual registration
and cancellation. Server-side epoch and authorization checks ensure that withdrawn or stale tools
cannot retain authority.

### Execution

The submission is a coherent, public, deterministic product with a short no-signup judge path,
clear loading and failure states, reset and refresh safety, authenticated separation of duties, and
repeatable behavior in both required browser clients.

### Potential Impact

RecallOps demonstrates a specific preventable harm: similarity-only retrieval selects a known
failed, incompatible action, while governed policy rejects it and prevents unreviewed outcomes from
becoming future authority. A later recurrence proves reviewed organizational learning. Only measured
evaluation results will appear in the final claims.

### Creativity and Ambition

**Capability Sculpting** is a memorable agent-native website pattern: capability is a function of
authoritative workflow state, not an agent promise. Visible authority handoffs, disagreement-
preserving evidence, review-gated recall, and a policy-verifying signed receipt form one causal
story rather than a collection of features.

The closing thesis is: **Similarity can discover experience. Only reviewed evidence earns
authority.**

## Scope Acceptance Gates

The scope is complete only when both `LIVE_PROOF_COMPLETE` and `ASSURANCE_COMPLETE` are true. All
of the following conditions are mandatory:

- The four tools and protected UI-only transitions are enforced by the server and visible in the
  live interface.
- The complete two-occurrence path works repeatedly after reset and refresh in both target clients.
- Reviewed evidence changes recurrence behavior; pending or ineligible evidence never does.
- Observation failure and stale or mismatched assessment fail closed without creating memory.
- A distinct reviewer is required and direct unauthorized requests fail.
- The signed receipt verifies offline, and tampering with every material binding is rejected.
- Published impact numbers are generated from committed tests, never hardcoded assertions.
- The public URL, sub-three-minute video, public licensed repository, tested-client disclosure, and
  existing-project provenance satisfy every official submission requirement.
- Every scored claim in the live experience links to its assurance evidence, and every assurance
  artifact identifies the deployed build, workflow, policy, and source revision it verifies.
