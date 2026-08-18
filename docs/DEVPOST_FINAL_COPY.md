# Devpost final copy

This is the paste-ready submission draft. Replace the video placeholder only after public or unlisted
playback succeeds without an account. Do not describe Bedrock as active unless the recorded status
endpoint reports it.

## Title

RecallOps — Memory That Must Earn the Right to Be Recalled

## Tagline

A governed SRE agent that remembers outcomes, rejects unsafe precedents, and proves who reviewed what.

## Links

- Live app: https://ltfrottcxj.execute-api.us-east-1.amazonaws.com
- Source: https://github.com/milos-plavsic/recallops
- Demo video: `REPLACE_WITH_PUBLIC_YOUTUBE_OR_VIMEO_URL`
- Judge evidence: https://github.com/milos-plavsic/recallops/blob/main/docs/EVIDENCE_INDEX.md

## Inspiration

Operational agents often treat vector similarity as permission. That is dangerous: the closest past
incident may belong to another tenant, target an incompatible release, or recommend an action that
made the outage worse. RecallOps starts from a stricter idea: memory is evidence, and evidence must
remain governed throughout its lifecycle.

## What it does

RecallOps analyzes an incident, retrieves semantically related operational memories, and applies
deterministic tenant, validity, compatibility, governance, and outcome controls before ranking. It
then proposes a typed action. Mutating proposals require exact-action human approval.

After an operator attests the externally performed action and records the result, RecallOps creates a
new memory in `pending_review`. That memory is excluded from future retrieval until a different
Cognito identity activates it. The next incident can then recall the same reviewed memory with its
source incident, observed outcome, and governance provenance. Revocation removes it from active
retrieval immediately while retaining the audit history.

## How we built it

CockroachDB is the persistent memory system, not a replaceable metadata store. One transactional
record connects the incident, vector candidate, decision, approval, execution attestation, outcome,
memory state, and governance event. A tenant-prefixed 1,024-dimensional vector index generates
candidates; deterministic SQL and application policy decide eligibility and rank.

The public application runs on Amazon ECS Fargate behind API Gateway and an internal load balancer.
Amazon Cognito supplies signed identity and separates operator from reviewer roles. Amazon S3 stores
encrypted, versioned evidence; CloudWatch provides logs, metrics, and server-verifiable alarm
evidence; Secrets Manager injects database credentials. Deterministic reasoning and embeddings keep
the judge path reproducible. Amazon Bedrock is supported as an optional bounded provider, but is not
required or misrepresented as active in the public demo.

We used two qualifying CockroachDB tools directly:

1. Distributed Vector Indexing, with a managed query-plan artifact that shows vector search through
   `memories_embedding_v2`.
2. The official `designing-application-transactions` Agent Skill, pinned to a reproducible revision;
   it shaped atomic incident/outbox persistence, provider calls outside transactions, and bounded
   serialization retries.

## Challenges we ran into

The hardest problem was preventing semantic retrieval from becoming an authorization bypass. We had
to align the query boundary, compatibility policy, four-eyes governance state machine, idempotency,
and audit provenance so a retry or concurrent request could not create conflicting truth. We also
kept evidence claims deliberately fail-closed: production claims require server-verifiable AWS
evidence, while local attestations are labeled as such.

## Accomplishments that we're proud of

- A complete visible store → govern → retrieve → act loop whose stable memory ID can be followed
  through the UI and CockroachDB.
- Safe abstention when no reviewed compatible success exists.
- Immediate revocation from active recall with retained history.
- Four-eyes review enforced by verified identities rather than a UI convention.
- 100% combined Python statement and branch coverage, browser accessibility tests, live CockroachDB
  boundary tests, and a safety-critical mutation-testing gate.
- Reproducible, release-stamped evidence with explicit limitations rather than inflated claims.
- An open-source CockroachDB memory-retrieval safety contribution proposed upstream, separately from
  the accepted official skill used for eligibility.

## What we learned

Agent memory needs database semantics more than it needs a larger prompt. Similarity should discover
candidates; authorization, compatibility, observed outcomes, identity, and lifecycle state should
decide whether any candidate may influence an action. We also learned that judge-facing evidence is
strongest when one causal identifier connects the product interaction, database row, audit event,
and deployment release.

## What's next

The next vertical increment is an allowlisted executor with least-privilege task roles and automatic
postcondition collection. We would also expand independent human review of retrieval decisions,
test larger managed-cluster datasets, and contribute the reusable retrieval-safety verifier through
the CockroachDB Agent Skills process.
