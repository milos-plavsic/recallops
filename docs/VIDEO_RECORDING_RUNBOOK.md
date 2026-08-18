# RecallOps video recording runbook

This is the authoritative recording-day sequence. The finished video must be under three minutes
and must show live state-changing actions rather than a slide or screenshot tour.

## Gate zero: do not record until these pass

- The deployed frontend contains `Vector candidate → POLICY SELECTED/REJECTED` labels.
- `GET /health` and `GET /ready` succeed on the public URL.
- `/v1/system/status` reports the final committed build SHA used by every proof artifact.
- Operator and reviewer Cognito accounts both sign in and expose different subjects.
- One rehearsal completes analyze → approve → attest → observe → review → analyze again.
- The CockroachDB query below returns the rehearsal memory without exposing identifiers or secrets.
- The DVI plan and Agent Skill evidence both name that same final build SHA; older-release artifacts
  are not used in the recording.
- ECS, CloudWatch, and S3 console tabs are open at safe, relevant views.
- Notifications, password prompts, bookmarks, personal tabs, and account menus are hidden.

Do not delete production data merely to obtain a clean take. Use a new incident idempotency key and
frame the newest memory row. If accumulated demo memories make the result ambiguous, record against
a freshly seeded isolated environment and label it accurately.

## Master cut: 2:52 target

The narration column is the final voice script. Record it after the screen takes are locked.

| Time | Cursor and live screen action | Final narration | Required overlay |
| --- | --- | --- | --- |
| 0:00–0:08 | Begin on the live incident form. Click **Analyze incident** by 0:06. | “For SRE teams, a similar incident is not necessarily a safe precedent. RecallOps remembers consequences.” | `RecallOps · governed operational memory` |
| 0:08–0:24 | Let the live result render. Point once to the proposed action and **Human approval required**. | “This public AWS agent retrieves persistent, tenant-scoped memory from CockroachDB, checks compatibility and outcomes, then proposes an approval-gated action.” | `LIVE · AWS + CockroachDB` |
| 0:24–0:45 | Expand **Candidate evidence**. Keep the selected and rejected candidates, their semantic and governed scores, provenance, and rejection reasons readable together. | “Vector search generates candidates; it never grants authority. A semantically close restart previously worsened the outage, so deterministic validity, compatibility, outcome, tenant, and governance controls reject it.” | `Similarity ≠ authorization` |
| 0:45–0:57 | Frame the automatically open **Replayable agent trace**. Point to tool order, sanitized evidence references, risk, attempt bound, and timeout. | “The replayable trace exposes tools, evidence references, risk, retries, and timeouts—an inspectable audit trail, not hidden chain-of-thought.” | `TRACE · evidence · risk · bounds` |
| 0:57–1:20 | Click **Approve exact action**, **Attest execution**, and **Record successful outcome**. Hold the short memory ID beside `PENDING REVIEW`. | “The operator approves the exact proposal, attests the externally performed action, and records recovery. Memory ID shown here is held pending review and remains retrieval-ineligible.” | `PENDING REVIEW · same memory ID` |
| 1:20–1:39 | Click **Switch identity**. Cut only credential entry and waiting. Resume with a visibly different subject prefix; click **Activate as reviewer** and hold the same memory ID beside `ACTIVE MEMORY`. | “A different Amazon Cognito identity performs four-eyes review. CockroachDB atomically records the reviewer, active state, and governance event before eligibility changes.” | `Cognito · independent reviewer · ACTIVE` |
| 1:39–1:59 | Click **Analyze again**, expand candidates, and frame the same short memory ID, source incident, reviewed flag, and observed outcome. | “Now the same reviewed memory appears in the next decision with its source and provenance. This visibly closes the store, govern, retrieve, and propose loop.” | `PENDING → ACTIVE → RECALLED` |
| 1:59–2:23 | In the pre-opened CockroachDB SQL Console, run the read-only memory query. Then show the redacted verified plan lines `vector search` and `memories@memories_embedding_v2`. | “The live row confirms outcome, observer, reviewer, active state, and audit event. The verified CockroachDB plan shows tenant-scoped vector search using the distributed index.” | `CRDB TOOL 1 · Distributed Vector Indexing` |
| 2:23–2:36 | Show the pinned `designing-application-transactions` skill revision beside the exact transaction consequences: atomic incident-plus-outbox, provider calls outside transactions, and bounded serialization retry. | “The pinned official CockroachDB Agent Skill directly shaped these retry-safe transaction boundaries; this split view shows the guidance and its implemented consequence.” | `CRDB TOOL 2 · Agent Skills Repo` |
| 2:36–2:47 | Use three pre-opened live views: stable ECS task, current CloudWatch signal, newest versioned S3 evidence. Keep the compact architecture inset visible. | “ECS runs the API behind API Gateway; Cognito separates identities; S3 versions evidence; and CloudWatch supplies observable, server-verifiable state.” | `AWS · ECS · API Gateway · Cognito · S3 · CloudWatch` |
| 2:47–2:52 | Return to the second analysis. Hold the recalled short memory ID and reviewed provenance completely still. | “RecallOps remembers what worked—and who proved it.” | `RecallOps` |

## Exact live click choreography

### Take A: causal memory loop

1. Start with the checkout incident prefilled and the operator already authenticated.
2. Click **Analyze incident**.
3. Wait for the loading state to disappear; do not cut away from the response arriving.
4. Expand **Candidate evidence** and hold until both policy outcomes are readable.
5. Expand **Replayable agent trace** and hold for three seconds.
6. Click **Approve exact action**; pause one second.
7. Click **Attest execution**; pause one second.
8. Click **Record successful outcome**; hold `PENDING REVIEW` for two seconds.
9. Click **Switch identity**. Stop the take before any credential is visible.
10. Resume after reviewer authentication. Preserve a short visual discontinuity so the cut is honest.
11. Click **Activate as reviewer**; hold `ACTIVE MEMORY` for two seconds.
12. Click **Analyze again** and show the same short memory ID, source incident, and reviewed flag in
    **Candidate evidence**.

Never simulate a click, replace a transition with a still frame, or imply that the execution
attestation mutated infrastructure. If network latency is shortened, preserve the loading state and
use an obvious jump cut.

### Take B: CockroachDB ground truth

Run this query live. Replace only the tenant literal when the authenticated deployment uses another
tenant. It deliberately excludes embeddings, incident payloads, secrets, and full identities.

```sql
SELECT
  left(m.id::STRING, 8) AS memory,
  m.service,
  m.state,
  m.outcome_score,
  round(m.confidence::DECIMAL, 2) AS confidence,
  CASE WHEN m.observed_by IS NULL THEN 'no' ELSE 'yes' END AS observed,
  CASE WHEN m.reviewed_by IS NULL THEN 'no' ELSE 'yes' END AS reviewed,
  e.action AS governance_event,
  m.created_at
FROM memories AS m
LEFT JOIN LATERAL (
  SELECT action
  FROM memory_events
  WHERE tenant_id = m.tenant_id AND memory_id = m.id
  ORDER BY created_at DESC
  LIMIT 1
) AS e ON true
WHERE m.tenant_id = 'demo' AND m.source_incident_id IS NOT NULL
ORDER BY m.created_at DESC
LIMIT 3;
```

Then open the latest redacted query-plan evidence and frame only these verified lines:

```text
• vector search
  table: memories@memories_embedding_v2
```

The artifact must identify its captured release and limitation: it is a managed, synthetic-row plan
whose optimizer choice may vary with cardinality and statistics. Do not show connection strings,
passwords, account email, cluster credentials, access tokens, tenant values, or embedding values.

### Take C: Agent Skill and AWS proof

The Agent Skill shot must connect a named tool to visible engineering outcomes. Frame the pinned
`designing-application-transactions` revision beside exactly three implemented consequences: atomic
incident-plus-outbox persistence, remote providers outside transactions, and bounded serialization
retry. Do not show the generic skills landing page or a long scrolling document.

Prepare these AWS console views before recording:

1. ECS service: desired and running task counts match; deployment is stable.
2. CloudWatch: a current RecallOps log event or relevant alarm state with no sensitive payload.
3. S3: the newest RecallOps evidence object, versioning indicator, and timestamp; hide account data.

API Gateway and Cognito are already demonstrated through the public endpoint and identity switch;
name them in the overlay rather than spending separate console cuts on them.

## Overlay file

Use a single typeface, one lower-third position, and no more than two lines. Each overlay remains for
at least two seconds.

```text
RecallOps · governed operational memory
LIVE · AWS + CockroachDB
Similarity ≠ authorization
TRACE · evidence · risk · bounds
PENDING REVIEW · same memory ID
Cognito · independent reviewer · ACTIVE
PENDING → ACTIVE → RECALLED
CRDB TOOL 1 · Distributed Vector Indexing
CRDB TOOL 2 · Agent Skills Repo
AWS · ECS · API Gateway · Cognito · S3 · CloudWatch
```

## Editing and audio specification

- Capture 1920×1080 at 30 fps; export H.264 at 1080p with AAC audio.
- Keep browser zoom between 110% and 125% and verify that candidate reasons do not clip.
- Use a gentle, clear female voice at approximately 120–130 words per minute while speaking. Leave
  deliberate silence for state changes and proof holds. Aim for calm authority,
  not advertising enthusiasm or sensual delivery.
- Record narration separately after picture lock. Duck or omit music; UI clicks need not be audible.
- Burn in accurate captions and manually correct `CockroachDB`, `Cognito`, `idempotency`, and `SRE`.
- Use hard cuts. Avoid animated transitions, stock footage, fake terminal typing, and title sequences.
- Freeze the final frame for one second; do not add a long credits screen.

## Failure-safe recording strategy

Record separate takes so one external console failure does not ruin the causal loop:

- Take A1: operator through `PENDING REVIEW`.
- Take A2: reviewer activation through second analysis.
- Take B: CockroachDB query and index.
- Take C1: Agent Skill evidence.
- Take C2: AWS service proof.
- Take D: optional live abstention.

The A1/A2 authentication cut is permitted; no other state transition should be reconstructed from
unrelated runs. Retain the raw recordings until the public upload is verified.

## Final acceptance test

- [ ] The first live action occurs by 0:07.
- [ ] A viewer can explain why the highest-similarity memory may be rejected.
- [ ] Approval, execution attestation, outcome capture, pending-review hold, independent review, and recall
      are all visibly performed.
- [ ] The language makes clear that execution is an attestation, not an infrastructure mutation.
- [ ] Before review, the new memory is visibly marked retrieval-ineligible; after review, the same
      short ID is visibly eligible and recalled.
- [ ] One stable short memory ID visibly connects pending, active, recalled, and SQL states.
- [ ] The CockroachDB row is queried live and the captured managed plan visibly proves DVI use.
- [ ] Both required CockroachDB tools are named and their actual use is explained.
- [ ] The AWS deployment and each claimed AWS service have visible, truthful evidence.
- [ ] Bedrock is called optional unless the recorded runtime actually uses it.
- [ ] No secret, email address, account number, token, password, or connection string is visible.
- [ ] Captions are accurate, the voice is intelligible, and every text proof is readable at 1080p.
- [ ] Duration is no more than 2:54, with the planned 2:52 cut leaving editing margin.
- [ ] YouTube or Vimeo playback works without signing in and the Devpost URL opens correctly.
