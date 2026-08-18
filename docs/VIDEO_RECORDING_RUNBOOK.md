# RecallOps video recording runbook

This is the authoritative recording-day sequence. The finished video must be under three minutes
and must show live state-changing actions rather than a slide or screenshot tour.

## Gate zero: do not record until these pass

- The deployed frontend contains `Vector candidate → POLICY SELECTED/REJECTED` labels.
- `GET /health` and `GET /ready` succeed on the public URL.
- Operator and reviewer Cognito accounts both sign in and expose different subjects.
- One rehearsal completes analyze → approve → attest → observe → review → analyze again.
- The CockroachDB query below returns the rehearsal memory without exposing identifiers or secrets.
- ECS, CloudWatch, and S3 console tabs are open at safe, relevant views.
- Notifications, password prompts, bookmarks, personal tabs, and account menus are hidden.

Do not delete production data merely to obtain a clean take. Use a new incident idempotency key and
frame the newest memory row. If accumulated demo memories make the result ambiguous, record against
a freshly seeded isolated environment and label it accurately.

## Master cut: 2:57 target

The narration column is the final voice script. Record it after the screen takes are locked.

| Time | Cursor and live screen action | Final narration | Required overlay |
| --- | --- | --- | --- |
| 0:00–0:10 | Begin on the live incident form. Click **Analyze incident** by 0:07. | “For an SRE team, the most similar incident is not always a safe precedent. RecallOps remembers consequences—not just similarity.” | `RecallOps · governed operational memory` |
| 0:10–0:26 | Let the live result render. Point once to the proposed action and **Human approval required**. | “This live agent retrieves tenant-scoped memory from CockroachDB, checks operational compatibility and observed outcomes, and proposes a bounded action that still requires human approval.” | `LIVE · public AWS deployment` |
| 0:26–0:48 | Expand **Candidate evidence**. Frame one rejected dangerous candidate and the selected successful candidate together. | “Vector search generates candidates; it never grants authority. The closest-looking restart previously worsened an outage, so deterministic tenant, validity, compatibility, outcome, and governance controls reject it in favor of reviewed evidence.” | `Similarity ≠ authorization` |
| 0:48–0:59 | Expand **Replayable agent trace**. Point to tool order, evidence reference, risk, attempt bound, and timeout. | “The trace shows the tools used, evidence consulted, risk classification, and bounded failure behavior. The reasoning provider cannot bypass these controls.” | `Inspectable trace · not chain-of-thought` |
| 0:59–1:20 | Click **Approve exact action**, **Attest execution**, and **Record successful outcome**. Pause on `PENDING REVIEW`. | “The operator approves the exact action, attests execution, and records the observed recovery. But the agent cannot declare its own advice successful. The new memory is quarantined and excluded from retrieval.” | `PENDING REVIEW · retrieval-ineligible` |
| 1:20–1:37 | Click **Switch identity**. Cut only credential entry and waiting. Resume as reviewer; click **Activate as reviewer**. Pause on `ACTIVE MEMORY`. | “A different Cognito identity performs four-eyes review. CockroachDB atomically records the reviewer and governance transition before the evidence becomes eligible.” | `Amazon Cognito · independent reviewer` |
| 1:37–1:56 | Click **Analyze again**, expand candidates, and frame the newly active memory participating in the decision. | “Now—and only now—the reviewed outcome informs the next incident. This is the complete store, govern, retrieve, and act memory loop.” | `ACTIVE → recalled in next decision` |
| 1:56–2:17 | Cut to the pre-opened CockroachDB SQL Console. Press **Run** on the read-only memory query; then run `SHOW INDEXES FROM memories`. | “This is the underlying record: outcome, observer, reviewer, active state, and audit event in one transactional system. The 1,024-dimensional embedding is searched with CockroachDB Distributed Vector Indexing.” | `CRDB TOOL 1 · Distributed Vector Indexing` |
| 2:17–2:28 | Show the pinned Agent Skill evidence and the corresponding transaction boundary together, preferably in a terminal or repository split view with no scrolling. | “The official transaction-design Agent Skill shaped the retry-safe incident, outcome, and governance boundaries used by the agent.” | `CRDB TOOL 2 · Agent Skills Repo` |
| 2:28–2:45 | Fast live cuts: healthy ECS task, current CloudWatch log or alarm, then the newest versioned S3 evidence object. | “On AWS, ECS runs the service behind API Gateway, Cognito separates roles, S3 archives versioned evidence, and CloudWatch provides observability and server-verifiable alarm state.” | `ECS · API Gateway · Cognito · S3 · CloudWatch` |
| 2:45–2:52 | Return to the rejected candidate or a rehearsed live abstention with action controls disabled. | “When no safe precedent exists, RecallOps abstains. Similarity can never authorize an action.” | `SAFE FAILURE · abstain` |
| 2:52–2:57 | Return to the second analysis with the active recalled memory visible. Hold still. | “RecallOps remembers what worked, who proved it, and when it is safe to use again.” | `RecallOps` |

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
12. Click **Analyze again** and show the newly active memory in **Candidate evidence**.

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

Then run:

```sql
SHOW INDEXES FROM memories;
```

Frame `memories_embedding_v2`. Do not show connection strings, passwords, account email, cluster
credentials, access tokens, or embedding values.

### Take C: Agent Skill and AWS proof

The Agent Skill shot must connect a named tool to a visible engineering outcome. Frame the pinned
`designing-application-transactions` evidence beside the incident/outcome/governance transaction
design. Do not show the generic skills landing page.

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
LIVE · public AWS deployment
Similarity ≠ authorization
Inspectable trace · not chain-of-thought
PENDING REVIEW · retrieval-ineligible
Amazon Cognito · independent reviewer
ACTIVE → recalled in next decision
CRDB TOOL 1 · Distributed Vector Indexing
CRDB TOOL 2 · Agent Skills Repo
ECS · API Gateway · Cognito · S3 · CloudWatch
SAFE FAILURE · abstain
RecallOps
```

## Editing and audio specification

- Capture 1920×1080 at 30 fps; export H.264 at 1080p with AAC audio.
- Keep browser zoom between 110% and 125% and verify that candidate reasons do not clip.
- Use a gentle, clear female voice at approximately 125–135 words per minute. Aim for calm authority,
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
- [ ] Approval, execution attestation, outcome capture, quarantine, independent review, and recall
      are all visibly performed.
- [ ] The language makes clear that execution is an attestation, not an infrastructure mutation.
- [ ] The newly learned memory is visibly absent before review and eligible after review.
- [ ] CockroachDB rows and the distributed vector index are run and shown live.
- [ ] Both required CockroachDB tools are named and their actual use is explained.
- [ ] The AWS deployment and each claimed AWS service have visible, truthful evidence.
- [ ] Bedrock is called optional unless the recorded runtime actually uses it.
- [ ] No secret, email address, account number, token, password, or connection string is visible.
- [ ] Captions are accurate, the voice is intelligible, and every text proof is readable at 1080p.
- [ ] Duration is no more than 2:59 to leave platform-transcoding margin.
- [ ] YouTube or Vimeo playback works without signing in and the Devpost URL opens correctly.
