# Three-minute demo production plan

> **Recording-day source of truth:** use
> [`VIDEO_RECORDING_RUNBOOK.md`](VIDEO_RECORDING_RUNBOOK.md) for the final timed narration,
> click choreography, overlays, console setup, and acceptance test. This document retains the
> broader production rationale and database proof notes.

This video must prove a causal loop, not tour a set of screenshots:

> incident → governed retrieval → human-approved action → observed outcome →
> pending memory → independent review → future recall

The public deployment is the primary recording target:
<https://ltfrottcxj.execute-api.us-east-1.amazonaws.com>. Use a local recording only
as a fallback, and label it accurately.

## Final cut

| Time | Screen and action | Narration |
| --- | --- | --- |
| 0:00–0:10 | Start on the live incident console, with the prefilled checkout incident visible. Overlay: **RecallOps — governed memory for SRE agents**. | “Operational agents often confuse a similar incident with a safe precedent. RecallOps is for SRE teams that need an agent to remember outcomes without silently learning a dangerous action.” |
| 0:10–0:32 | Click **Analyze incident**. Keep the cursor still while the response renders. Point once to the proposed action and **Approval required**. | “The live agent retrieves tenant-scoped memories from CockroachDB, checks version compatibility and observed outcomes, and proposes the safe precedent. It can recommend this mutation, but it cannot execute it without approval.” |
| 0:32–0:49 | Open **Candidate evidence**. Frame the `Vector candidate → POLICY SELECTED/REJECTED` labels and show the successful compatible candidate beside the similar failed candidate and its rejection reason. | “Vector similarity supplies candidates; it is never treated as authorization. Deterministic tenant, validity, compatibility, outcome, and governance controls decide eligibility and rank. This semantically close restart caused a second outage, so policy rejects it in favor of outcome-backed evidence.” |
| 0:49–1:02 | Open **Replayable agent trace** and briefly show ordered steps, evidence references, bounded risk, and status. | “This trace records what the agent actually did, the evidence it used, and its bounded failure behavior. It is an inspectable decision, not hidden chain-of-thought.” |
| 1:02–1:22 | Click **Approve exact action**, **Attest execution**, then **Record successful outcome**. Pause on **PENDING REVIEW**. | “The operator approves the exact command, attests execution, and records the observed recovery. RecallOps writes a new memory, but excludes it from retrieval while it is pending independent review.” |
| 1:22–1:38 | Click **Switch identity**. Cut the sign-in wait and credential entry. Resume after reviewer sign-in. Overlay: **Amazon Cognito — separate reviewer identity**. | “A separate Cognito identity enforces four-eyes review. Authentication is cut from the recording so no credentials are exposed.” |
| 1:38–1:51 | Click **Activate as reviewer**. Pause on **ACTIVE MEMORY**. | “The reviewer activates the evidence. CockroachDB commits the state transition and its governance event as an auditable record.” |
| 1:51–2:10 | Click **Analyze again**. Open **Candidate evidence** and show the newly governed memory in the next decision. | “On the next incident, the agent can retrieve and act on the reviewed outcome. That is the complete store, govern, retrieve, and act memory loop.” |
| 2:10–2:28 | Cut to a pre-opened CockroachDB Cloud SQL Console containing the read-only query below. Run it and show the new `active` memory and its `activate` event. | “This is the underlying CockroachDB record: outcome, observer, reviewer, active state, and governance event. The embedding is 1,024-dimensional and searched through CockroachDB Distributed Vector Indexing.” |
| 2:28–2:43 | Show the architecture diagram. Highlight CockroachDB, then the deployed AWS services. Overlay: **CockroachDB DVI + transactions · Amazon ECS · API Gateway · Cognito · S3 evidence · CloudWatch alarms**. Keep the matching deployment-evidence identifiers visible, but never credentials. | “CockroachDB is the transactional vector memory layer. On AWS, ECS runs the API, API Gateway exposes it, Cognito separates roles, S3 archives versioned evidence, and CloudWatch supplies observability and server-verifiable alarm evidence. Bedrock is supported as an optional provider; this public demo uses deterministic providers for judge reliability.” |
| 2:43–2:54 | Show the synthetic policy regression result and browser test result. Keep the label **synthetic policy regression** visible. | “Deterministic policy cases exercise known safety failures, while browser and integration tests verify the user-visible loop. These are regression proofs, not production accuracy claims.” |
| 2:54–3:00 | Return to the active-memory result or closing title. | “RecallOps is an agent that learns what worked—and knows who proved it.” |

Do not spend the opening on a title animation, architecture slide, repository, or
benchmark. The first real click occurs by 0:10.

## CockroachDB proof shot

Prepare this query before recording. Replace the tenant literal only if the deployed
tenant differs. The query is read-only and intentionally omits embeddings, incident
payloads, secrets, and full user identifiers.

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

Then briefly show the index without dumping vector values:

```sql
SHOW INDEXES FROM memories;
```

Frame the `memories_embedding_v2` row. If the console exposes a cluster identifier or
account email, crop or blur it. Never show a connection string, password, token,
Secrets Manager value, browser password prompt, or terminal environment.

## Recording setup

1. Record at 1920×1080 and 30 fps. Set browser zoom to roughly 110%, then verify that
   result cards, buttons, and evidence text remain fully visible.
2. Disable notifications and close unrelated tabs, bookmarks, downloads, password
   prompts, and browser extensions that expose personal information.
3. Pre-authenticate as the operator. Keep the reviewer credentials in the password
   manager, but cut the credential-entry section from the edit.
4. Open the SQL console, architecture diagram, test evidence, and live application in
   final tab order before recording. Preload each tab once.
5. Use a clean demo run. Confirm `/health` and `/ready`, then rehearse the exact button
   sequence once without recording. Do not rehearse against the final clean dataset.
6. Pause for one second after each click and two seconds on `PENDING REVIEW`, `ACTIVE
   MEMORY`, and the second analysis. Move the cursor only to direct attention.
7. Record the screen and narration separately if a single take makes either worse.
   Use jump cuts for latency and authentication, but never replace the live state
   transitions with still images.
8. Add burned-in captions and the exact service/feature overlays from the timeline.
   Keep music absent or very quiet beneath speech.

## Capture as short takes

- **Take A — live causal loop:** 0:00–2:10, including both identities and the second
  analysis. This is the irreplaceable proof.
- **Take B — database proof:** the read-only CockroachDB query and vector-index row.
- **Take C — architecture and evidence:** architecture, regression result, and tests.
- **Voice track:** record from the final script after the best screen takes are locked.

This structure makes a transient sign-in, database-console, or narration error cheap
to redo without faking the product interaction.

## Pre-upload acceptance check

- A first-time viewer sees the application act by 0:10.
- The same video visibly proves store, exclusion, independent governance, retrieval,
  and action on memory.
- CockroachDB and each AWS service are named on screen, not only in narration.
- The database proof is live, readable, read-only, and contains no secret.
- Bedrock is described as optional unless the recorded deployment actually uses it.
- Synthetic tests are labeled as regression evidence, not production accuracy.
- The final video is at most three minutes, has readable captions, and plays at 1080p.
- The uploaded YouTube or Vimeo link is public or unlisted and works in a signed-out
  browser window without a login.
