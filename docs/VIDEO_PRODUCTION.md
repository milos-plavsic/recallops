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

The exact 2:52 timeline and final narration live only in
[`VIDEO_RECORDING_RUNBOOK.md`](VIDEO_RECORDING_RUNBOOK.md). Do not maintain a second script here.
The locked proof milestones are:

1. Analyze by 0:06; show policy-selected and policy-rejected vector candidates.
2. Show sanitized evidence references, risk, retries, and timeout in the live trace.
3. Carry one short memory ID through `PENDING REVIEW`, `ACTIVE`, recalled candidate, and SQL row.
4. Distinguish execution attestation from the externally performed operational action.
5. Query the CockroachDB row live and show the captured managed plan using
   `memories@memories_embedding_v2` for vector search.
6. Connect the pinned Agent Skill to three concrete transaction consequences.
7. Show ECS, CloudWatch, and S3 live with the architecture inset; name API Gateway and Cognito.
8. Return to the recalled memory by 2:47 and finish by 2:52.

Do not spend the opening on a title animation, architecture slide, repository, or benchmark.

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

Then show the latest redacted managed query-plan artifact with `vector search` and
`memories@memories_embedding_v2` framed together. This proves use rather than merely index
existence. Keep its synthetic-row/optimizer limitation readable. If the console exposes a cluster
identifier or account email, crop or blur it. Never show a connection string, password, token,
Secrets Manager value, browser password prompt, or terminal environment.

## Recording setup

1. Record at 1920×1080 and 30 fps. Set browser zoom to roughly 110%, then verify that
   result cards, buttons, and evidence text remain fully visible.
2. Disable notifications and close unrelated tabs, bookmarks, downloads, password
   prompts, and browser extensions that expose personal information.
3. Pre-authenticate as the operator. Keep the reviewer credentials in the password
   manager, but cut the credential-entry section from the edit.
4. Open the SQL console, redacted DVI plan, video proof card, AWS views, and live application in
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

- **Take A — live causal loop:** 0:00–1:59, including both identities and the second
  analysis. This is the irreplaceable proof.
- **Take B — database proof:** the read-only CockroachDB query and redacted DVI execution plan.
- **Take C — eligibility proof:** the pinned Agent Skill and concrete transaction consequences.
- **Take D — AWS proof:** ECS, CloudWatch, and S3 with the compact architecture inset.
- **Voice track:** record from the final script after the best screen takes are locked.

This structure makes a transient sign-in, database-console, or narration error cheap
to redo without faking the product interaction.

## Pre-upload acceptance check

- A first-time viewer sees the application act by 0:10.
- The same video visibly proves store, pending-review exclusion, independent governance,
  retrieval, and an approval-gated proposal based on memory.
- CockroachDB and each AWS service are named on screen, not only in narration.
- The database proof is live, readable, read-only, and contains no secret.
- Bedrock is described as optional unless the recorded deployment actually uses it.
- The final video is no more than 2:54, has readable captions, and plays at 1080p.
- The uploaded YouTube or Vimeo link is public or unlisted and works in a signed-out
  browser window without a login.
