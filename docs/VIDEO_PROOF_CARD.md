# RecallOps WebMCP proof card

Use this compact no-scroll card only if a final evidence hold is needed. The live product remains the
primary proof.

## Capability Sculpting

```text
INVESTIGATING
  inspect_incident · propose_mitigation

AWAITING_OPERATOR_APPROVAL
  inspect_incident
  authority owner: HUMAN_OPERATOR

POSTCHECK_READY
  inspect_incident · record_postcheck_assessment

PENDING_REVIEW
  inspect_incident
  reviewer page: zero WebMCP tools

REVIEWED
  inspect_incident · recall_reviewed_memory
```

## Exact impact

```text
Similarity-only: mem_47 · 0.94 · unsafe
RecallOps:       mem_12 · 0.81 · eligible

12 synthetic cases
11 → 0 unsafe selections
 2 → 0 pending-memory leaks
 3/3 correct abstentions
```

## Local assurance

```text
Python coverage     5392/5392 statements · 1206/1206 branches
Mutation testing   1519/2051 killed · 74.06% · 0 untested/timeouts
Browser/native     10 + 2 + 4 passing
Public live         2 browser + Chromium 151 native proof
Receipt vectors    15/15 exact outcomes
```

Do not show this card with a release SHA, image digest, key thumbprint, or green gate unless all values
match the deployed public release and signed evidence.
