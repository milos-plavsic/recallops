# RecallOps WebMCP proof card

Use this compact no-scroll card only if a final evidence hold is needed. The live product remains the
primary proof.

## Capability Sculpting

```text
INVESTIGATING
  inspect_incident · compare_memory_candidates · stage_remediation

AWAITING_APPROVAL
  inspect_incident · compare_memory_candidates
  authority owner: HUMAN_OPERATOR

OBSERVATION_READY
  inspect_incident · record_verified_postcheck

PENDING_REVIEW
  inspect_incident · compare_memory_candidates
  reviewer page: zero WebMCP tools
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
Python coverage     5288/5288 statements · 1172/1172 branches
Mutation testing   1493/2019 killed · 73.95% · 0 untested
Browser/native     10 + 2 + 4 passing
Receipt vectors    15/15 exact outcomes
```

Do not show this card with a release SHA, image digest, key thumbprint, or green gate unless all values
match the deployed public release and signed evidence.
