# RecallOps release evidence report

Release: `fc638214e07ce244973ba41ecfefb9bde25ceea3`
Generated: `2026-08-10T19:53:38.387257+00:00`

## Claim coverage

| Criterion | Claim | Evidence | Status |
| --- | --- | --- | --- |
| Agentic Memory | RecallOps retrieves only tenant-scoped, reviewed, compatible, successful memory and safely abstains otherwise. | `evaluation/statistical/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`end-to-end-cockroach/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`database-boundaries/fc638214e07ce244973ba41ecfefb9bde25ceea3.json` | PASS |
| Technical Implementation | CockroachDB is the transactional system of record, vector memory index, governance boundary, and outbox source. | `cockroach-query-plan/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`database-boundaries/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`ccloud/fc638214e07ce244973ba41ecfefb9bde25ceea3.json` | PASS |
| Technical Implementation | The public judge runtime meaningfully uses ECS, throttled API Gateway, Cognito, S3, CloudWatch, and Secrets Manager. | `deployment/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`aws-security/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`resilience/fc638214e07ce244973ba41ecfefb9bde25ceea3.json` | PASS |
| Potential Impact | Outcome and governance policy reduces unsafe selections relative to similarity-only retrieval on the disclosed benchmark. | `evaluation/statistical/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`performance/fc638214e07ce244973ba41ecfefb9bde25ceea3.json` | PASS |
| Readiness | The immutable public release is authenticated, observable, least-privileged, recoverable, and reproducibly tested. | `deployment/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`container-security/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`resilience/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`restore-drill/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`visual/fc638214e07ce244973ba41ecfefb9bde25ceea3/index.json` | PASS |
| Originality | The product closes the loop from retrieval through approval, execution evidence, observed outcome, independent review, and future recall. | `deployment/fc638214e07ce244973ba41ecfefb9bde25ceea3.json`<br>`visual/fc638214e07ce244973ba41ecfefb9bde25ceea3/index.json`<br>`agent-skills/fc638214e07ce244973ba41ecfefb9bde25ceea3.md` | PASS |

## Integrity

- Catalogued artifacts: 30
- Release-specific artifacts: 15
- Redaction violations: 0
- Every artifact digest is recorded in `evidence/manifest.json`.
- Synthetic evidence is labelled and is not represented as production data.
