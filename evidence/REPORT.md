# RecallOps release evidence report

Release: `4b70ef6a5d013ec7803ce5b8253045c89739c2d6`
Generated: `2026-08-10T21:54:56.186660+00:00`

## Claim coverage

| Criterion | Claim | Evidence | Status |
| --- | --- | --- | --- |
| Agentic Memory | RecallOps retrieves only tenant-scoped, reviewed, compatible, successful memory and safely abstains otherwise. | `evaluation/statistical/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`end-to-end-cockroach/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`database-boundaries/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json` | PASS |
| Technical Implementation | CockroachDB is the transactional system of record, vector memory index, governance boundary, and outbox source. | `cockroach-query-plan/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`database-boundaries/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`ccloud/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`managed-load/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json` | PASS |
| Technical Implementation | The public judge runtime meaningfully uses ECS, throttled API Gateway, Cognito, S3, CloudWatch, and Secrets Manager. | `deployment/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`aws-security/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`resilience/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json` | PASS |
| Potential Impact | Outcome and governance policy reduces unsafe selections relative to similarity-only retrieval on the disclosed benchmark. | `evaluation/statistical/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`performance/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`ablation/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json` | PASS |
| Readiness | The immutable public release is authenticated, observable, least-privileged, recoverable, and reproducibly tested. | `deployment/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`container-security/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`supply-chain/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`resilience/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`restore-drill/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`data-restore/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`visual/4b70ef6a5d013ec7803ce5b8253045c89739c2d6/index.json` | PASS |
| Originality | The product closes the loop from retrieval through approval, execution evidence, observed outcome, independent review, and future recall. | `deployment/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`visual/4b70ef6a5d013ec7803ce5b8253045c89739c2d6/index.json`<br>`agent-skills/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.md` | PASS |
| Readiness | The deployed AWS cost floor is based on live dimensions, observed usage, and current public prices with explicit exclusions. | `cost/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json`<br>`deployment/4b70ef6a5d013ec7803ce5b8253045c89739c2d6.json` | PASS |

## Integrity

- Catalogued artifacts: 59
- Release-specific artifacts: 23
- Redaction violations: 0
- Every artifact digest is recorded in `evidence/manifest.json`.
- Synthetic evidence is labelled and is not represented as production data.
