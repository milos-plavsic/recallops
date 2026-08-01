# Threat model

## Scope and assets

The protected assets are tenant incident data, operational memories, embeddings,
review decisions, database credentials, OIDC tokens, S3 evidence, and the integrity of
recommended actions. Trust boundaries exist at the public ALB, token verification,
tenant-scoped API, Bedrock/S3 calls, and CockroachDB connection.

The model assumes TLS is correctly configured, the OIDC administrator controls tenant
assignment, the CockroachDB URL is held in Secrets Manager, and no execution adapter
is attached. A compromised cloud administrator, malicious model provider, or endpoint
host is outside the preventive scope and must be addressed by organizational controls.

| Threat | Control | Residual risk / detection |
| --- | --- | --- |
| Spoofed tenant or role headers | Production mode ignores identity headers and verifies RS256 signature, issuer, client, `token_use`, expiry, subject, tenant, and roles | Compromised IdP remains authoritative; monitor IdP administration |
| Cross-tenant retrieval | Tenant and service predicates execute before vector ranking; body tenant must match the principal | Query regressions are guarded by API, store, and evaluation tests |
| Memory poisoning | Outcomes enter `pending_review`; observer cannot activate; only active memories are retrieved | Colluding operators can approve poison; audit `memory_events` and alert on unusual activation volume |
| Replay or duplicate requests | Tenant-scoped idempotency keys and unique source-incident memory link | A stolen valid token remains usable until expiry; keep access-token lifetime short |
| Prompt injection in incident text or memory | Bedrock is instructed to reason only from supplied evidence; output never directly executes; mutations require approval | Model text can still be misleading; operator must inspect rationale and evidence |
| Retrieval of obsolete advice | Version compatibility, positive-evidence decay, revocation, quarantine, and supersession | Compatibility is exact-version today; semantic compatibility needs domain-specific policy |
| Known failed action becomes attractive with age | Negative outcomes never decay toward safety | Incorrect negative observations require reviewer correction through replacement, not history deletion |
| Database outage or ambiguous commit | Finite deadlines; idempotent writes; authoritative-store failure is fail-closed | Client sees failure and safely retries with the same idempotency key |
| Bedrock embedding outage, throttling, or malformed response | Bounded standard retries, then retrieval abstention; no substitute vector is queried or persisted | Memory-backed remediation and learning stop until recovery; structured degradation event is emitted |
| Bedrock reasoning outage, throttling, or malformed response | Bounded standard retries, then deterministic evidence-only diagnosis marked degraded | Diagnostic quality is lower; the fallback cannot add telemetry beyond supplied evidence |
| S3 outage | Analysis remains in CockroachDB; archival failure is structured and observable | Evidence copy is absent until a reconciliation worker is implemented |
| Resource exhaustion / abuse | WAF IP rate rule, bounded payloads, pool limits, provider deadlines, ECS health and rollback | Distributed attacks can bypass per-IP rate limits; add managed WAF rules for production traffic |
| Secret disclosure | No static AWS credentials; Secrets Manager injection; secret omitted from outputs and source | ECS task/environment access exposes the database URL; restrict IAM and administrative access |
| Supply-chain compromise | Bounded dependencies, public source, CI lint/type/test/evaluation, Dependabot, MIT license | Transitive dependencies are not hermetic; review updates and generate release SBOM |
| Malicious deployment | Clean-tree release, immutable Git-SHA ECR tag and digest, scan-on-push, CloudFormation, ECS rollback | Deployment principal can still publish authorized malicious code; require protected branch/review in production |
| Evidence deletion | S3 versioning, retain policies, public-access block, TLS-only bucket policy | Account-level deletion remains possible; production should add Object Lock and separate backup account |

## Privacy and retention

Incident symptoms can contain customer or infrastructure identifiers. The API should
receive the minimum operational evidence needed, never raw secrets. S3 versions expire
after 365 days in the supplied template; CockroachDB retention is intentionally not
automated because governance/legal requirements differ. Production operators must set
tenant-specific retention and deletion policies before processing personal data.

## Explicit non-goals

RecallOps does not execute remediation, discover secrets, replace incident command, or
claim that an LLM diagnosis is ground truth. Approval records are evidence of human
authorization, not proof that an action is intrinsically safe.
