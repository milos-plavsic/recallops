# Threat model

## Scope and assets

The protected assets are tenant incident data, operational memories, embeddings,
review decisions, database credentials, OIDC tokens, S3 evidence, and the integrity of
recommended actions. Trust boundaries exist at the public ALB, token verification,
tenant-scoped API, Bedrock/S3 calls, and CockroachDB connection.

The model assumes TLS is correctly configured, the OIDC administrator controls tenant
assignment, and the CockroachDB URL is held in Secrets Manager. The challenge workflow attaches
only the isolated, deterministic checkout simulator described below; no production execution
adapter is attached. A compromised cloud administrator, malicious model provider, or endpoint
host is outside the preventive scope and must be addressed by organizational controls.

| Threat | Control | Residual risk / detection |
| --- | --- | --- |
| Spoofed tenant or role headers | Production mode ignores identity headers and verifies RS256 signature, issuer, client, `token_use`, expiry, issued-at time, bounded token age, subject, tenant, and roles | Compromised IdP remains authoritative; monitor IdP administration |
| Stolen or guessed judge bootstrap link | Only SHA-256 code digests are configured; exchange is exact-Origin and HMAC-pseudonymous-client rate limited; sessions are opaque, short lived, stored only by hash, and revocable | The fragment code is a bearer credential until exchanged; deliver it only through judge-only instructions and rotate it after judging |
| Cross-site protected mutation | Judge sessions use `SameSite=Strict`, `HttpOnly`, production `Secure`, `__Host-` cookies plus exact-Origin and synchronizer-CSRF validation | XSS within the application origin can act as the user; CSP, bounded rendering, and output escaping remain required |
| WebMCP attempts a protected transition | Protected actions require an operator/reviewer session, UI channel, exact epoch, Origin, and CSRF token; CSRF authority is never attached to WebMCP requests | This does not claim to stop arbitrary browser automation or a compromised origin |
| Cross-tenant retrieval | Tenant and service predicates execute before vector ranking; body tenant must match the principal; direct cross-tenant relationships fail named composite foreign keys | One shared API SQL principal can access permitted rows across tenants; query regressions are guarded by API/store/evaluation tests and direct CockroachDB probes, but RLS is not claimed |
| Memory poisoning | Outcomes enter `pending_review`; observer cannot activate; only active memories are retrieved | Colluding operators can approve poison; audit `memory_events` and alert on unusual activation volume |
| Replay or duplicate requests | Tenant-scoped idempotency keys, immutable insert-or-compare evidence records, exact proposal and observation digests, monotonic workflow epochs, and unique source-incident memory link | A stolen valid token remains usable until expiry; keep access-token lifetime short |
| Agent alters or invents remediation execution | The only executable challenge action is an exact command/digest mapped to a fixed allowlist identifier inside an isolated simulator; arbitrary text is never shell-evaluated; execution is UI/operator-only | The simulator proves authorization and evidence architecture, not production adapter safety |
| Agent invents postcheck measurements | The agent receives only an opaque observation ID and bounded assessment fields; the server resolves immutable measurements and independently computes a versioned policy verdict | The deterministic observation provider is authoritative for the demonstration; production telemetry requires separately secured provider credentials and provenance |
| Observation provider fails or races | Failure moves to `POSTCHECK_UNAVAILABLE`, exposes no assessment tool, and creates no observation or memory; retry reuses the immutable execution and cannot reapply the mutation | Extended provider outage blocks learning, as intended; operator may reset the synthetic scenario |
| Agent disagrees with policy | Immutable measurement, attributable agent assessment, and deterministic policy verdict are preserved separately; policy controls outcome sign and independent review controls retrieval | A flawed policy can still misclassify evidence; version, test, monitor, and review policy changes |
| Client inflates evidence strength | Elevated evidence is verified server-side against an OK CloudWatch alarm or an object in the configured evidence bucket; HTTP references are rejected | CloudWatch alarm and evidence-object integrity remain authoritative; protect their writers and audit changes |
| Prompt injection in incident text or memory | Bedrock is instructed to reason only from supplied evidence; output never directly executes; mutations require approval | Model text can still be misleading; operator must inspect rationale and evidence |
| Retrieval of obsolete advice | Version compatibility, positive-evidence decay, revocation, quarantine, and supersession | Compatibility is exact-version today; semantic compatibility needs domain-specific policy |
| Known failed action becomes attractive with age | Negative outcomes never decay toward safety | Incorrect negative observations require reviewer correction through replacement, not history deletion |
| Database outage or ambiguous commit | Finite deadlines; idempotent writes; authoritative-store failure is fail-closed | Client sees failure and safely retries with the same idempotency key |
| Domain write commits without capability transition | Proposal, approval, simulator execution, observation/verdict, assessment/memory, and review write their domain record and workflow epoch in one serializable transaction; fault injection verifies rollback | External observation collection occurs between two authoritative transitions; a state race rejects persistence and retry does not repeat the execution |
| Bedrock embedding outage, throttling, or malformed response | Bounded standard retries, then retrieval abstention; no substitute vector is queried or persisted | Memory-backed remediation and learning stop until recovery; structured degradation event is emitted |
| Bedrock reasoning outage, throttling, or malformed response | Bounded standard retries, then deterministic evidence-only diagnosis marked degraded | Diagnostic quality is lower; the fallback cannot add telemetry beyond supplied evidence |
| S3 outage | Analysis remains in CockroachDB; lease-protected outbox delivery retries with bounded exponential backoff and terminal dead-letter state | Evidence copy is absent until a reviewed operator repair/requeue; alarm on dead letters and oldest backlog age |
| Resource exhaustion / abuse | WAF IP rate rule, bounded payloads, pool limits, provider deadlines, ECS health and rollback | Distributed attacks can bypass per-IP rate limits; add managed WAF rules for production traffic |
| Secret disclosure | No static AWS credentials; Secrets Manager injection; secret omitted from outputs and source | ECS task/environment access exposes the database URL; restrict IAM and administrative access |
| Compromised database credential | Migration owner, API, and outbox identities are separated; runtime roles have exact grants and cannot mutate schema, delete rows, administer roles, or read unrelated tables | The shared API credential is not a per-tenant database identity; rotate it immediately and inspect tenant audit trails |
| Supply-chain compromise | Bounded dependencies, immutable-pinned GitHub Actions, CI lint/type/test/evaluation, dependency audit, CloudFormation lint, SBOM, Dependabot, MIT license | Transitive dependencies are not hermetic; review updates and sign release artifacts in production |
| Malicious deployment | Clean-tree release, immutable Git-SHA ECR tag and digest, scan-on-push, pinned distroless runtime, non-root read-only containers with all capabilities dropped, CloudFormation, ECS rollback | Deployment principal can still publish authorized malicious code; require protected branch/review in production |
| Evidence deletion | S3 versioning, retain policies, public-access block, TLS-only bucket policy | Account-level deletion remains possible; production should add Object Lock and separate backup account |

## Privacy and retention

Incident symptoms can contain customer or infrastructure identifiers. The API should
receive the minimum operational evidence needed, never raw secrets. S3 versions expire
after 365 days in the supplied template; CockroachDB retention is intentionally not
automated because governance/legal requirements differ. Production operators must set
tenant-specific retention and deletion policies before processing personal data.

## Explicit non-goals

RecallOps does not execute production remediation, discover secrets, replace incident command, or
claim that an LLM diagnosis is ground truth. It mutates only an explicitly labeled isolated
simulator. Approval records prove authorization of the exact proposal digest, not that an action is
intrinsically safe or that a human was physically present.
