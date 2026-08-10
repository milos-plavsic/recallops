# Security policy

Report vulnerabilities privately to the repository owner. Do not open public issues containing credentials, tenant data, exploit details, or incident evidence.

## Current guarantees

- Tenant identity is required and checked before retrieval.
- Production OIDC mode validates RS256 signatures, issuer, expiry, issued-at time, application,
  access-token use, bounded token age, tenant, subject, and roles before request handling.
- Tenant and actor values in request bodies must match verified claims; identity headers are ignored
  in OIDC mode.
- Vector queries constrain tenant and service before ranking.
- CockroachDB composite foreign keys reject six cross-tenant relationship classes through direct
  SQL; CI exercises the named constraints instead of inferring isolation from application results.
- Migration, API, and outbox database privileges are separated. Runtime roles have exact table
  grants and cannot delete rows, mutate schema, administer roles, or read the migration ledger.
- Consequential actions require a durable, single-decision approval record.
- Newly observed outcomes are quarantined from retrieval until an independent actor reviews them.
- Memory activation, quarantine, revocation, and supersession are tenant-scoped and audit logged.
- Known failed remediations retain their negative ranking penalty as evidence ages.
- AWS credentials are obtained through the runtime credential chain; no static keys are accepted by application configuration.
- Database credentials are injected from AWS Secrets Manager in the deployment template.
- S3 evidence is encrypted, versioned, blocked from public access, and retained if the stack is deleted.
- Evidence outbox delivery is lease-protected, retry-bounded, and terminally dead-lettered after
  the configured attempt budget; dead-letter state and payload-free backlog signals are auditable.

## Deployment requirements

The public hackathon deployment must enable OIDC, TLS termination, rate limiting, and restricted
inbound networking before accepting untrusted traffic. `X-Tenant-ID`, `X-Actor-ID`, and `X-Roles`
are local demonstration inputs and are ignored in OIDC mode. Do not connect execution
adapters to production infrastructure until operations are allowlisted, dry-run capable,
time-limited, auditable, and protected by postcondition checks.

Set `RECALLOPS_AUTH_MODE=oidc` outside local demonstrations. Keep OIDC access-token lifetimes
short; the service enforces `RECALLOPS_OIDC_MAX_TOKEN_AGE_SECONDS` (default 3700 seconds) and
allows only a small configurable clock skew. Rotate compromised credentials at the identity
provider, revoke affected sessions, and inspect the tenant-scoped audit trail.

Use separate Secrets Manager URLs for the migration owner and `recallops_api` login as described
in [`docs/DATABASE_SECURITY.md`](docs/DATABASE_SECURITY.md). Tenant row visibility is currently
application-enforced; do not describe composite foreign keys as CockroachDB RLS or database-level
row authorization.

The complete abuse-case analysis and residual-risk register is in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
