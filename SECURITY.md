# Security policy

Report vulnerabilities privately to the repository owner. Do not open public issues containing credentials, tenant data, exploit details, or incident evidence.

## Current guarantees

- Tenant identity is required and checked before retrieval.
- Production OIDC mode validates RS256 signatures, issuer, expiry, issued-at time, application,
  access-token use, tenant, subject, and roles before request handling.
- Tenant and actor values in request bodies must match verified claims; identity headers are ignored
  in OIDC mode.
- Vector queries constrain tenant and service before ranking.
- Consequential actions require a durable, single-decision approval record.
- Newly observed outcomes are quarantined from retrieval until an independent actor reviews them.
- Memory activation, quarantine, revocation, and supersession are tenant-scoped and audit logged.
- Known failed remediations retain their negative ranking penalty as evidence ages.
- AWS credentials are obtained through the runtime credential chain; no static keys are accepted by application configuration.
- Database credentials are injected from AWS Secrets Manager in the deployment template.
- S3 evidence is encrypted, versioned, blocked from public access, and retained if the stack is deleted.

## Deployment requirements

The public hackathon deployment must enable OIDC, TLS termination, rate limiting, and restricted
inbound networking before accepting untrusted traffic. `X-Tenant-ID`, `X-Actor-ID`, and `X-Roles`
are local demonstration inputs and are ignored in OIDC mode. Do not connect execution
adapters to production infrastructure until operations are allowlisted, dry-run capable,
time-limited, auditable, and protected by postcondition checks.
