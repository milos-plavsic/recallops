# Security policy

Report vulnerabilities privately to the repository owner. Do not open public issues containing credentials, tenant data, exploit details, or incident evidence.

## Current guarantees

- Tenant identity is required and checked before retrieval.
- Vector queries constrain tenant and service before ranking.
- Consequential actions require a durable, single-decision approval record.
- Newly observed outcomes are quarantined from retrieval until an independent actor reviews them.
- Memory activation, quarantine, revocation, and supersession are tenant-scoped and audit logged.
- Known failed remediations retain their negative ranking penalty as evidence ages.
- AWS credentials are obtained through the runtime credential chain; no static keys are accepted by application configuration.
- Database credentials are injected from AWS Secrets Manager in the deployment template.
- S3 evidence is encrypted, versioned, blocked from public access, and retained if the stack is deleted.

## Deployment requirements

The public hackathon demo must add TLS termination, authenticated user identity, rate limiting, and
restricted inbound networking before accepting untrusted traffic. The `X-Tenant-ID` header is a
local demonstration boundary, not production authentication. Until verified identity is enabled,
do not expose outcome or governance endpoints to untrusted clients. Do not connect execution
adapters to production infrastructure until operations are allowlisted, dry-run capable,
time-limited, auditable, and protected by postcondition checks.
