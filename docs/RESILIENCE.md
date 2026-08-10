# Resilience model

RecallOps treats remote systems as finite and fallible. Every AWS request uses a
finite connect timeout, finite read timeout, TCP keepalive, and standard SDK retries
with a bounded total attempt count. CockroachDB pool acquisition, connection setup,
and SQL statements also have deadlines. The defaults cap retries without creating a
second application-level retry loop that would multiply latency and load.

| Failure | System behavior | Safety property |
| --- | --- | --- |
| Bedrock embedding unavailable or malformed | Skip vector retrieval, abstain from memory-backed remediation, and mark the analysis degraded | No vector from a different semantic space is queried or persisted |
| Bedrock reasoning unavailable or malformed | Render a deterministic evidence-only diagnosis and mark the analysis degraded | The fallback cannot add telemetry beyond supplied memory |
| S3 evidence write unavailable | Persist the CockroachDB analysis, emit a structured error, and return the result; a lease-protected outbox retries delivery | Incident response remains available; archival loss is observable |
| CockroachDB unavailable or deadline exceeded | Fail the API request | The service never answers from uncommitted or cross-tenant state |
| Concurrent duplicate request | CockroachDB unique key or in-memory lock returns one incident | Retries cannot create multiple incident identities |
| Outbox retry budget exhausted | Terminally dead-letter the message, preserve the failure reason, and alert from backlog/dead-letter signals | Infinite retries cannot silently consume capacity or hide archival loss |
| ECS revision cannot become healthy | `/live` health checks fail and the deployment circuit breaker rolls back | A failed release does not replace the last healthy revision |

The degradation boundary is deliberately asymmetric. Reasoning may fall back to a
deterministic evidence-only diagnostic, but embeddings never fall back across semantic
spaces. An embedding outage therefore removes memory-backed remediation and learning
until the configured provider recovers. Derived S3 evidence delivery retries through
the transactional outbox in a dedicated ECS container with its own least-privilege database
identity. A message is claimed with a finite lease and exponential backoff; after
`RECALLOPS_OUTBOX_MAX_ATTEMPTS` (default 8) it is marked dead-lettered and requires an explicit
operator repair decision. `recallops-outbox --status` emits payload-free `pending`,
`dead_lettered`, oldest-age, and max-attempt signals suitable for scheduled collection and alarms.
CockroachDB is the tenant-isolated source of truth and fails
closed. Mutating remediation always retains its approval requirement.

## Readiness and recovery

`/live` is a process liveness endpoint used by ECS and ALB health checks. `/ready` is reserved
for a bounded authoritative-store probe and must be used by deployment automation before shifting
traffic; it must not return success from a stale cache. Schema migration startup is serialized by a
CockroachDB row lock, so concurrent ECS tasks cannot apply ordered migrations simultaneously.
Every applied migration includes an immutable SHA-256 checksum.

When a message is dead-lettered, first correct the underlying S3/IAM/dependency failure, then
inspect the immutable incident and audit record. Requeue only through a reviewed operational
procedure; do not edit payloads or reset attempts in-place without recording the actor and reason.

## Reproduce

Run the automated failure and concurrency suite and capture its release-keyed summary:

```bash
uv run pytest tests/test_resilience.py -q
uv run python scripts/capture-resilience.py --output /tmp/resilience.json
```

The capture covers provider degradation, embedding fail-closed behavior, concurrent
idempotency, bounded AWS retries, outbox retry release, dead-letter limits, payload-free status,
and encrypted archival. It uses controlled test doubles and therefore complements rather than
replaces a managed dependency outage drill.

`scripts/capture-data-restore.py` performs the stronger data-path drill against a disposable
CockroachDB database: it creates a passphrase-encrypted native backup, restores the full database
under a temporary name, compares every table by row count and deterministic content digest, then
drops the restored database. It proves same-cluster recoverability for that snapshot; it does not
prove cross-cluster or regional disaster recovery. The backup collection remains governed by the
configured CockroachDB userfile retention.

For a local database outage drill, start the demo, stop only the CockroachDB
container, and confirm incident creation fails within the configured deadline:

```powershell
docker compose up -d --build
docker compose stop cockroach
Measure-Command { Invoke-RestMethod -Method Post -Uri http://localhost:8080/incidents -Headers @{ 'X-Tenant-ID' = 'tenant-a' } -ContentType application/json -Body '{"tenant_id":"tenant-a","service":"payments","service_version":"1.0.0","symptom":"timeout burst","idempotency_key":"outage-drill-001"}' }
```

Restore with `docker compose start cockroach`. In AWS, use an ECS deployment with an
invalid image digest in a non-production drill stack and capture the service event
showing circuit-breaker rollback. Never inject failure into the judging environment
without first preserving the last healthy revision.
