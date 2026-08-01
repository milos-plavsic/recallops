# Resilience model

RecallOps treats remote systems as finite and fallible. Every AWS request uses a
finite connect timeout, finite read timeout, TCP keepalive, and standard SDK retries
with a bounded total attempt count. CockroachDB pool acquisition, connection setup,
and SQL statements also have deadlines. The defaults cap retries without creating a
second application-level retry loop that would multiply latency and load.

| Failure | System behavior | Safety property |
| --- | --- | --- |
| Bedrock embedding unavailable or malformed | Use deterministic 1024-dimensional embedding and mark the analysis degraded | Retrieval stays tenant/state filtered; no write action is invented |
| Bedrock reasoning unavailable or malformed | Render a deterministic evidence-only diagnosis and mark the analysis degraded | The fallback cannot add telemetry beyond supplied memory |
| S3 evidence write unavailable | Persist the CockroachDB analysis, emit a structured error, and return the result | Incident response remains available; archival loss is observable |
| CockroachDB unavailable or deadline exceeded | Fail the API request | The service never answers from uncommitted or cross-tenant state |
| Concurrent duplicate request | CockroachDB unique key or in-memory lock returns one incident | Retries cannot create multiple incident identities |
| ECS revision cannot become healthy | Deployment circuit breaker rolls back | A failed release does not replace the last healthy revision |

The degradation boundary is deliberately asymmetric. AI enrichment and derived S3
evidence may fail open into a conservative diagnostic response. CockroachDB is the
tenant-isolated source of truth and fails closed. Mutating remediation always retains
its approval requirement.

## Reproduce

Run the automated failure and concurrency suite:

```powershell
./.venv/Scripts/pytest.exe tests/test_resilience.py -q
```

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
