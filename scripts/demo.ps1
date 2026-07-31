$ErrorActionPreference = 'Stop'

$headers = @{ 'X-Tenant-ID' = 'demo' }
$incident = @{
    tenant_id = 'demo'
    service = 'checkout'
    service_version = '2026.07.31'
    symptom = 'latency spike after connection pool exhaustion'
    idempotency_key = "demo-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
} | ConvertTo-Json

$analysis = Invoke-RestMethod `
    -Method Post `
    -Uri 'http://localhost:8080/v1/incidents' `
    -Headers $headers `
    -ContentType 'application/json' `
    -Body $incident

$analysis | Select-Object incident_id, diagnosis, confidence, memories, proposed_action |
    ConvertTo-Json -Depth 10

$approval = @{
    tenant_id = 'demo'
    approved = $true
    actor_id = 'demo-operator'
    reason = 'Evidence and version compatibility verified during demo'
} | ConvertTo-Json

Invoke-RestMethod `
    -Method Post `
    -Uri "http://localhost:8080/v1/incidents/$($analysis.incident_id)/approval" `
    -Headers $headers `
    -ContentType 'application/json' `
    -Body $approval | ConvertTo-Json
