$ErrorActionPreference = 'Stop'

$headers = @{ 'X-Tenant-ID' = 'demo'; 'X-Actor-ID' = 'demo-operator' }
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

$outcome = @{
    tenant_id = 'demo'
    action_taken = $analysis.proposed_action.command
    outcome = 'Latency and error rate remained at baseline for the observation window'
    outcome_score = 1.0
    confidence = 0.97
    actor_id = 'demo-observer'
} | ConvertTo-Json

$headers['X-Actor-ID'] = 'demo-observer'

$learned = Invoke-RestMethod `
    -Method Post `
    -Uri "http://localhost:8080/v1/incidents/$($analysis.incident_id)/outcome" `
    -Headers $headers `
    -ContentType 'application/json' `
    -Body $outcome

$learned | ConvertTo-Json

$governance = @{
    tenant_id = 'demo'
    actor_id = 'demo-reviewer'
    action = 'activate'
    reason = 'Independent review confirmed the observed recovery window'
} | ConvertTo-Json

$headers['X-Actor-ID'] = 'demo-reviewer'

Invoke-RestMethod `
    -Method Post `
    -Uri "http://localhost:8080/v1/memories/$($learned.id)/governance" `
    -Headers $headers `
    -ContentType 'application/json' `
    -Body $governance | ConvertTo-Json
