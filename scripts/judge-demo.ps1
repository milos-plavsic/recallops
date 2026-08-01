[CmdletBinding()]
param([switch]$NoBrowser)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

docker compose up -d --build
if ($LASTEXITCODE -ne 0) { throw "RecallOps startup failed" }
docker compose run --rm seed
if ($LASTEXITCODE -ne 0) { throw "Demo memory seed failed" }
docker run --rm recallops:local recallops-eval
if ($LASTEXITCODE -ne 0) { throw "Safety benchmark failed" }

$healthy = $false
for ($attempt = 1; $attempt -le 30; $attempt++) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8080/health" -TimeoutSec 2
        if ($response.status -eq "ok") { $healthy = $true; break }
    } catch {
        Start-Sleep -Seconds 2
    }
}
if (-not $healthy) { throw "RecallOps did not become healthy within 60 seconds" }

Write-Host "RecallOps judge console: http://localhost:8080"
Write-Host "OpenAPI contract:        http://localhost:8080/docs"
if (-not $NoBrowser) {
    Start-Process "http://localhost:8080"
}
