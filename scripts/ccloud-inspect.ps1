param(
    [string]$ClusterName = 'recallops'
)

$ErrorActionPreference = 'Stop'

$ccloud = Get-Command ccloud -ErrorAction SilentlyContinue
if (-not $ccloud) {
    $installed = Join-Path $env:APPDATA 'ccloud\ccloud.exe'
    if (-not (Test-Path -LiteralPath $installed)) {
        throw 'Install ccloud 0.6.12 or newer and authenticate with ccloud auth login.'
    }
    $ccloudPath = $installed
} else {
    $ccloudPath = $ccloud.Source
}

$cluster = & $ccloudPath cluster info $ClusterName --output json --quiet | ConvertFrom-Json
$users = & $ccloudPath cluster user list $ClusterName --output json --quiet | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) {
    throw 'ccloud inspection failed. Run ccloud auth login and retry.'
}

[ordered]@{
    evidence_version = 1
    generated_at = [DateTimeOffset]::UtcNow.ToString('O')
    tool = (& $ccloudPath version | Select-Object -First 1)
    cluster = [ordered]@{
        name = $cluster.name
        id = $cluster.id
        state = $cluster.state
        plan = $cluster.plan
        cloud_provider = $cluster.cloud_provider
        cockroach_version = $cluster.cockroach_version
        regions = @($cluster.regions | ForEach-Object { $_.name })
    }
    sql_identities = @($users | ForEach-Object { $_.name })
} | ConvertTo-Json -Depth 5
