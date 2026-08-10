param(
    [string]$ClusterName = 'recallops',
    [string]$BuildSha = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Get-Sha256([string]$Value) {
    $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
    $digest = [Security.Cryptography.SHA256]::HashData($bytes)
    return [Convert]::ToHexString($digest).ToLowerInvariant()
}

if (-not $BuildSha) {
    $BuildSha = (git rev-parse HEAD).Trim()
}
if ($BuildSha -notmatch '^[a-f0-9]{40}$') {
    throw 'BuildSha must be a full 40-character Git SHA.'
}

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

$clusterJson = & $ccloudPath cluster info $ClusterName --output json --quiet
if ($LASTEXITCODE -ne 0) {
    throw 'ccloud cluster inspection failed. Run ccloud auth login and retry.'
}
$usersJson = & $ccloudPath cluster user list $ClusterName --output json --quiet
if ($LASTEXITCODE -ne 0) {
    throw 'ccloud user inspection failed. Run ccloud auth login and retry.'
}
$cluster = $clusterJson | ConvertFrom-Json
$users = $usersJson | ConvertFrom-Json
$toolVersion = (& $ccloudPath version | Select-Object -First 1)

[ordered]@{
    evidence_version = 1
    generated_at = [DateTimeOffset]::UtcNow.ToString('O')
    build_sha = $BuildSha
    environment_class = 'managed-cockroach-read-only'
    command = 'ccloud cluster info + ccloud cluster user list'
    tool = $toolVersion
    redaction = 'cluster ID, cluster name, and SQL identities replaced with SHA-256 digests'
    pass_criteria = 'cluster is ready, cloud provider is AWS, and runtime SQL identities exist'
    cluster = [ordered]@{
        name_digest = Get-Sha256 ([string]$cluster.name)
        id_digest = Get-Sha256 ([string]$cluster.id)
        state = $cluster.state
        plan = $cluster.plan
        cloud_provider = $cluster.cloud_provider
        cockroach_version = $cluster.cockroach_version
        regions = @($cluster.regions | ForEach-Object { $_.name })
    }
    sql_identity_digests = @($users | ForEach-Object { Get-Sha256 ([string]$_.name) } | Sort-Object)
    passed = (
        ([string]$cluster.state).ToLowerInvariant() -in @('created', 'ready', 'running') -and
        ([string]$cluster.cloud_provider).ToLowerInvariant() -eq 'aws' -and
        @($users).Count -gt 0
    )
} | ConvertTo-Json -Depth 5
