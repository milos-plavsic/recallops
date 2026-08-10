[CmdletBinding()]
param(
    [string]$DemoUrl = $env:RECALLOPS_DEMO_URL,
    [string]$VideoUrl = $env:RECALLOPS_VIDEO_URL,
    [string]$ReleaseSha = $env:RECALLOPS_RELEASE_SHA
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check([string]$Name, [bool]$Passed, [string]$Evidence) {
    $checks.Add([pscustomobject]@{ name = $Name; passed = $Passed; evidence = $Evidence })
}

$branch = git branch --show-current
$dirty = [bool](git status --porcelain)
$repo = gh repo view --json visibility,licenseInfo,url | ConvertFrom-Json
Add-Check "clean-main" ($branch -eq "main" -and -not $dirty) "branch=$branch dirty=$dirty"
Add-Check "public-repository" ($repo.visibility -eq "PUBLIC") $repo.url
Add-Check "open-source-license" ($repo.licenseInfo.key -eq "mit") $repo.licenseInfo.name

$requiredFiles = @(
    "README.md", "LICENSE", "Dockerfile", "compose.yaml", ".env.example",
    "evaluation/memory_cases.json", "docs/JUDGE_GUIDE.md", "docs/ARCHITECTURE.md",
    "docs/COCKROACH_TOOLS.md", "docs/AWS_DEPLOYMENT.md", "docs/THREAT_MODEL.md",
    "docs/BENCHMARK.md", "docs/COST_MODEL.md", "docs/PROVENANCE.md"
)
$missing = @($requiredFiles | Where-Object { -not (Test-Path -LiteralPath $_) })
Add-Check "evidence-package" ($missing.Count -eq 0) $(if ($missing) { $missing -join ", " } else { "all required files present" })

$headSha = (git rev-parse HEAD).Trim()
if (-not $ReleaseSha) { $ReleaseSha = $headSha }
if ($ReleaseSha -notmatch '^[a-f0-9]{40}$') { throw "ReleaseSha must be a full Git SHA" }
git merge-base --is-ancestor $ReleaseSha HEAD
Add-Check "release-sha-is-published-history" ($LASTEXITCODE -eq 0) "release=$ReleaseSha head=$headSha"
$agentSkillEvidence = "evidence/agent-skills/$ReleaseSha.md"
Add-Check "official-agent-skill-evidence" (Test-Path -LiteralPath $agentSkillEvidence) $agentSkillEvidence

& uv run recallops-eval *> $null
Add-Check "policy-benchmark" ($LASTEXITCODE -eq 0) "uv run recallops-eval exit=$LASTEXITCODE"
& uv run recallops-eval --mode end-to-end *> $null
Add-Check "end-to-end-benchmark" ($LASTEXITCODE -eq 0) "uv run recallops-eval --mode end-to-end exit=$LASTEXITCODE"
Add-Check "functional-demo-url" ($DemoUrl -match '^https://[^\s]+$') $(if ($DemoUrl) { $DemoUrl } else { "missing" })
if ($DemoUrl -match '^https://[^\s]+$') {
    try {
        $health = Invoke-RestMethod -Uri "$($DemoUrl.TrimEnd('/'))/health" -TimeoutSec 20
        Add-Check "live-demo-health" ($health.status -eq 'ok') "status=$($health.status)"
    } catch {
        Add-Check "live-demo-health" $false $_.Exception.Message
    }
} else {
    Add-Check "live-demo-health" $false "demo URL missing"
}
Add-Check "public-video-url" ($VideoUrl -match '^https://(www\.)?(youtube\.com|youtu\.be|vimeo\.com)/') $(if ($VideoUrl) { $VideoUrl } else { "missing" })

$passed = @($checks | Where-Object passed).Count
$report = [pscustomobject]@{
    ready = $passed -eq $checks.Count
    passed = $passed
    total = $checks.Count
    generated_at = [DateTimeOffset]::UtcNow.ToString("o")
    checks = $checks
}
$report | ConvertTo-Json -Depth 5
if (-not $report.ready) { exit 1 }
