[CmdletBinding()]
param(
    [string]$Profile = "default",
    [string]$Region = "us-east-1",
    [string[]]$ModelId = @(
        "amazon.titan-embed-text-v2:0",
        "amazon.nova-lite-v1:0"
    )
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$checks = foreach ($model in $ModelId) {
    try {
        $availability = aws bedrock get-foundation-model-availability `
            --profile $Profile `
            --region $Region `
            --model-id $model `
            --output json | ConvertFrom-Json

        [pscustomobject]@{
            model_id = $model
            authorized = $availability.authorizationStatus -eq "AUTHORIZED"
            authorization_status = $availability.authorizationStatus
            agreement_status = $availability.agreementAvailability.status
            entitlement_status = $availability.entitlementAvailability
            region_status = $availability.regionAvailability
            error = $null
        }
    }
    catch {
        [pscustomobject]@{
            model_id = $model
            authorized = $false
            authorization_status = "UNKNOWN"
            agreement_status = "UNKNOWN"
            entitlement_status = "UNKNOWN"
            region_status = "UNKNOWN"
            error = $_.Exception.Message
        }
    }
}

$ready = @($checks | Where-Object { -not $_.authorized }).Count -eq 0
[pscustomobject]@{
    ready = $ready
    account = (aws sts get-caller-identity --profile $Profile --query Account --output text)
    region = $Region
    checked_at = [DateTimeOffset]::UtcNow.ToString("o")
    models = @($checks)
} | ConvertTo-Json -Depth 5

if (-not $ready) { exit 1 }
