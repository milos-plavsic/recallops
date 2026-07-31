$ErrorActionPreference = 'Stop'

if (-not (Get-Command ccloud -ErrorAction SilentlyContinue)) {
    throw 'Install the ccloud CLI before running this script.'
}

ccloud cluster list --output json
ccloud service-account list --output json
