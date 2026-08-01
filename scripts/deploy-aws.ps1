[CmdletBinding()]
param(
    [string]$Region = "us-east-1",
    [string]$StackName = "recallops-production",
    [string]$RepositoryName = "recallops",
    [Parameter(Mandatory = $true)][string]$DatabaseUrlSecretArn,
    [Parameter(Mandatory = $true)][string]$VpcId,
    [Parameter(Mandatory = $true)][string]$PublicSubnetIds,
    [Parameter(Mandatory = $true)][string]$PrivateSubnetIds,
    [Parameter(Mandatory = $true)][string]$CertificateArn,
    [Parameter(Mandatory = $true)][string]$PublicHostname,
    [Parameter(Mandatory = $true)][string]$OidcIssuer,
    [Parameter(Mandatory = $true)][string]$OidcAudience,
    [Parameter(Mandatory = $true)][string]$BedrockModelArns,
    [string]$BedrockModelId = "amazon.nova-lite-v1:0",
    [string]$BedrockEmbeddingModelId = "amazon.titan-embed-text-v2:0"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

foreach ($command in @("aws", "docker", "git")) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $command"
    }
}
if (git status --porcelain) {
    throw "Refusing to deploy a dirty worktree. Commit the exact release first."
}

$accountId = aws sts get-caller-identity --region $Region --query Account --output text
if ($LASTEXITCODE -ne 0) { throw "AWS identity verification failed" }
$registry = "$accountId.dkr.ecr.$Region.amazonaws.com"
$repositoryUri = "$registry/$RepositoryName"
$gitSha = git rev-parse HEAD

aws ecr describe-repositories --region $Region --repository-names $RepositoryName *> $null
if ($LASTEXITCODE -ne 0) {
    aws ecr create-repository --region $Region --repository-name $RepositoryName `
        --image-scanning-configuration scanOnPush=true --image-tag-mutability IMMUTABLE *> $null
    if ($LASTEXITCODE -ne 0) { throw "ECR repository creation failed" }
}
aws ecr put-image-scanning-configuration --region $Region --repository-name $RepositoryName `
    --image-scanning-configuration scanOnPush=true *> $null
if ($LASTEXITCODE -ne 0) { throw "ECR scanning configuration failed" }
aws ecr put-image-tag-mutability --region $Region --repository-name $RepositoryName `
    --image-tag-mutability IMMUTABLE *> $null
if ($LASTEXITCODE -ne 0) { throw "ECR immutability configuration failed" }

aws ecr get-login-password --region $Region | docker login --username AWS --password-stdin $registry
if ($LASTEXITCODE -ne 0) { throw "ECR login failed" }
docker build --pull --tag "${repositoryUri}:${gitSha}" .
if ($LASTEXITCODE -ne 0) { throw "Container build failed" }
docker push "${repositoryUri}:${gitSha}"
if ($LASTEXITCODE -ne 0) { throw "Container push failed" }
$digest = aws ecr describe-images --region $Region --repository-name $RepositoryName `
    --image-ids "imageTag=$gitSha" --query 'imageDetails[0].imageDigest' --output text
if ($digest -notmatch '^sha256:[a-f0-9]{64}$') { throw "ECR returned an invalid image digest" }
$imageUri = "${repositoryUri}@${digest}"

aws cloudformation deploy --region $Region --stack-name $StackName `
    --template-file infra/aws/cloudformation.yaml --capabilities CAPABILITY_NAMED_IAM `
    --no-fail-on-empty-changeset `
    --parameter-overrides `
        "ImageUri=$imageUri" "DatabaseUrlSecretArn=$DatabaseUrlSecretArn" `
        "VpcId=$VpcId" "PublicSubnetIds=$PublicSubnetIds" `
        "PrivateSubnetIds=$PrivateSubnetIds" "CertificateArn=$CertificateArn" `
        "PublicHostname=$PublicHostname" `
        "OidcIssuer=$OidcIssuer" "OidcAudience=$OidcAudience" `
        "BedrockModelArns=$BedrockModelArns" "BedrockModelId=$BedrockModelId" `
        "BedrockEmbeddingModelId=$BedrockEmbeddingModelId" `
    --tags Application=RecallOps ManagedBy=CloudFormation SourceCommit=$gitSha
if ($LASTEXITCODE -ne 0) { throw "CloudFormation deployment failed" }

aws ecs wait services-stable --region $Region `
    --cluster "$StackName-cluster" --services "$StackName-api"
if ($LASTEXITCODE -ne 0) { throw "ECS service did not stabilize" }
aws cloudformation describe-stacks --region $Region --stack-name $StackName `
    --query 'Stacks[0].Outputs' --output table
