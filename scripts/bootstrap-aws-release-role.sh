#!/usr/bin/env bash
set -euo pipefail

region="${AWS_REGION:-us-east-1}"
expected_account="${RECALLOPS_EXPECTED_AWS_ACCOUNT:?set RECALLOPS_EXPECTED_AWS_ACCOUNT}"
profile_args=()
if [[ -n "${AWS_PROFILE:-}" ]]; then
  profile_args=(--profile "$AWS_PROFILE")
fi

actual_account="$(aws sts get-caller-identity "${profile_args[@]}" --query Account --output text)"
actual_arn="$(aws sts get-caller-identity "${profile_args[@]}" --query Arn --output text)"
if [[ "$actual_account" != "$expected_account" || "$actual_arn" != "arn:aws:iam::${expected_account}:root" ]]; then
  echo "Bootstrap requires the exact intended AWS root session." >&2
  exit 1
fi

uv run python scripts/aws-zero-spend-preflight.py \
  --region "$region" --minimum-credits 50 --minimum-days 14 \
  --output artifacts/aws/zero-spend-preflight.json

execution_role="recallops-cloudformation-execution"
if aws iam get-role "${profile_args[@]}" --role-name "$execution_role" >/dev/null 2>&1; then
  aws iam update-assume-role-policy "${profile_args[@]}" \
    --role-name "$execution_role" \
    --policy-document file://infra/aws/cloudformation-execution-trust.json
else
  aws iam create-role "${profile_args[@]}" \
    --role-name "$execution_role" \
    --description "Bounded RecallOps CloudFormation service role" \
    --assume-role-policy-document file://infra/aws/cloudformation-execution-trust.json \
    --tags Key=Application,Value=RecallOps Key=Purpose,Value=cloudformation-execution >/dev/null
fi
aws iam put-role-policy "${profile_args[@]}" \
  --role-name "$execution_role" \
  --policy-name RecallOpsCloudFormationExecution \
  --policy-document file://infra/aws/public-demo-execution-policy.json

aws iam put-role-policy "${profile_args[@]}" \
  --role-name RecallOpsGitHubDeployment \
  --policy-name RecallOpsDeploymentBoundary \
  --policy-document file://infra/aws/deployment-role-policy.json

echo "RecallOps bootstrap roles updated after exact-account and zero-spend verification."
