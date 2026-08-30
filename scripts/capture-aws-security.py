#!/usr/bin/env python3
"""Capture sanitized, assertion-based AWS runtime security evidence."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3


def capture(
    stack_name: str,
    region: str,
    release_sha: str,
    repository: str,
    image_digest: str,
    foundation_stack_name: str | None = None,
) -> dict[str, Any]:
    cf = boto3.client("cloudformation", region_name=region)
    runtime_resources = cf.describe_stack_resources(StackName=stack_name)["StackResources"]
    foundation_resources = (
        cf.describe_stack_resources(StackName=foundation_stack_name)["StackResources"]
        if foundation_stack_name and foundation_stack_name != stack_name
        else runtime_resources
    )

    def by_type(resources: list[dict[str, Any]]) -> dict[str, list[str]]:
        indexed: dict[str, list[str]] = {}
        for item in resources:
            indexed.setdefault(item["ResourceType"], []).append(item["PhysicalResourceId"])
        return indexed

    runtime_by_type = by_type(runtime_resources)
    foundation_by_type = by_type(foundation_resources)

    ecs = boto3.client("ecs", region_name=region)
    tasks = [
        ecs.describe_task_definition(taskDefinition=task_arn)["taskDefinition"]
        for task_arn in runtime_by_type["AWS::ECS::TaskDefinition"]
    ]
    containers = [container for task in tasks for container in task["containerDefinitions"]]

    s3 = boto3.client("s3", region_name=region)
    bucket = foundation_by_type["AWS::S3::Bucket"][0]
    versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    public = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    encryption = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"][
        "Rules"
    ][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]

    logs = boto3.client("logs", region_name=region)
    log_names = runtime_by_type.get("AWS::Logs::LogGroup", [])
    retention = []
    for name in log_names:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        exact = next(group for group in groups if group["logGroupName"] == name)
        retention.append(exact.get("retentionInDays", 0))

    api = boto3.client("apigatewayv2", region_name=region)
    api_id = runtime_by_type["AWS::ApiGatewayV2::Api"][0]
    stages = api.get_stages(ApiId=api_id)["Items"]
    stage = next(item for item in stages if item["StageName"] == "$default")
    route_settings = stage.get("DefaultRouteSettings", {})

    cloudwatch = boto3.client("cloudwatch", region_name=region)
    alarm_names = runtime_by_type.get("AWS::CloudWatch::Alarm", [])
    alarms = cloudwatch.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]

    iam = boto3.client("iam", region_name=region)
    role_summaries = []
    role_arns = {
        (role_arn, kind)
        for task in tasks
        for role_arn, kind in (
            (task["taskRoleArn"], "task"),
            (task["executionRoleArn"], "execution"),
        )
    }
    for role_arn, kind in sorted(role_arns):
        role_name = role_arn.rsplit("/", 1)[-1]
        role_summaries.append(
            {
                "kind": kind,
                "inline_policy_count": len(
                    iam.list_role_policies(RoleName=role_name)["PolicyNames"]
                ),
                "attached_policy_count": len(
                    iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
                ),
            }
        )

    ecr = boto3.client("ecr", region_name=region)
    scan = ecr.describe_image_scan_findings(
        repositoryName=repository, imageId={"imageDigest": image_digest}
    )
    scan_status = scan["imageScanStatus"]["status"]
    scan_counts = scan.get("imageScanFindings", {}).get("findingSeverityCounts", {})

    assertions = {
        "release_image_digest_pinned": all("@sha256:" in item["image"] for item in containers),
        "runtime_non_root": all(item.get("user") == "65532" for item in containers),
        "runtime_read_only_root": all(item.get("readonlyRootFilesystem") for item in containers),
        "runtime_drops_all_linux_capabilities": all(
            item.get("linuxParameters", {}).get("capabilities", {}).get("drop") == ["ALL"]
            for item in containers
        ),
        "s3_versioning_enabled": versioning == "Enabled",
        "s3_public_access_fully_blocked": all(public.values()),
        "s3_default_encryption_enabled": encryption in {"AES256", "aws:kms"},
        "logs_have_finite_retention": bool(retention) and all(days > 0 for days in retention),
        "api_throttling_enabled": route_settings.get("ThrottlingRateLimit", 0) > 0
        and route_settings.get("ThrottlingBurstLimit", 0) > 0,
        "api_detailed_metrics_enabled": route_settings.get("DetailedMetricsEnabled") is True,
        "alarms_configured": len(alarms) >= 3,
        "task_and_execution_roles_separated": all(
            task["taskRoleArn"] != task["executionRoleArn"] for task in tasks
        ),
        "exact_image_scan_complete": scan_status == "COMPLETE",
        "exact_image_scan_zero_findings": sum(scan_counts.values()) == 0,
    }
    return {
        "evidence_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "build_sha": release_sha,
        "environment_class": f"aws-public-judge-demo-{region}",
        "command": "scripts/capture-aws-security.py",
        "controls": {
            "container_count": len(containers),
            "runtime_containers": sorted(item["name"] for item in containers),
            "s3_encryption": encryption,
            "log_retention_days": sorted(retention),
            "api_throttling_rate_per_second": route_settings.get("ThrottlingRateLimit"),
            "api_throttling_burst": route_settings.get("ThrottlingBurstLimit"),
            "alarm_count": len(alarms),
            "alarm_states": sorted(alarm["StateValue"] for alarm in alarms),
            "iam_roles": role_summaries,
            "ecr_scan": {
                "status": scan_status,
                "finding_count": sum(scan_counts.values()),
                "severity_counts": scan_counts,
            },
        },
        "assertions": assertions,
        "passed": all(assertions.values()),
        "redaction": (
            "Account, ARN, resource name, bucket, role, network, and credential values omitted"
        ),
        "limitations": (
            "Point-in-time control-plane inspection; it does not prove long-duration availability."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-name", required=True)
    parser.add_argument(
        "--foundation-stack-name",
        help="stack containing the evidence bucket; defaults to --stack-name",
    )
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--repository", default="recallops")
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = capture(
        args.stack_name,
        args.region,
        args.release_sha,
        args.repository,
        args.image_digest,
        args.foundation_stack_name,
    )
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
