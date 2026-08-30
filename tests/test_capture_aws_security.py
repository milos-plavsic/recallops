from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any


def _load_script() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "capture-aws-security.py"
    spec = importlib.util.spec_from_file_location("capture_aws_security", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _CloudFormation:
    def __init__(self) -> None:
        self.requested: list[str] = []

    def describe_stack_resources(self, *, StackName: str) -> dict[str, Any]:
        self.requested.append(StackName)
        if StackName == "foundation":
            return {
                "StackResources": [
                    {"ResourceType": "AWS::S3::Bucket", "PhysicalResourceId": "evidence"}
                ]
            }
        return {
            "StackResources": [
                {"ResourceType": "AWS::ECS::TaskDefinition", "PhysicalResourceId": "task"},
                {"ResourceType": "AWS::Logs::LogGroup", "PhysicalResourceId": "logs"},
                {"ResourceType": "AWS::ApiGatewayV2::Api", "PhysicalResourceId": "api"},
                *[
                    {"ResourceType": "AWS::CloudWatch::Alarm", "PhysicalResourceId": name}
                    for name in ("alarm-1", "alarm-2", "alarm-3")
                ],
            ]
        }


class _Clients:
    def __init__(self) -> None:
        self.cloudformation = _CloudFormation()

    def client(self, service: str, **_: Any) -> Any:
        return getattr(self, service)

    @property
    def ecs(self) -> Any:
        class Ecs:
            @staticmethod
            def describe_task_definition(**_: Any) -> dict[str, Any]:
                return {
                    "taskDefinition": {
                        "taskRoleArn": "arn:task-role",
                        "executionRoleArn": "arn:execution-role",
                        "containerDefinitions": [
                            {
                                "name": "api",
                                "image": "repo@sha256:" + "a" * 64,
                                "user": "65532",
                                "readonlyRootFilesystem": True,
                                "linuxParameters": {"capabilities": {"drop": ["ALL"]}},
                            }
                        ],
                    }
                }

        return Ecs()

    @property
    def s3(self) -> Any:
        class S3:
            @staticmethod
            def get_bucket_versioning(**_: Any) -> dict[str, str]:
                return {"Status": "Enabled"}

            @staticmethod
            def get_public_access_block(**_: Any) -> dict[str, Any]:
                return {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    }
                }

            @staticmethod
            def get_bucket_encryption(**_: Any) -> dict[str, Any]:
                return {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}
                        ]
                    }
                }

        return S3()

    @property
    def logs(self) -> Any:
        class Logs:
            @staticmethod
            def describe_log_groups(**_: Any) -> dict[str, Any]:
                return {"logGroups": [{"logGroupName": "logs", "retentionInDays": 30}]}

        return Logs()

    @property
    def apigatewayv2(self) -> Any:
        class Api:
            @staticmethod
            def get_stages(**_: Any) -> dict[str, Any]:
                return {
                    "Items": [
                        {
                            "StageName": "$default",
                            "DefaultRouteSettings": {
                                "ThrottlingRateLimit": 10,
                                "ThrottlingBurstLimit": 20,
                                "DetailedMetricsEnabled": True,
                            },
                        }
                    ]
                }

        return Api()

    @property
    def cloudwatch(self) -> Any:
        class CloudWatch:
            @staticmethod
            def describe_alarms(**_: Any) -> dict[str, Any]:
                return {"MetricAlarms": [{"StateValue": "OK"}] * 3}

        return CloudWatch()

    @property
    def iam(self) -> Any:
        class Iam:
            @staticmethod
            def list_role_policies(**_: Any) -> dict[str, list[str]]:
                return {"PolicyNames": ["least-privilege"]}

            @staticmethod
            def list_attached_role_policies(**_: Any) -> dict[str, list[str]]:
                return {"AttachedPolicies": []}

        return Iam()

    @property
    def ecr(self) -> Any:
        class Ecr:
            @staticmethod
            def describe_image_scan_findings(**_: Any) -> dict[str, Any]:
                return {
                    "imageScanStatus": {"status": "COMPLETE"},
                    "imageScanFindings": {"findingSeverityCounts": {}},
                }

        return Ecr()


def test_capture_supports_split_runtime_and_foundation_stacks(monkeypatch: Any) -> None:
    module = _load_script()
    clients = _Clients()
    monkeypatch.setattr(module.boto3, "client", clients.client)

    report = module.capture(
        "runtime",
        "us-east-1",
        "a" * 40,
        "recallops",
        "sha256:" + "a" * 64,
        foundation_stack_name="foundation",
    )

    assert clients.cloudformation.requested == ["runtime", "foundation"]
    assert report["passed"] is True
    assert report["assertions"]["s3_versioning_enabled"] is True
