from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

ROOT = Path(__file__).parents[1]
CURRENT_ACCOUNT = "158363272009"
RETIRED_ACCOUNTS = ("963114131710",)


class CloudFormationLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Parse intrinsic tags into deterministic data suitable for policy tests."""


def _intrinsic(
    loader: CloudFormationLoader, tag_suffix: str, node: yaml.Node
) -> dict[str, Any]:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"!{tag_suffix}": value}


CloudFormationLoader.add_multi_constructor("!", _intrinsic)


def template(name: str) -> dict[str, Any]:
    parsed = yaml.load(
        (ROOT / "infra" / "aws" / name).read_text(),
        Loader=CloudFormationLoader,
    )
    assert isinstance(parsed, dict)
    return parsed


def policy(name: str) -> dict[str, Any]:
    parsed = json.loads((ROOT / "infra" / "aws" / name).read_text())
    assert isinstance(parsed, dict)
    return parsed


def walk(value: object) -> Iterator[object]:
    yield value
    if isinstance(value, Mapping):
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            yield from walk(child)


def actions(value: object) -> set[str]:
    found: set[str] = set()
    for node in walk(value):
        if not isinstance(node, Mapping) or "Action" not in node:
            continue
        item = node["Action"]
        if isinstance(item, str):
            found.add(item)
        elif isinstance(item, Sequence):
            found.update(str(action) for action in item)
    return found


def environment(container: Mapping[str, Any]) -> dict[str, object]:
    return {item["Name"]: item["Value"] for item in container["Environment"]}


def test_foundation_is_immutable_private_and_cryptographically_durable() -> None:
    resources = template("foundation.yaml")["Resources"]
    repository = resources["ContainerRepository"]["Properties"]
    assert repository["ImageTagMutability"] == "IMMUTABLE"
    assert repository["ImageScanningConfiguration"] == {"ScanOnPush": True}
    assert "RepositoryPolicyText" not in repository

    signing = resources["ReceiptSigningKey"]
    assert signing["DeletionPolicy"] == "RetainExceptOnCreate"
    assert signing["UpdateReplacePolicy"] == "Retain"
    assert signing["Properties"]["KeySpec"] == "ECC_NIST_EDWARDS25519"
    assert signing["Properties"]["KeyUsage"] == "SIGN_VERIFY"
    assert signing["Properties"]["EnableKeyRotation"] is False

    encryption = resources["EvidenceEncryptionKey"]
    assert encryption["DeletionPolicy"] == "RetainExceptOnCreate"
    assert encryption["UpdateReplacePolicy"] == "Retain"
    assert encryption["Properties"]["KeySpec"] == "SYMMETRIC_DEFAULT"
    assert encryption["Properties"]["EnableKeyRotation"] is True

    bucket = resources["EvidenceBucket"]
    props = bucket["Properties"]
    assert bucket["DeletionPolicy"] == "Retain"
    assert bucket["UpdateReplacePolicy"] == "Retain"
    assert props["ObjectLockEnabled"] is True
    retention = props["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]
    assert retention["Mode"] == "COMPLIANCE"
    assert retention["Days"] == {"!Ref": "EvidenceRetentionDays"}
    assert props["VersioningConfiguration"] == {"Status": "Enabled"}
    assert set(props["PublicAccessBlockConfiguration"].values()) == {True}
    encryption_default = props["BucketEncryption"][
        "ServerSideEncryptionConfiguration"
    ][0]["ServerSideEncryptionByDefault"]
    assert encryption_default["SSEAlgorithm"] == "aws:kms"
    assert encryption_default["KMSMasterKeyID"] == {
        "!GetAtt": "EvidenceEncryptionKey.Arn"
    }

    statements = resources["EvidenceBucketPolicy"]["Properties"]["PolicyDocument"][
        "Statement"
    ]
    assert {statement["Sid"] for statement in statements} == {
        "DenyInsecureTransport",
        "DenyUnencryptedObjectWrites",
        "DenyWrongEncryptionKey",
    }
    assert all(statement["Effect"] == "Deny" for statement in statements)


def test_public_demo_has_no_identity_federation_or_serverless_authority_path() -> None:
    document = template("public-demo.yaml")
    resource_types = {
        resource["Type"] for resource in document["Resources"].values()
    }
    forbidden_prefixes = (
        "AWS::Cognito::",
        "AWS::Lambda::",
        "AWS::Organizations::",
        "AWS::EC2::NatGateway",
    )
    assert not any(
        resource_type.startswith(forbidden_prefixes)
        for resource_type in resource_types
    )

    api_container = document["Resources"]["ApiTaskDefinition"]["Properties"][
        "ContainerDefinitions"
    ][0]
    api_environment = environment(api_container)
    assert api_environment["RECALLOPS_AUTH_MODE"] == "judge"
    assert api_environment["RECALLOPS_JUDGE_COOKIE_SECURE"] == "true"
    assert api_environment["RECALLOPS_REASONING_PROVIDER"] == "deterministic"
    assert api_environment["RECALLOPS_EMBEDDING_PROVIDER"] == "deterministic"
    assert api_environment["RECALLOPS_DIAGNOSTIC_PROVIDER"] == "none"


def test_templates_do_not_use_cloudformation_rejected_yaml_aliases() -> None:
    for name in ("cloudformation.yaml", "foundation.yaml", "public-demo.yaml"):
        source = (ROOT / "infra" / "aws" / name).read_text()
        assert not any(
            token.startswith(("&", "*")) and token[1:].isidentifier()
            for line in source.splitlines()
            for token in line.split()
        )


def test_task_identity_is_separated_and_only_receipt_worker_can_sign() -> None:
    resources = template("public-demo.yaml")["Resources"]
    task_roles = {
        name: resource
        for name, resource in resources.items()
        if name.endswith("TaskRole")
    }
    execution_roles = {
        name: resource
        for name, resource in resources.items()
        if name.endswith("ExecutionRole")
    }
    assert set(task_roles) == {
        "ApiTaskRole",
        "OutboxTaskRole",
        "ReceiptTaskRole",
        "MigrationTaskRole",
    }
    assert set(execution_roles) == {
        "ApiExecutionRole",
        "OutboxExecutionRole",
        "ReceiptExecutionRole",
        "MigrationExecutionRole",
    }
    assert all("kms:Sign" not in actions(role) for role in execution_roles.values())
    assert all(
        "kms:Sign" not in actions(role)
        for name, role in task_roles.items()
        if name != "ReceiptTaskRole"
    )

    receipt = task_roles["ReceiptTaskRole"]
    signing_statement = next(
        statement
        for node in walk(receipt)
        if isinstance(node, Mapping)
        for statement in [node]
        if statement.get("Action") == "kms:Sign"
    )
    assert signing_statement["Resource"] == {"!Ref": "ReceiptSigningKeyArn"}
    assert signing_statement["Condition"] == {
        "StringEquals": {"kms:SigningAlgorithm": "ED25519_SHA_512"}
    }


def test_api_can_only_read_finalized_versioned_bundles() -> None:
    resources = template("public-demo.yaml")["Resources"]
    api_role = resources["ApiTaskRole"]
    assert actions(api_role) == {
        "s3:GetObjectVersion",
        "s3:GetObjectVersionAttributes",
        "kms:Decrypt",
        "sts:AssumeRole",
    }
    api_text = json.dumps(api_role, sort_keys=True)
    assert "synthetic-authority-bundles/*" in api_text
    assert "s3:PutObject" not in api_text
    assert "releases/" not in api_text

    receipt_role = resources["ReceiptTaskRole"]
    receipt_text = json.dumps(receipt_role, sort_keys=True)
    assert "${ReleaseArtifactsPrefix}/*" in receipt_text
    assert "synthetic-authority-bundles/*" in receipt_text
    assert "tenants/*" not in receipt_text


def test_network_has_one_ingress_path_and_workers_have_none() -> None:
    resources = template("public-demo.yaml")["Resources"]
    assert resources["LoadBalancer"]["Properties"]["Scheme"] == "internal"
    assert resources["ApiIntegration"]["Properties"]["ConnectionType"] == "VPC_LINK"
    assert resources["ApiStage"]["Properties"]["DefaultRouteSettings"] == {
        "DetailedMetricsEnabled": True,
        "ThrottlingBurstLimit": 40,
        "ThrottlingRateLimit": 20,
    }

    api_security_group = resources["ApiTaskSecurityGroup"]["Properties"]
    assert api_security_group["SecurityGroupIngress"] == [
        {
            "IpProtocol": "tcp",
            "FromPort": 8080,
            "ToPort": 8080,
            "SourceSecurityGroupId": {"!Ref": "LoadBalancerSecurityGroup"},
        }
    ]
    assert "SecurityGroupIngress" not in resources["WorkerTaskSecurityGroup"][
        "Properties"
    ]

    for service in ("ApiService", "OutboxService", "ReceiptService"):
        network = resources[service]["Properties"]["NetworkConfiguration"][
            "AwsvpcConfiguration"
        ]
        assert network["AssignPublicIp"] == "ENABLED"
        assert network["Subnets"] == {"!Ref": "PublicSubnetIds"}
    assert resources["ApiService"]["Properties"]["EnableExecuteCommand"] is False
    assert resources["OutboxService"]["Properties"]["EnableExecuteCommand"] is False
    assert resources["ReceiptService"]["Properties"]["EnableExecuteCommand"] is False


def test_release_bootstraps_fail_closed_before_any_service_runs() -> None:
    document = template("public-demo.yaml")
    parameters = document["Parameters"]
    assert parameters["DesiredApiCount"]["Default"] == 0
    assert parameters["DesiredOutboxCount"]["Default"] == 0
    assert parameters["DesiredReceiptCount"]["Default"] == 0
    resources = document["Resources"]
    assert resources["MigrationTaskDefinition"]["Properties"]["ContainerDefinitions"][
        0
    ]["Command"] == ["recallops-migrate"]
    assert resources["ReceiptService"]["Properties"]["DesiredCount"] == {
        "!Ref": "DesiredReceiptCount"
    }

    for task in (
        "ApiTaskDefinition",
        "OutboxTaskDefinition",
        "ReceiptTaskDefinition",
        "MigrationTaskDefinition",
    ):
        container = resources[task]["Properties"]["ContainerDefinitions"][0]
        assert container["ReadonlyRootFilesystem"] is True
        assert container["LinuxParameters"]["Capabilities"] == {"Drop": ["ALL"]}


def test_deployment_authority_is_current_account_only_and_cannot_sign() -> None:
    deployment = policy("deployment-role-policy.json")
    execution = policy("public-demo-execution-policy.json")
    combined = json.dumps([deployment, execution], sort_keys=True)
    assert CURRENT_ACCOUNT in combined
    assert not any(account in combined for account in RETIRED_ACCOUNTS)
    assert "kms:Sign" not in actions(deployment)
    assert "organizations:CreateOrganization" not in actions(deployment)
    assert "organizations:InviteAccountToOrganization" not in actions(deployment)
    assert "organizations:CreateOrganization" not in actions(execution)
    assert "organizations:InviteAccountToOrganization" not in actions(execution)

    pass_role = next(
        statement
        for statement in deployment["Statement"]
        if statement["Sid"] == "PassOnlyRecallOpsCloudFormationRole"
    )
    assert pass_role["Resource"] == (
        f"arn:aws:iam::{CURRENT_ACCOUNT}:role/recallops-cloudformation-execution"
    )
    assert pass_role["Condition"] == {
        "StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}
    }


def test_cloudformation_execution_policy_has_no_wildcard_identity_mutation() -> None:
    execution = policy("public-demo-execution-policy.json")
    all_actions = actions(execution)
    assert "iam:*" not in all_actions
    assert "kms:*" not in all_actions
    assert "s3:*" not in all_actions
    assert "ecs:ExecuteCommand" not in all_actions
    assert not any(action.startswith("organizations:") for action in all_actions)

    role_statement = next(
        statement
        for statement in execution["Statement"]
        if statement["Sid"] == "ManageRecallOpsTaskRoles"
    )
    assert role_statement["Resource"] == (
        f"arn:aws:iam::{CURRENT_ACCOUNT}:role/recallops-*"
    )
    assert "iam:AttachRolePolicy" not in role_statement["Action"]
    assert "iam:UpdateRole" not in role_statement["Action"]

    random_password = next(
        statement
        for statement in execution["Statement"]
        if statement["Sid"] == "GenerateRecallOpsSecretValues"
    )
    assert random_password == {
        "Sid": "GenerateRecallOpsSecretValues",
        "Effect": "Allow",
        "Action": "secretsmanager:GetRandomPassword",
        "Resource": "*",
    }

    retired_s3_api_names = {
        "s3:DeleteBucketEncryption",
        "s3:DeleteBucketLifecycle",
        "s3:DeleteBucketTagging",
        "s3:GetBucketEncryption",
        "s3:GetBucketLifecycleConfiguration",
        "s3:PutBucketEncryption",
        "s3:PutBucketLifecycleConfiguration",
    }
    assert all_actions.isdisjoint(retired_s3_api_names)
    assert {
        "s3:GetEncryptionConfiguration",
        "s3:GetLifecycleConfiguration",
        "s3:PutEncryptionConfiguration",
        "s3:PutLifecycleConfiguration",
    } <= all_actions
