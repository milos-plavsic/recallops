from typing import Any

import pytest
from botocore.exceptions import ClientError

from recallops.diagnostics import (
    AwsCloudWatchAlarmInspector,
    AwsEcsDeploymentInspector,
    DiagnosticScope,
    ReadOnlyDiagnosticTools,
)
from recallops.resilience import DependencyUnavailable


class FakeCloudWatch:
    def __init__(self, response: dict[str, Any] | Exception) -> None:
        self.response = response
        self.requests: list[dict[str, Any]] = []

    def describe_alarms(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class FakeEcs:
    def __init__(self, response: dict[str, Any] | Exception) -> None:
        self.response = response
        self.requests: list[dict[str, Any]] = []

    def describe_services(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def inspector_clients(
    monkeypatch: pytest.MonkeyPatch,
    cloudwatch: FakeCloudWatch,
    ecs: FakeEcs,
) -> tuple[AwsCloudWatchAlarmInspector, AwsEcsDeploymentInspector]:
    def client(service: str, **kwargs: Any) -> object:
        assert kwargs["config"].connect_timeout == 1
        assert kwargs["config"].read_timeout == 2
        assert kwargs["config"].retries == {"mode": "standard", "total_max_attempts": 2}
        return cloudwatch if service == "cloudwatch" else ecs

    monkeypatch.setattr("recallops.diagnostics.boto3.client", client)
    return (
        AwsCloudWatchAlarmInspector("us-east-1", "recallops", 1, 2, 2, max_alarms=2),
        AwsEcsDeploymentInspector(
            "us-east-1", "recallops", "recallops", 1, 2, 2, max_deployments=2
        ),
    )


def test_diagnostics_derive_only_bounded_deployment_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cloudwatch = FakeCloudWatch(
        {
            "MetricAlarms": [
                {"AlarmName": "secret-a", "StateValue": "OK"},
                {"AlarmName": "secret-b", "StateValue": "ALARM"},
                {"AlarmName": "secret-c", "StateValue": "OK"},
            ],
            "CompositeAlarms": [],
            "NextToken": "intentionally-not-followed",
        }
    )
    ecs = FakeEcs(
        {
            "failures": [],
            "services": [
                {
                    "desiredCount": 3,
                    "runningCount": 2,
                    "pendingCount": 1,
                    "deployments": [
                        {
                            "status": "PRIMARY",
                            "rolloutState": "IN_PROGRESS",
                            "desiredCount": 3,
                            "runningCount": 2,
                            "pendingCount": 1,
                        },
                        {
                            "status": "ACTIVE",
                            "rolloutState": "COMPLETED",
                            "desiredCount": 0,
                            "runningCount": 0,
                            "pendingCount": 0,
                        },
                        {
                            "status": "INACTIVE",
                            "rolloutState": "COMPLETED",
                            "desiredCount": 0,
                            "runningCount": 0,
                            "pendingCount": 0,
                        },
                    ],
                }
            ],
        }
    )
    alarm_inspector, ecs_inspector = inspector_clients(monkeypatch, cloudwatch, ecs)
    scope = DiagnosticScope.from_tenant_service("tenant-a", "payments")

    alarms = alarm_inspector.inspect(scope)
    deployments = ecs_inspector.inspect(scope)

    assert cloudwatch.requests == [
        {"AlarmNamePrefix": "recallops-tenant-a-payments", "MaxRecords": 2}
    ]
    assert ecs.requests == [{"cluster": "recallops", "services": ["recallops-tenant-a-payments"]}]
    assert [alarm.state for alarm in alarms.alarms] == ["OK", "ALARM"]
    assert alarms.truncated is True
    assert len(deployments.deployments) == 2
    assert deployments.truncated is True
    assert deployments.running_count == 2
    assert alarms.limit == deployments.limit == 2
    # No AWS names, ARNs, alarm reasons, tags, or user-controlled input are persisted.
    assert "secret" not in repr(alarms)
    assert "tenant-a" not in repr(alarms)
    assert alarms.evidence_ref.startswith("urn:recallops:diagnostic:cloudwatch-alarms:")
    assert deployments.evidence_ref.startswith("urn:recallops:diagnostic:ecs-deployment:")


def test_facade_accepts_only_validated_tenant_and_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cloudwatch = FakeCloudWatch({"MetricAlarms": [], "CompositeAlarms": []})
    ecs = FakeEcs({"failures": [], "services": []})
    alarms, deployments = inspector_clients(monkeypatch, cloudwatch, ecs)
    tools = ReadOnlyDiagnosticTools(alarms, deployments)

    result = tools.inspect("tenant-a", "payments")
    assert result[1].service_found is False
    with pytest.raises(ValueError, match="invalid diagnostic service"):
        tools.inspect("tenant-a", "payments;drop-table")
    # Invalid scope fails before any additional AWS request is made.
    assert len(cloudwatch.requests) == 1
    assert len(ecs.requests) == 1


@pytest.mark.parametrize(
    ("factory", "dependency"),
    [
        (
            lambda: AwsCloudWatchAlarmInspector("us-east-1", "bad/prefix", 1, 2, 2),
            "invalid alarm_name_prefix",
        ),
        (
            lambda: AwsEcsDeploymentInspector(
                "us-east-1", "cluster", "prefix", 1, 2, 2, max_deployments=0
            ),
            "max_deployments must be between 1 and 20",
        ),
    ],
)
def test_diagnostic_configuration_has_finite_hard_bounds(factory: Any, dependency: str) -> None:
    with pytest.raises(ValueError, match=dependency):
        factory()


@pytest.mark.parametrize("kind", ["cloudwatch", "ecs"])
def test_aws_errors_fail_closed_as_dependency_unavailable(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "read")
    cloudwatch = FakeCloudWatch(error if kind == "cloudwatch" else {"MetricAlarms": []})
    ecs = FakeEcs(error if kind == "ecs" else {"failures": [], "services": []})
    alarm_inspector, ecs_inspector = inspector_clients(monkeypatch, cloudwatch, ecs)
    scope = DiagnosticScope.from_tenant_service("tenant-a", "payments")

    with pytest.raises(DependencyUnavailable) as raised:
        (alarm_inspector if kind == "cloudwatch" else ecs_inspector).inspect(scope)
    assert raised.value.dependency == f"{kind}_diagnostics"


def test_malformed_aws_data_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    cloudwatch = FakeCloudWatch({"MetricAlarms": [{"StateValue": "UNKNOWN"}]})
    ecs = FakeEcs({"failures": [], "services": []})
    alarms, _ = inspector_clients(monkeypatch, cloudwatch, ecs)

    with pytest.raises(DependencyUnavailable) as raised:
        alarms.inspect(DiagnosticScope.from_tenant_service("tenant-a", "payments"))
    assert raised.value.dependency == "cloudwatch_diagnostics"
