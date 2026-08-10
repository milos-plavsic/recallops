"""Bounded, read-only AWS diagnostic tools for incident investigation.

The module deliberately accepts only a tenant and service identity.  AWS resource
names are derived from that identity and deployment-owned prefixes; callers cannot
turn an incident field into an ARN, Logs Insights query, metric expression, or SDK
operation.  Returned evidence references are opaque digests, so diagnostic output
is safe to persist in an incident trace without exposing account resource names.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Protocol, cast

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from recallops.resilience import DependencyUnavailable, aws_client_config

_IDENTITY_PART = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ALARM_STATES = frozenset({"OK", "ALARM", "INSUFFICIENT_DATA"})
_DEPLOYMENT_STATES = frozenset({"PRIMARY", "ACTIVE", "INACTIVE"})
_ROLLOUT_STATES = frozenset({"COMPLETED", "FAILED", "IN_PROGRESS"})


def _opaque_digest(kind: str, value: object) -> str:
    """Return a domain-separated digest rather than a resource identifier."""
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return sha256(f"recallops:{kind}:{payload}".encode()).hexdigest()


def _opaque_reference(kind: str, value: object) -> str:
    return f"urn:recallops:diagnostic:{kind}:{_opaque_digest(kind, value)}"


@dataclass(frozen=True, slots=True)
class DiagnosticScope:
    """Validated incident identity used to derive (never accept) AWS targets."""

    tenant_id: str
    service: str

    @classmethod
    def from_tenant_service(cls, tenant_id: str, service: str) -> DiagnosticScope:
        for name, value in (("tenant_id", tenant_id), ("service", service)):
            if not _IDENTITY_PART.fullmatch(value):
                raise ValueError(f"invalid diagnostic {name}")
        return cls(tenant_id=tenant_id, service=service)

    @property
    def resource_suffix(self) -> str:
        """A deterministic, bounded resource suffix for deployment conventions."""
        return f"{self.tenant_id}-{self.service}"

    @property
    def digest(self) -> str:
        return _opaque_digest("scope", {"tenant_id": self.tenant_id, "service": self.service})


@dataclass(frozen=True, slots=True)
class AlarmStatus:
    state: str


@dataclass(frozen=True, slots=True)
class AlarmInspection:
    """A privacy-safe, bounded CloudWatch alarm observation."""

    scope_digest: str
    evidence_ref: str
    target_digest: str
    alarms: tuple[AlarmStatus, ...]
    limit: int
    truncated: bool


@dataclass(frozen=True, slots=True)
class DeploymentStatus:
    status: str
    rollout_state: str | None
    desired_count: int
    running_count: int
    pending_count: int


@dataclass(frozen=True, slots=True)
class EcsDeploymentInspection:
    """A privacy-safe, bounded ECS service deployment observation."""

    scope_digest: str
    evidence_ref: str
    target_digest: str
    service_found: bool
    desired_count: int | None
    running_count: int | None
    pending_count: int | None
    deployments: tuple[DeploymentStatus, ...]
    limit: int
    truncated: bool


class CloudWatchAlarmInspector(Protocol):
    def inspect(self, scope: DiagnosticScope) -> AlarmInspection: ...


class EcsDeploymentInspector(Protocol):
    def inspect(self, scope: DiagnosticScope) -> EcsDeploymentInspection: ...


def _validate_limit(value: int, *, maximum: int, field: str) -> int:
    if not 1 <= value <= maximum:
        raise ValueError(f"{field} must be between 1 and {maximum}")
    return value


def _require_nonnegative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"invalid AWS {field}")
    return value


class AwsCloudWatchAlarmInspector:
    """Inspect at most ``max_alarms`` deployment-derived CloudWatch alarms."""

    def __init__(
        self,
        region: str,
        alarm_name_prefix: str,
        connect_timeout: float,
        read_timeout: float,
        max_attempts: int,
        *,
        max_alarms: int = 5,
    ) -> None:
        if not _IDENTITY_PART.fullmatch(alarm_name_prefix):
            raise ValueError("invalid alarm_name_prefix")
        self._alarm_name_prefix = alarm_name_prefix
        self._max_alarms = _validate_limit(max_alarms, maximum=20, field="max_alarms")
        self._client = boto3.client(
            "cloudwatch",
            region_name=region,
            config=aws_client_config(connect_timeout, read_timeout, max_attempts),
        )

    def inspect(self, scope: DiagnosticScope) -> AlarmInspection:
        # This is the only AWS identifier used, and it is deployment-derived.
        alarm_prefix = f"{self._alarm_name_prefix}-{scope.resource_suffix}"
        target = {"alarm_prefix": alarm_prefix}
        try:
            response = self._client.describe_alarms(
                AlarmNamePrefix=alarm_prefix,
                MaxRecords=self._max_alarms,
            )
            raw_alarms = response.get("MetricAlarms", []) + response.get("CompositeAlarms", [])
            if not isinstance(raw_alarms, list):
                raise ValueError("invalid CloudWatch alarm response")
            states: list[AlarmStatus] = []
            for alarm in raw_alarms[: self._max_alarms]:
                if not isinstance(alarm, dict) or alarm.get("StateValue") not in _ALARM_STATES:
                    raise ValueError("invalid CloudWatch alarm state")
                states.append(AlarmStatus(state=cast(str, alarm["StateValue"])))
            observation = {
                "scope": scope.digest,
                "target": target,
                "states": [state.state for state in states],
            }
            return AlarmInspection(
                scope_digest=scope.digest,
                evidence_ref=_opaque_reference("cloudwatch-alarms", observation),
                target_digest=_opaque_digest("cloudwatch-target", target),
                alarms=tuple(states),
                limit=self._max_alarms,
                # We intentionally do not follow pagination: plans must remain bounded.
                truncated=bool(response.get("NextToken")),
            )
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as error:
            raise DependencyUnavailable("cloudwatch_diagnostics") from error


class AwsEcsDeploymentInspector:
    """Inspect one deployment-derived ECS service and bounded deployment metadata."""

    def __init__(
        self,
        region: str,
        cluster_name: str,
        service_name_prefix: str,
        connect_timeout: float,
        read_timeout: float,
        max_attempts: int,
        *,
        max_deployments: int = 5,
    ) -> None:
        if not _IDENTITY_PART.fullmatch(cluster_name):
            raise ValueError("invalid cluster_name")
        if not _IDENTITY_PART.fullmatch(service_name_prefix):
            raise ValueError("invalid service_name_prefix")
        self._cluster_name = cluster_name
        self._service_name_prefix = service_name_prefix
        self._max_deployments = _validate_limit(
            max_deployments, maximum=20, field="max_deployments"
        )
        self._client = boto3.client(
            "ecs",
            region_name=region,
            config=aws_client_config(connect_timeout, read_timeout, max_attempts),
        )

    def inspect(self, scope: DiagnosticScope) -> EcsDeploymentInspection:
        service_name = f"{self._service_name_prefix}-{scope.resource_suffix}"
        target = {"cluster": self._cluster_name, "service": service_name}
        try:
            response = self._client.describe_services(
                cluster=self._cluster_name,
                services=[service_name],
            )
            failures = response.get("failures", [])
            services = response.get("services", [])
            if not isinstance(failures, list) or not isinstance(services, list):
                raise ValueError("invalid ECS response")
            # A provider-reported failure (including access denial or a malformed
            # service identifier) is never converted into reassuring evidence.
            if failures:
                raise ValueError("ECS service inspection failed")
            if not services:
                return self._not_found(scope, target)
            if len(services) != 1 or not isinstance(services[0], dict):
                raise ValueError("invalid ECS service response")
            service = cast(dict[str, Any], services[0])
            deployments = service.get("deployments", [])
            if not isinstance(deployments, list):
                raise ValueError("invalid ECS deployments")
            statuses = tuple(
                self._deployment_status(deployment)
                for deployment in deployments[: self._max_deployments]
            )
            desired = _require_nonnegative_int(service.get("desiredCount"), "desiredCount")
            running = _require_nonnegative_int(service.get("runningCount"), "runningCount")
            pending = _require_nonnegative_int(service.get("pendingCount"), "pendingCount")
            observation = {
                "scope": scope.digest,
                "target": target,
                "desired": desired,
                "running": running,
                "pending": pending,
                "deployments": [
                    {
                        "status": status.status,
                        "rollout_state": status.rollout_state,
                        "desired_count": status.desired_count,
                        "running_count": status.running_count,
                        "pending_count": status.pending_count,
                    }
                    for status in statuses
                ],
            }
            return EcsDeploymentInspection(
                scope_digest=scope.digest,
                evidence_ref=_opaque_reference("ecs-deployment", observation),
                target_digest=_opaque_digest("ecs-target", target),
                service_found=True,
                desired_count=desired,
                running_count=running,
                pending_count=pending,
                deployments=statuses,
                limit=self._max_deployments,
                truncated=len(deployments) > self._max_deployments,
            )
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as error:
            raise DependencyUnavailable("ecs_diagnostics") from error

    def _not_found(self, scope: DiagnosticScope, target: dict[str, str]) -> EcsDeploymentInspection:
        observation = {"scope": scope.digest, "target": target, "found": False}
        return EcsDeploymentInspection(
            scope_digest=scope.digest,
            evidence_ref=_opaque_reference("ecs-deployment", observation),
            target_digest=_opaque_digest("ecs-target", target),
            service_found=False,
            desired_count=None,
            running_count=None,
            pending_count=None,
            deployments=(),
            limit=self._max_deployments,
            truncated=False,
        )

    @staticmethod
    def _deployment_status(deployment: object) -> DeploymentStatus:
        if not isinstance(deployment, dict):
            raise ValueError("invalid ECS deployment")
        status = deployment.get("status")
        rollout_state = deployment.get("rolloutState")
        if status not in _DEPLOYMENT_STATES:
            raise ValueError("invalid ECS deployment status")
        if rollout_state is not None and rollout_state not in _ROLLOUT_STATES:
            raise ValueError("invalid ECS rollout state")
        return DeploymentStatus(
            status=cast(str, status),
            rollout_state=cast(str | None, rollout_state),
            desired_count=_require_nonnegative_int(
                deployment.get("desiredCount"), "deployment desiredCount"
            ),
            running_count=_require_nonnegative_int(
                deployment.get("runningCount"), "deployment runningCount"
            ),
            pending_count=_require_nonnegative_int(
                deployment.get("pendingCount"), "deployment pendingCount"
            ),
        )


@dataclass(frozen=True, slots=True)
class ReadOnlyDiagnosticTools:
    """Integration facade for a bounded, two-tool diagnostic plan step."""

    alarms: CloudWatchAlarmInspector
    deployments: EcsDeploymentInspector

    def inspect(
        self, tenant_id: str, service: str
    ) -> tuple[AlarmInspection, EcsDeploymentInspection]:
        scope = DiagnosticScope.from_tenant_service(tenant_id, service)
        # Each implementation performs only a single read-only AWS request.
        return self.alarms.inspect(scope), self.deployments.inspect(scope)
