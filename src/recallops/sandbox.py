"""Typed checkout sandbox and deterministic, independently derived postcheck policy."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Protocol
from uuid import UUID

from recallops.domain import (
    IncidentAnalysis,
    PolicyVerdict,
    PostcheckClassification,
    PostcheckObservation,
    SandboxExecution,
    SandboxExecutionRequest,
    SandboxMetrics,
)
from recallops.resilience import DependencyUnavailable

SANDBOX_ACTION_ID = "checkout.reduce_concurrency_and_recycle.v1"
SANDBOX_ACTION_COMMAND = "reduce worker concurrency to 24 and recycle saturated connections"
SIMULATOR_VERSION = "checkout-simulator-v1"
OBSERVATION_SOURCE = "checkout-simulator-telemetry-v1"
POLICY_VERSION = "checkout-recovery-policy-v1"


def _digest(payload: Mapping[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SandboxPolicyError(ValueError):
    pass


class ObservationProvider(Protocol):
    def collect(self, execution: SandboxExecution) -> PostcheckObservation: ...


class CheckoutSandbox:
    """Creates a typed simulation record; it never evaluates or executes command text."""

    def prepare_execution(
        self,
        incident_id: UUID,
        analysis: IncidentAnalysis,
        request: SandboxExecutionRequest,
    ) -> SandboxExecution:
        action = analysis.proposed_action
        if action.action_hash is None or request.proposal_hash != action.action_hash:
            raise SandboxPolicyError("sandbox request is not bound to the proposed action")
        if action.command != SANDBOX_ACTION_COMMAND:
            raise SandboxPolicyError("proposed action is not in the sandbox allowlist")
        before = SandboxMetrics(
            worker_concurrency=64,
            saturated_connections=40,
            latency_p95_ms=1420,
            error_rate=0.031,
        )
        after = SandboxMetrics(
            worker_concurrency=24,
            saturated_connections=3,
            latency_p95_ms=210,
            error_rate=0.004,
        )
        material: dict[str, object] = {
            "incident_id": str(incident_id),
            "tenant_id": request.tenant_id,
            "proposal_hash": request.proposal_hash,
            "action_id": SANDBOX_ACTION_ID,
            "simulator_version": SIMULATOR_VERSION,
            "idempotency_key": request.idempotency_key,
            "before": before.model_dump(mode="json"),
            "after": after.model_dump(mode="json"),
        }
        return SandboxExecution(
            incident_id=incident_id,
            tenant_id=request.tenant_id,
            actor_id=request.actor_id,
            proposal_hash=request.proposal_hash,
            action_id=SANDBOX_ACTION_ID,
            simulator_version=SIMULATOR_VERSION,
            idempotency_key=request.idempotency_key,
            before=before,
            after=after,
            execution_digest=_digest(material),
        )


class DeterministicObservationProvider:
    def collect(self, execution: SandboxExecution) -> PostcheckObservation:
        material: dict[str, object] = {
            "execution_id": str(execution.id),
            "incident_id": str(execution.incident_id),
            "tenant_id": execution.tenant_id,
            "proposal_hash": execution.proposal_hash,
            "execution_digest": execution.execution_digest,
            "source": OBSERVATION_SOURCE,
            "observation_window_seconds": 300,
            "before": execution.before.model_dump(mode="json"),
            "after": execution.after.model_dump(mode="json"),
        }
        return PostcheckObservation(
            execution_id=execution.id,
            incident_id=execution.incident_id,
            tenant_id=execution.tenant_id,
            proposal_hash=execution.proposal_hash,
            execution_digest=execution.execution_digest,
            source=OBSERVATION_SOURCE,
            observation_window_seconds=300,
            before=execution.before,
            after=execution.after,
            observation_digest=_digest(material),
        )


class UnavailableObservationProvider:
    def collect(self, execution: SandboxExecution) -> PostcheckObservation:
        del execution
        raise DependencyUnavailable("sandbox_observation_provider")


def evaluate_observation(observation: PostcheckObservation) -> PolicyVerdict:
    checks = {
        "LATENCY_RECOVERY_THRESHOLD": (
            observation.after.latency_p95_ms <= 300
            and observation.after.latency_p95_ms <= observation.before.latency_p95_ms * 0.5
        ),
        "ERROR_RATE_RECOVERY_THRESHOLD": (
            observation.after.error_rate <= 0.005
            and observation.after.error_rate <= observation.before.error_rate * 0.5
        ),
        "SATURATION_RECOVERY_THRESHOLD": (
            observation.after.saturated_connections <= 5
            and observation.after.saturated_connections < observation.before.saturated_connections
        ),
    }
    passed = [name for name, result in checks.items() if result]
    failed = [name for name, result in checks.items() if not result]
    classification = (
        PostcheckClassification.RECOVERED
        if not failed
        else PostcheckClassification.NOT_RECOVERED
    )
    return PolicyVerdict(
        classification=classification,
        policy_version=POLICY_VERSION,
        checks_passed=passed,
        checks_failed=failed,
        observation_digest=observation.observation_digest,
    )
