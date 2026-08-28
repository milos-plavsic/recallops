from unittest.mock import MagicMock
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from recallops.api import create_app
from recallops.config import Settings
from recallops.domain import Memory
from recallops.embedding import DeterministicEmbedder
from recallops.resilience import DependencyUnavailable
from recallops.service import IncidentWorkflowError
from recallops.store import InMemoryStore
from recallops.workflow import RequestChannel, WorkflowState


def execute_analyzed_action(client: TestClient, incident: dict, headers: dict[str, str]) -> str:
    action = incident["proposed_action"]
    workflow = client.get(
        f"/v1/incidents/{incident['incident_id']}/capabilities", headers=headers
    ).json()
    workflow_headers = {
        **headers,
        "X-RecallOps-Channel": "ui",
        "X-Workflow-Epoch": str(workflow["epoch"]),
    }
    response = client.post(
        f"/v1/incidents/{incident['incident_id']}/execution",
        headers=workflow_headers,
        json={
            "tenant_id": headers["X-Tenant-ID"],
            "actor_id": headers["X-Actor-ID"],
            "action_hash": action["action_hash"],
            "action_taken": action["command"],
            "evidence_refs": ["test://execution/verified"],
        },
    )
    assert response.status_code == 201
    return action["command"]


def authoritative_headers(
    client: TestClient, incident_id: str, headers: dict[str, str]
) -> dict[str, str]:
    workflow = client.get(f"/v1/incidents/{incident_id}/capabilities", headers=headers).json()
    return {
        **headers,
        "X-RecallOps-Channel": "ui",
        "X-Workflow-Epoch": str(workflow["epoch"]),
    }


def test_judge_console_and_live_evaluation_are_served() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))

    console = client.get("/")
    report = client.get("/v1/evaluation")

    assert console.status_code == 200
    assert "RecallOps remembers consequences" in console.text
    assert "Replayable agent trace" in client.get("/assets/app.js").text
    assert report.status_code == 200
    assert report.json()["passed"] is True
    assert report.json()["similarity_only"]["unsafe_selection_rate"] > 0


def test_tenant_boundary_is_enforced() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.post(
        "/v1/incidents",
        headers={"X-Tenant-ID": "other"},
        json={
            "tenant_id": "demo",
            "service": "checkout",
            "service_version": "v1",
            "symptom": "elevated latency",
            "idempotency_key": "event-0001",
        },
    )
    assert response.status_code == 403


def test_health() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.get("/health")
    assert response.json() == {"status": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["origin-agent-cluster"] == "?1"
    assert "tools=(self)" in response.headers["permissions-policy"]
    assert client.get("/live").json() == {"status": "alive"}
    assert client.get("/ready").json() == {"status": "ready"}


def test_system_status_distinguishes_configuration_from_runtime_verification() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.get("/v1/system/status")
    assert response.status_code == 200
    assert response.json()["embedding_space"].startswith("deterministic:")
    assert response.json()["bedrock_runtime_verified"] is None


def test_diagnostics_configuration_requires_all_resource_prefixes() -> None:
    with pytest.raises(ValueError, match="AWS diagnostics require"):
        create_app(Settings(store="memory", diagnostic_provider="aws"), InMemoryStore())


def test_complete_aws_diagnostics_configuration_builds_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[str] = []
    monkeypatch.setattr(
        "recallops.api.AwsCloudWatchAlarmInspector",
        lambda *args, **kwargs: created.append("alarms") or MagicMock(),
    )
    monkeypatch.setattr(
        "recallops.api.AwsEcsDeploymentInspector",
        lambda *args, **kwargs: created.append("ecs") or MagicMock(),
    )
    app = create_app(
        Settings(
            store="memory",
            diagnostic_provider="aws",
            diagnostic_alarm_prefix="recallops",
            diagnostic_ecs_cluster="recallops",
            diagnostic_ecs_service_prefix="recallops",
        ),
        InMemoryStore(),
    )
    assert app.state.service._diagnostic_tools is not None
    assert created == ["alarms", "ecs"]


def test_oidc_token_origin_is_added_to_content_security_policy() -> None:
    settings = Settings(
        store="memory",
        oidc_token_url="https://identity.example.test/oauth/token",
    )
    response = TestClient(create_app(settings, InMemoryStore())).get("/health")
    assert "https://identity.example.test" in response.headers["content-security-policy"]


@pytest.mark.parametrize("mode", ["false", "exception"])
def test_readiness_fails_closed(mode: str) -> None:
    store = InMemoryStore()
    store.ready = MagicMock(
        return_value=False, side_effect=RuntimeError("secret") if mode == "exception" else None
    )
    response = TestClient(create_app(Settings(store="memory"), store)).get("/ready")
    assert response.status_code == 503
    assert response.json() == {"status": "not_ready"}
    assert "secret" not in response.text


def test_workflow_failures_map_to_safe_http_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    app = create_app(Settings(store="memory"), InMemoryStore())
    client = TestClient(app)
    headers = {
        "X-Tenant-ID": "demo",
        "X-Actor-ID": "operator",
        "X-Roles": "operator",
        "X-RecallOps-Channel": "ui",
        "X-Workflow-Epoch": "1",
    }
    incident_id = "00000000-0000-0000-0000-000000000001"
    workflow_id = UUID(incident_id)
    app.state.workflows.ensure_for_analysis("demo", workflow_id, "0" * 64, mutating=True)
    approval = {
        "tenant_id": "demo",
        "actor_id": "operator",
        "approved": True,
        "reason": "reviewed",
    }
    monkeypatch.setattr(
        app.state.service,
        "decide_approval",
        MagicMock(side_effect=IncidentWorkflowError("approval conflict")),
    )
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval", headers=headers, json=approval
        ).status_code
        == 409
    )

    app.state.workflows.transition(
        workflow_id,
        "demo",
        1,
        WorkflowState.AWAITING_OPERATOR_APPROVAL,
        WorkflowState.APPROVED_AWAITING_EXECUTION,
        channel=RequestChannel.UI,
        actor_subject="operator",
        role="operator",
    )
    headers["X-Workflow-Epoch"] = "2"

    execution = {
        "tenant_id": "demo",
        "actor_id": "operator",
        "action_hash": "0" * 64,
        "action_taken": "inspect",
        "evidence_refs": ["test://evidence"],
    }
    monkeypatch.setattr(
        app.state.service,
        "prepare_execution",
        MagicMock(side_effect=DependencyUnavailable("bedrock")),
    )
    unavailable = client.post(
        f"/v1/incidents/{incident_id}/execution", headers=headers, json=execution
    )
    assert unavailable.status_code == 503 and unavailable.headers["retry-after"] == "30"
    monkeypatch.setattr(
        app.state.service,
        "prepare_execution",
        MagicMock(side_effect=IncidentWorkflowError("execution conflict")),
    )
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/execution", headers=headers, json=execution
        ).status_code
        == 409
    )
    monkeypatch.setattr(app.state.service, "prepare_execution", MagicMock(return_value=None))
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/execution", headers=headers, json=execution
        ).status_code
        == 404
    )

    app.state.workflows.transition(
        workflow_id,
        "demo",
        2,
        WorkflowState.APPROVED_AWAITING_EXECUTION,
        WorkflowState.OBSERVING_POSTCHECK,
        channel=RequestChannel.UI,
        actor_subject="operator",
        role="operator",
    )
    headers["X-Workflow-Epoch"] = "3"

    outcome = {
        "tenant_id": "demo",
        "actor_id": "operator",
        "action_taken": "inspect",
        "outcome": "healthy",
        "outcome_score": 1,
        "confidence": 0.8,
    }
    monkeypatch.setattr(
        app.state.service,
        "prepare_outcome",
        MagicMock(side_effect=DependencyUnavailable("embedding")),
    )
    unavailable = client.post(f"/v1/incidents/{incident_id}/outcome", headers=headers, json=outcome)
    assert unavailable.status_code == 503 and unavailable.headers["retry-after"] == "30"
    monkeypatch.setattr(
        app.state.service,
        "prepare_outcome",
        MagicMock(side_effect=IncidentWorkflowError("outcome conflict")),
    )
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/outcome", headers=headers, json=outcome
        ).status_code
        == 409
    )


def test_execution_rejects_actor_mismatch_before_service_call() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.post(
        "/v1/incidents/00000000-0000-0000-0000-000000000001/execution",
        headers={"X-Tenant-ID": "demo", "X-Actor-ID": "operator"},
        json={
            "tenant_id": "demo",
            "actor_id": "someone-else",
            "action_hash": "0" * 64,
            "action_taken": "inspect",
            "evidence_refs": ["test://evidence"],
        },
    )
    assert response.status_code == 403


def test_incident_read_and_single_approval() -> None:
    embedder = DeterministicEmbedder()
    store = InMemoryStore(
        [
            Memory(
                tenant_id="demo",
                service="checkout",
                service_version="v1",
                symptom="elevated latency",
                action="reduce worker concurrency",
                outcome="latency recovered",
                outcome_score=1.0,
                confidence=0.95,
                embedding=embedder.embed("checkout elevated latency"),
            )
        ]
    )
    client = TestClient(create_app(Settings(store="memory"), store))
    headers = {"X-Tenant-ID": "demo", "X-Actor-ID": "operator-1"}
    created = client.post(
        "/v1/incidents",
        headers=headers,
        json={
            "tenant_id": "demo",
            "service": "checkout",
            "service_version": "v1",
            "symptom": "elevated latency",
            "idempotency_key": "event-0002",
        },
    )
    assert created.status_code == 201
    incident = created.json()
    incident_id = incident["incident_id"]
    assert [step["tool"] for step in incident["agent_trace"]] == [
        "embed_incident",
        "retrieve_governed_memory",
        "reason_from_evidence",
    ]
    assert all(step["risk"] == "read_only" for step in incident["agent_trace"])
    assert client.get(f"/v1/incidents/{incident_id}", headers=headers).status_code == 200
    approval = {
        "tenant_id": "demo",
        "approved": True,
        "actor_id": "operator-1",
        "reason": "diagnostic evidence verified",
    }
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval",
            headers=authoritative_headers(client, incident_id, headers),
            json=approval,
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval",
            headers={**headers, "X-RecallOps-Channel": "ui", "X-Workflow-Epoch": "1"},
            json=approval,
        ).status_code
        == 409
    )


def test_unknown_incident_read_returns_not_found() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.get(
        "/v1/incidents/00000000-0000-0000-0000-000000000001",
        headers={"X-Tenant-ID": "demo"},
    )
    assert response.status_code == 404


def test_approval_rejects_cross_tenant_payload() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.post(
        "/v1/incidents/00000000-0000-0000-0000-000000000001/approval",
        headers={"X-Tenant-ID": "other"},
        json={
            "tenant_id": "demo",
            "approved": False,
            "actor_id": "operator-1",
            "reason": "tenant mismatch must be rejected",
        },
    )
    assert response.status_code == 403


def test_outcome_is_learned_once_and_embedding_is_not_exposed() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    headers = {"X-Tenant-ID": "demo", "X-Actor-ID": "operator-observer"}
    created = client.post(
        "/v1/incidents",
        headers=headers,
        json={
            "tenant_id": "demo",
            "service": "checkout",
            "service_version": "v1",
            "symptom": "elevated latency",
            "idempotency_key": "event-outcome-0001",
        },
    )
    incident = created.json()
    incident_id = incident["incident_id"]
    action_taken = execute_analyzed_action(client, incident, headers)
    payload = {
        "tenant_id": "demo",
        "action_taken": action_taken,
        "outcome": "latency returned to baseline",
        "outcome_score": 1.0,
        "confidence": 0.97,
        "actor_id": "operator-observer",
    }
    outcome_headers = authoritative_headers(client, incident_id, headers)
    first = client.post(
        f"/v1/incidents/{incident_id}/outcome", headers=outcome_headers, json=payload
    )
    second = client.post(
        f"/v1/incidents/{incident_id}/outcome", headers=outcome_headers, json=payload
    )
    assert first.status_code == 201
    assert second.status_code == 409
    assert "embedding" not in first.json()
    assert first.json()["state"] == "pending_review"


def test_outcome_rejects_cross_tenant_access() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.post(
        "/v1/incidents/00000000-0000-0000-0000-000000000001/outcome",
        headers={"X-Tenant-ID": "other"},
        json={
            "tenant_id": "demo",
            "action_taken": "unsafe action",
            "outcome": "unknown",
            "outcome_score": 0,
            "confidence": 0.5,
            "actor_id": "operator-1",
        },
    )
    assert response.status_code == 403


def test_outcome_for_unknown_incident_returns_not_found() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.post(
        "/v1/incidents/00000000-0000-0000-0000-000000000001/outcome",
        headers={"X-Tenant-ID": "demo", "X-Actor-ID": "operator-1"},
        json={
            "tenant_id": "demo",
            "action_taken": "inspect service metrics",
            "outcome": "no incident existed",
            "outcome_score": 0,
            "confidence": 0.5,
            "actor_id": "operator-1",
        },
    )
    assert response.status_code == 404


def test_memory_governance_enforces_four_eyes_and_tenant_boundary() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    observer_headers = {"X-Tenant-ID": "demo", "X-Actor-ID": "operator-observer"}
    incident = client.post(
        "/v1/incidents",
        headers=observer_headers,
        json={
            "tenant_id": "demo",
            "service": "checkout",
            "service_version": "v1",
            "symptom": "elevated latency",
            "idempotency_key": "event-governance-0001",
        },
    ).json()
    action_taken = execute_analyzed_action(client, incident, observer_headers)
    memory = client.post(
        f"/v1/incidents/{incident['incident_id']}/outcome",
        headers=authoritative_headers(client, incident["incident_id"], observer_headers),
        json={
            "tenant_id": "demo",
            "action_taken": action_taken,
            "outcome": "latency returned to baseline",
            "outcome_score": 1.0,
            "confidence": 0.97,
            "actor_id": "operator-observer",
        },
    ).json()
    self_review = client.post(
        f"/v1/memories/{memory['id']}/governance",
        headers=authoritative_headers(client, incident["incident_id"], observer_headers),
        json={
            "tenant_id": "demo",
            "actor_id": "operator-observer",
            "action": "activate",
            "reason": "self approval must be rejected",
        },
    )
    assert self_review.status_code == 409

    activated = client.post(
        f"/v1/memories/{memory['id']}/governance",
        headers=authoritative_headers(
            client,
            incident["incident_id"],
            {"X-Tenant-ID": "demo", "X-Actor-ID": "operator-reviewer"},
        ),
        json={
            "tenant_id": "demo",
            "actor_id": "operator-reviewer",
            "action": "activate",
            "reason": "independent telemetry confirms recovery",
        },
    )
    assert activated.status_code == 200
    assert activated.json()["state"] == "active"

    cross_tenant = client.post(
        f"/v1/memories/{memory['id']}/governance",
        headers={"X-Tenant-ID": "other"},
        json={
            "tenant_id": "demo",
            "actor_id": "attacker",
            "action": "revoke",
            "reason": "cross tenant mutation",
        },
    )
    assert cross_tenant.status_code == 403


def test_unknown_memory_governance_returns_not_found() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.post(
        "/v1/memories/00000000-0000-0000-0000-000000000001/governance",
        headers={"X-Tenant-ID": "demo", "X-Actor-ID": "operator-reviewer"},
        json={
            "tenant_id": "demo",
            "actor_id": "operator-reviewer",
            "action": "revoke",
            "reason": "memory does not exist",
        },
    )
    assert response.status_code == 404


def test_demo_auth_requires_tenant_identity() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.get("/v1/incidents/00000000-0000-0000-0000-000000000001")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_public_config_and_authenticated_identity() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    config = client.get("/v1/config")
    assert config.status_code == 200
    assert config.json()["auth_required"] is False
    identity = client.get(
        "/v1/me",
        headers={"X-Tenant-ID": "demo", "X-Actor-ID": "operator-1", "X-Roles": "operator"},
    )
    assert identity.status_code == 200
    assert identity.json() == {
        "subject": "operator-1",
        "tenant_id": "demo",
        "roles": ["operator"],
    }


def test_governance_requires_reviewer_role() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.post(
        "/v1/memories/00000000-0000-0000-0000-000000000001/governance",
        headers={
            "X-Tenant-ID": "demo",
            "X-Actor-ID": "operator-1",
            "X-Roles": "operator",
        },
        json={
            "tenant_id": "demo",
            "actor_id": "operator-1",
            "action": "revoke",
            "reason": "operators cannot govern memory",
        },
    )
    assert response.status_code == 403
