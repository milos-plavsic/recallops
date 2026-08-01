from fastapi.testclient import TestClient

from recallops.api import create_app
from recallops.config import Settings
from recallops.domain import Memory
from recallops.embedding import DeterministicEmbedder
from recallops.store import InMemoryStore


def execute_analyzed_action(client: TestClient, incident: dict, headers: dict[str, str]) -> str:
    action = incident["proposed_action"]
    response = client.post(
        f"/v1/incidents/{incident['incident_id']}/execution",
        headers=headers,
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


def test_judge_console_and_live_evaluation_are_served() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))

    console = client.get("/")
    report = client.get("/v1/evaluation")

    assert console.status_code == 200
    assert "RecallOps remembers consequences" in console.text
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
    assert client.get("/health").json() == {"status": "ok"}


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
    assert client.get(f"/v1/incidents/{incident_id}", headers=headers).status_code == 200
    approval = {
        "tenant_id": "demo",
        "approved": True,
        "actor_id": "operator-1",
        "reason": "diagnostic evidence verified",
    }
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval", headers=headers, json=approval
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval", headers=headers, json=approval
        ).status_code
        == 404
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
    first = client.post(f"/v1/incidents/{incident_id}/outcome", headers=headers, json=payload)
    second = client.post(f"/v1/incidents/{incident_id}/outcome", headers=headers, json=payload)
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
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
        headers=observer_headers,
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
        headers=observer_headers,
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
        headers={"X-Tenant-ID": "demo", "X-Actor-ID": "operator-reviewer"},
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
    response = client.get(
        "/v1/incidents/00000000-0000-0000-0000-000000000001"
    )
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
