from fastapi.testclient import TestClient

from recallops.api import create_app
from recallops.config import Settings
from recallops.store import InMemoryStore


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
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    headers = {"X-Tenant-ID": "demo"}
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
    incident_id = created.json()["incident_id"]
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
    headers = {"X-Tenant-ID": "demo"}
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
    incident_id = created.json()["incident_id"]
    payload = {
        "tenant_id": "demo",
        "action_taken": "reduce worker concurrency",
        "outcome": "latency returned to baseline",
        "outcome_score": 1.0,
        "confidence": 0.97,
    }
    first = client.post(f"/v1/incidents/{incident_id}/outcome", headers=headers, json=payload)
    second = client.post(f"/v1/incidents/{incident_id}/outcome", headers=headers, json=payload)
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert "embedding" not in first.json()


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
        },
    )
    assert response.status_code == 403


def test_outcome_for_unknown_incident_returns_not_found() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.post(
        "/v1/incidents/00000000-0000-0000-0000-000000000001/outcome",
        headers={"X-Tenant-ID": "demo"},
        json={
            "tenant_id": "demo",
            "action_taken": "inspect service metrics",
            "outcome": "no incident existed",
            "outcome_score": 0,
            "confidence": 0.5,
        },
    )
    assert response.status_code == 404
