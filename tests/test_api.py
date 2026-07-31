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
