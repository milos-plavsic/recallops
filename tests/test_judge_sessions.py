import hashlib

from fastapi.testclient import TestClient
from pydantic import SecretStr

from recallops.api import create_app
from recallops.auth import JudgeSessionAuthenticator
from recallops.config import Settings
from recallops.domain import Memory
from recallops.embedding import DeterministicEmbedder
from recallops.sessions import InMemoryJudgeSessionRepository
from recallops.store import InMemoryStore

OPERATOR_CODE = "operator-bootstrap-code-2026"
REVIEWER_CODE = "reviewer-bootstrap-code-2026"


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "store": "memory",
        "auth_mode": "judge",
        "public_origin": "http://testserver",
        "judge_tenant_id": "judge",
        "judge_operator_bootstrap_sha256": digest(OPERATOR_CODE),
        "judge_reviewer_bootstrap_sha256": digest(REVIEWER_CODE),
        "judge_rate_limit_key": SecretStr("test-rate-limit-key-with-enough-entropy"),
        "judge_cookie_secure": False,
    }
    values.update(updates)
    return Settings(**values)


def exchange(client: TestClient, code: str) -> dict[str, object]:
    response = client.post(
        "/v1/judge/session/exchange",
        headers={"Origin": "http://testserver"},
        json={"code": code},
    )
    assert response.status_code == 200
    return response.json()


def test_judge_exchange_uses_opaque_cookie_and_server_derived_identity() -> None:
    client = TestClient(create_app(settings(), InMemoryStore()))
    assert client.get("/v1/me").status_code == 401
    assert (
        client.post(
            "/v1/judge/session/exchange",
            headers={"Origin": "https://evil.example"},
            json={"code": OPERATOR_CODE},
        ).status_code
        == 403
    )

    result = exchange(client, OPERATOR_CODE)

    assert result["identity"] == {
        "subject": "judge-operator",
        "tenant_id": "judge",
        "roles": ["agent", "operator"],
        "auth_method": "judge_session",
    }
    cookie = client.cookies.get("recallops_session")
    assert cookie is not None and OPERATOR_CODE not in cookie
    assert (
        "HttpOnly"
        in client.post(
            "/v1/judge/session/exchange",
            headers={"Origin": "http://testserver"},
            json={"code": OPERATOR_CODE},
        ).headers["set-cookie"]
    )
    assert client.get("/v1/me").json()["subject"] == "judge-operator"


def test_judge_protected_transition_requires_origin_and_csrf() -> None:
    embedder = DeterministicEmbedder()
    seed = Memory(
        tenant_id="judge",
        service="checkout",
        service_version="v1",
        symptom="latency spike",
        action="reduce concurrency",
        outcome="recovered",
        outcome_score=1,
        confidence=0.95,
        reviewed_by="seed-reviewer",
        embedding=embedder.embed("checkout latency spike"),
    )
    client = TestClient(create_app(settings(), InMemoryStore([seed])))
    credentials = exchange(client, OPERATOR_CODE)
    incident = client.post(
        "/v1/incidents",
        headers={"X-RecallOps-Channel": "webmcp"},
        json={
            "tenant_id": "judge",
            "service": "checkout",
            "service_version": "v1",
            "symptom": "latency spike",
            "idempotency_key": "judge-csrf-proof",
        },
    ).json()
    approval = {
        "tenant_id": "judge",
        "actor_id": "judge-operator",
        "approved": True,
        "reason": "reviewed exact proposal",
    }
    path = f"/v1/incidents/{incident['incident_id']}/approval"
    base_headers = {"X-RecallOps-Channel": "ui", "X-Workflow-Epoch": "1"}
    assert client.post(path, headers=base_headers, json=approval).status_code == 403
    assert (
        client.post(
            path,
            headers={
                **base_headers,
                "Origin": "https://evil.example",
                "X-CSRF-Token": str(credentials["csrf_token"]),
            },
            json=approval,
        ).status_code
        == 403
    )
    accepted = client.post(
        path,
        headers={
            **base_headers,
            "Origin": "http://testserver",
            "X-CSRF-Token": str(credentials["csrf_token"]),
        },
        json=approval,
    )
    assert accepted.status_code == 200


def test_judge_exchange_is_rate_limited_and_roles_cannot_be_supplied() -> None:
    configured = settings(judge_exchange_attempt_limit=2)
    client = TestClient(create_app(configured, InMemoryStore()))
    for _ in range(2):
        assert (
            client.post(
                "/v1/judge/session/exchange",
                headers={"Origin": "http://testserver"},
                json={"code": "wrong-bootstrap-code"},
            ).status_code
            == 401
        )
    limited = client.post(
        "/v1/judge/session/exchange",
        headers={"Origin": "http://testserver"},
        json={"code": OPERATOR_CODE},
    )
    assert limited.status_code == 429


def test_judge_logout_revokes_server_session() -> None:
    client = TestClient(create_app(settings(), InMemoryStore()))
    credentials = exchange(client, REVIEWER_CODE)
    response = client.post(
        "/v1/judge/session/logout",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": str(credentials["csrf_token"]),
        },
    )
    assert response.status_code == 200
    assert response.json() == {"revoked": True}
    assert client.get("/v1/me").status_code == 401


def test_production_judge_cookie_uses_host_prefix_and_secure_attributes() -> None:
    client = TestClient(create_app(settings(judge_cookie_secure=True), InMemoryStore()))
    response = client.post(
        "/v1/judge/session/exchange",
        headers={"Origin": "http://testserver"},
        json={"code": OPERATOR_CODE},
    )
    cookie = response.headers["set-cookie"]
    assert response.status_code == 200
    assert cookie.startswith("__Host-recallops_session=")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    assert "Secure" in cookie


def test_judge_authenticator_rejects_missing_configuration_and_invalid_session() -> None:
    repository = InMemoryJudgeSessionRepository()
    try:
        JudgeSessionAuthenticator(Settings(auth_mode="judge"), repository)
    except ValueError as error:
        assert "bootstrap" in str(error)
    else:
        raise AssertionError("missing judge configuration was accepted")

    authenticator = JudgeSessionAuthenticator(settings(), repository)
    try:
        authenticator.authenticate(None, None, None, None, "invalid")
    except ValueError as error:
        assert "invalid or expired" in str(error)
    else:
        raise AssertionError("invalid judge session was accepted")
