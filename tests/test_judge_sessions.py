from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

from fastapi.testclient import TestClient
from pydantic import SecretStr

from recallops.api import create_app
from recallops.auth import JudgeSessionAuthenticator, JudgeSessionError
from recallops.config import Settings
from recallops.domain import Memory, MemoryState
from recallops.embedding import DeterministicEmbedder
from recallops.sessions import (
    InMemoryJudgeSessionRepository,
    JudgeRun,
    JudgeRunCapacityError,
    ReviewHandoff,
)
from recallops.store import InMemoryStore
from recallops.workflow import WorkflowState


def settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "store": "memory",
        "auth_mode": "judge",
        "public_origin": "http://testserver",
        "judge_rate_limit_key": SecretStr("test-rate-limit-key-with-enough-entropy"),
        "judge_cookie_secure": False,
    }
    values.update(updates)
    return Settings(**values)  # type: ignore[arg-type]


def create_run(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    assert response.status_code == 201
    return cast(dict[str, object], response.json())


def make_run(*, suffix: int = 1, expired: bool = False) -> JudgeRun:
    now = datetime.now(UTC)
    return JudgeRun(
        run_id=UUID(f"00000000-0000-0000-0000-{suffix:012d}"),
        tenant_id=f"judge_test_{suffix}",
        generation=1,
        scenario_version="scenario-v1",
        source_incident_id=UUID(f"10000000-0000-0000-0000-{suffix:012d}"),
        operator_subject=f"operator_{suffix}",
        build_sha="abc123",
        capability_policy_version="policy-v1",
        created_at=now,
        expires_at=now + timedelta(minutes=-1 if expired else 5),
    )


def test_judge_runs_are_isolated_server_derived_and_opaque() -> None:
    app = create_app(settings(), InMemoryStore())
    first, second = TestClient(app), TestClient(app)
    assert first.get("/v1/me").status_code == 401
    one, two = create_run(first), create_run(second)
    run_one, run_two = one["run"], two["run"]
    assert isinstance(run_one, dict) and isinstance(run_two, dict)
    assert run_one["run_id"] != run_two["run_id"]
    assert run_one["incident_id"] != run_two["incident_id"]
    identity = one["identity"]
    assert isinstance(identity, dict) and identity["roles"] == ["agent", "operator"]
    cookie = first.cookies.get("recallops_operator")
    assert cookie is not None and str(identity["subject"]) not in cookie
    assert "tenant_id" not in one
    assert second.get(f"/v1/incidents/{run_one['incident_id']}").status_code == 404


def test_run_launch_validates_origin_media_body_and_quota() -> None:
    client = TestClient(create_app(settings(judge_run_launch_limit=2), InMemoryStore()))
    assert client.post("/v1/judge/runs", json={}).status_code == 403
    assert (
        client.post(
            "/v1/judge/runs",
            headers={"Origin": "https://evil.example", "Content-Type": "application/json"},
            json={},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/v1/judge/runs",
            headers={"Origin": "http://testserver", "Content-Type": "text/plain"},
            content="{}",
        ).status_code
        == 415
    )
    assert (
        client.post(
            "/v1/judge/runs",
            headers={"Origin": "http://testserver", "Content-Type": "application/json"},
            json={"tenant_id": "attacker"},
        ).status_code
        == 400
    )
    create_run(client)
    create_run(client)
    assert (
        client.post(
            "/v1/judge/runs",
            headers={"Origin": "http://testserver", "Content-Type": "application/json"},
            json={},
        ).status_code
        == 429
    )
    capacity = TestClient(
        create_app(settings(judge_active_run_limit=1, judge_run_launch_limit=3), InMemoryStore())
    )
    create_run(capacity)
    assert capacity.get("/v1/operator/run").status_code == 200
    assert (
        capacity.post(
            "/v1/judge/runs",
            headers={"Origin": "http://testserver", "Content-Type": "application/json"},
            json={},
        ).status_code
        == 503
    )


def test_reset_rotates_every_authority_binding_and_old_cookie_stays_dead() -> None:
    app = create_app(settings(), InMemoryStore())
    client = TestClient(app)
    initial = create_run(client)
    old_cookie = client.cookies.get("recallops_operator")
    old_run = initial["run"]
    assert isinstance(old_run, dict)
    assert client.post("/v1/operator/run/reset").status_code == 403
    assert (
        client.post(
            "/v1/operator/run/reset",
            headers={"Origin": "http://testserver", "X-CSRF-Token": "wrong-token"},
        ).status_code
        == 403
    )
    response = client.post(
        "/v1/operator/run/reset",
        headers={"Origin": "http://testserver", "X-CSRF-Token": str(initial["csrf_token"])},
    )
    assert response.status_code == 201
    new_run = response.json()["run"]
    assert new_run["run_id"] != old_run["run_id"]
    assert new_run["incident_id"] != old_run["incident_id"]
    assert new_run["generation"] == 2
    assert client.cookies.get("recallops_operator") != old_cookie
    persisted_old_run = app.state.judge_repository.get_run(UUID(str(old_run["run_id"])))
    assert persisted_old_run is not None
    reset_events = app.state.ledger_repository.list_events(
        persisted_old_run.run_id, persisted_old_run.tenant_id
    )
    assert [event.sequence for event in reset_events] == [1, 2]
    assert reset_events[0].reason_code == "RUN_GENESIS_ACCEPTED"
    assert reset_events[1].reason_code == "WORKFLOW_RESET_ACCEPTED"
    assert reset_events[1].capabilities_after == ()
    timeline = client.get("/v1/evidence/timeline")
    assert timeline.status_code == 200
    assert timeline.json()["authority_claim"].startswith("Only authority_commit")
    client.cookies.set("recallops_operator", str(old_cookie))
    assert client.get("/v1/operator/run").status_code == 401


def test_reset_compare_and_swap_has_one_authoritative_result() -> None:
    app = create_app(settings(), InMemoryStore())
    client = TestClient(app)
    started = create_run(client)
    app.state.judge_repository.reset_run = lambda _run_id: False
    response = client.post(
        "/v1/operator/run/reset",
        headers={"Origin": "http://testserver", "X-CSRF-Token": str(started["csrf_token"])},
    )
    assert response.status_code == 409


def test_mixed_role_cookies_are_selected_by_route() -> None:
    client = TestClient(create_app(settings(), InMemoryStore()))
    create_run(client)
    client.cookies.set("recallops_reviewer", "attacker-controlled-cookie")
    response = client.get("/v1/me")
    assert response.status_code == 200
    assert client.get("/v1/reviewer/evidence").status_code == 401


def test_reviewer_handoff_is_single_use_purpose_bound_and_separate() -> None:
    store = InMemoryStore()
    app = create_app(settings(), store)
    operator = TestClient(app)
    started = create_run(operator)
    run, identity = started["run"], started["identity"]
    assert isinstance(run, dict) and isinstance(identity, dict)
    run_record = app.state.judge_repository.get_run(UUID(str(run["run_id"])))
    assert run_record is not None
    incident_id = run_record.source_incident_id
    memory = Memory(
        tenant_id=run_record.tenant_id,
        service="checkout",
        service_version="v2.4.1",
        symptom="checkout latency",
        action="restore bounded concurrency",
        outcome="recovered",
        outcome_score=1,
        confidence=0.95,
        valid=False,
        state=MemoryState.PENDING_REVIEW,
        source_incident_id=incident_id,
        observed_by="agent_assessor",
        embedding=DeterministicEmbedder().embed("checkout latency"),
    )
    store.save_outcome_memory(memory)
    repository = app.state.workflows._repository
    current = repository.get(incident_id, run_record.tenant_id)
    assert current is not None
    repository.transition(
        incident_id,
        run_record.tenant_id,
        current.epoch,
        current.state,
        WorkflowState.PENDING_REVIEW,
        operator_subject=str(identity["subject"]),
    )
    issued = operator.post(
        "/v1/operator/reviewer-handoff",
        headers={"Origin": "http://testserver", "X-CSRF-Token": str(started["csrf_token"])},
        json={"purpose": "initial_review", "memory_digest": memory.memory_digest},
    )
    assert issued.status_code == 201
    code = urlsplit(issued.json()["reviewer_url"]).fragment.removeprefix("review=")
    assert code and code not in repr(app.state.judge_repository._handoffs)
    reviewer = TestClient(app)
    exchanged = reviewer.post(
        "/v1/judge/reviewer-exchange",
        headers={"Origin": "http://testserver"},
        json={"code": code},
    )
    assert exchanged.status_code == 200
    assert exchanged.json()["identity"]["roles"] == ["reviewer"]
    assert exchanged.json()["identity"]["subject"] != identity["subject"]
    assert reviewer.cookies.get("recallops_reviewer") is not None
    replay = TestClient(app).post(
        "/v1/judge/reviewer-exchange",
        headers={"Origin": "http://testserver"},
        json={"code": code},
    )
    assert replay.status_code == 401


def test_handoff_and_exchange_reject_missing_prerequisites() -> None:
    store = InMemoryStore()
    app = create_app(settings(judge_exchange_attempt_limit=1), store)
    operator = TestClient(app)
    started = create_run(operator)
    headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": str(started["csrf_token"]),
    }
    assert (
        operator.post(
            "/v1/operator/reviewer-handoff",
            headers=headers,
            json={"purpose": "invalid", "memory_digest": "0" * 64},
        ).status_code
        == 422
    )
    assert (
        operator.post(
            "/v1/operator/reviewer-handoff",
            headers=headers,
            json={"purpose": "initial_review", "memory_digest": "0" * 64},
        ).status_code
        == 409
    )
    run_data = started["run"]
    assert isinstance(run_data, dict)
    run = app.state.judge_repository.get_run(UUID(str(run_data["run_id"])))
    assert run is not None
    workflow_repository = app.state.workflows._repository
    workflow = workflow_repository.get(run.source_incident_id, run.tenant_id)
    assert workflow is not None
    workflow_repository.transition(
        run.source_incident_id,
        run.tenant_id,
        workflow.epoch,
        workflow.state,
        WorkflowState.PENDING_REVIEW,
    )
    assert (
        operator.post(
            "/v1/operator/reviewer-handoff",
            headers=headers,
            json={"purpose": "initial_review", "memory_digest": "0" * 64},
        ).status_code
        == 409
    )
    active_memory = Memory(
        tenant_id=run.tenant_id,
        service="checkout",
        service_version="v2.4.1",
        symptom="checkout latency",
        action="restore bounded concurrency",
        outcome="recovered",
        outcome_score=1,
        confidence=0.95,
        state=MemoryState.ACTIVE,
        source_incident_id=run.source_incident_id,
        observed_by="agent_assessor",
        embedding=DeterministicEmbedder().embed("checkout latency"),
    )
    store.save_outcome_memory(active_memory)
    assert (
        operator.post(
            "/v1/operator/reviewer-handoff",
            headers=headers,
            json={"purpose": "initial_review", "memory_digest": active_memory.memory_digest},
        ).status_code
        == 409
    )
    pending = workflow_repository.get(run.source_incident_id, run.tenant_id)
    assert pending is not None
    workflow_repository.transition(
        run.source_incident_id,
        run.tenant_id,
        pending.epoch,
        pending.state,
        WorkflowState.REVIEWED,
    )
    assert (
        operator.post(
            "/v1/operator/reviewer-handoff",
            headers=headers,
            json={"purpose": "revocation", "memory_digest": active_memory.memory_digest},
        ).status_code
        == 201
    )
    reviewer = TestClient(app)
    assert reviewer.post("/v1/judge/reviewer-exchange", json={"code": "x" * 43}).status_code == 403
    assert (
        reviewer.post(
            "/v1/judge/reviewer-exchange",
            headers={"Origin": "http://testserver"},
            json={"code": "short"},
        ).status_code
        == 401
    )
    assert (
        reviewer.post(
            "/v1/judge/reviewer-exchange",
            headers={"Origin": "http://testserver"},
            json={"code": "x" * 43},
        ).status_code
        == 401
    )
    assert (
        reviewer.post(
            "/v1/judge/reviewer-exchange",
            headers={"Origin": "http://testserver"},
            json={"code": "y" * 43},
        ).status_code
        == 429
    )


def test_expired_handoff_and_same_subject_reviewer_fail_closed() -> None:
    repository = InMemoryJudgeSessionRepository()
    now = datetime.now(UTC)
    run = JudgeRun(
        run_id=UUID("00000000-0000-0000-0000-000000000001"),
        tenant_id="judge_test",
        generation=1,
        scenario_version="scenario-v1",
        source_incident_id=UUID("00000000-0000-0000-0000-000000000002"),
        operator_subject="operator_subject",
        build_sha="abc123",
        capability_policy_version="policy-v1",
        created_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    repository.save_run(run, 100)
    repository.save_handoff(
        ReviewHandoff(
            code_hash="a" * 64,
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            workflow_id=run.source_incident_id,
            memory_id=UUID("00000000-0000-0000-0000-000000000003"),
            memory_digest="b" * 64,
            purpose="initial_review",
            issued_by_subject=run.operator_subject,
            expires_at=now - timedelta(seconds=1),
        )
    )
    assert repository.consume_handoff("a" * 64) is None
    authenticator = JudgeSessionAuthenticator(settings(), repository)
    try:
        authenticator.create_session(
            "reviewer",
            run_id=run.run_id,
            tenant_id=run.tenant_id,
            generation=run.generation,
            subject=run.operator_subject,
        )
    except JudgeSessionError as error:
        assert "independent" in str(error)
    else:
        raise AssertionError("operator subject received reviewer authority")


def test_in_memory_repository_expiry_duplicates_and_reset_fail_closed() -> None:
    repository = InMemoryJudgeSessionRepository()
    repository._attempts["client"] = (datetime.now(UTC) - timedelta(seconds=61), 99)
    assert repository.consume_attempt("client", 1, 60)
    repository.revoke("missing")
    assert repository.get_run(UUID(int=0)) is None
    expired = make_run(expired=True)
    repository.save_run(expired, 100)
    expired_result = repository.get_run(expired.run_id)
    assert expired_result is not None and expired_result.status == "expired"
    assert not repository.run_is_current(expired.run_id, expired.tenant_id, 1)
    assert not repository.reset_run(UUID(int=0))
    assert not repository.reset_run(expired.run_id)

    active = make_run(suffix=2)
    repository.save_run(active, 100)
    try:
        repository.save_run(make_run(suffix=3), active_limit=1)
    except JudgeRunCapacityError:
        pass
    else:
        raise AssertionError("authoritative active-run quota was bypassed")
    try:
        repository.save_run(active.model_copy(update={"run_id": UUID(int=99)}), 100)
    except ValueError as error:
        assert "tenant" in str(error)
    else:
        raise AssertionError("duplicate tenant was accepted")
    handoff = ReviewHandoff(
        code_hash="e" * 64,
        run_id=active.run_id,
        tenant_id=active.tenant_id,
        workflow_id=active.source_incident_id,
        memory_id=UUID(int=3),
        memory_digest="f" * 64,
        purpose="initial_review",
        issued_by_subject=active.operator_subject,
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
    )
    repository.save_handoff(handoff)
    try:
        repository.save_handoff(handoff)
    except ValueError as error:
        assert "already exists" in str(error)
    else:
        raise AssertionError("duplicate handoff was accepted")
    assert repository.consume_handoff("0" * 64) is None
    assert repository.consume_handoff(handoff.code_hash) is not None
    assert repository.consume_handoff(handoff.code_hash) is None
    assert repository.active_run_count() == 1
    assert repository.reset_run(active.run_id)
    assert not repository.reset_run(active.run_id)
    assert repository.active_run_count() == 0


def test_authenticator_enforces_role_run_scope_and_csrf() -> None:
    repository = InMemoryJudgeSessionRepository()
    run = make_run()
    repository.save_run(run, 100)
    authenticator = JudgeSessionAuthenticator(settings(), repository)
    invalid_calls = (
        {"role": "admin", "subject": "admin"},
        {"role": "reviewer", "subject": "reviewer", "run_id": UUID(int=99)},
        {"role": "reviewer", "subject": "reviewer"},
        {
            "role": "operator",
            "subject": run.operator_subject,
            "review_handoff_hash": "a" * 64,
        },
    )
    for overrides in invalid_calls:
        arguments: dict[str, object] = {
            "role": "operator",
            "run_id": run.run_id,
            "tenant_id": run.tenant_id,
            "generation": run.generation,
            "subject": run.operator_subject,
        }
        arguments.update(overrides)
        try:
            authenticator.create_session(**arguments)  # type: ignore[arg-type]
        except JudgeSessionError:
            pass
        else:
            raise AssertionError("invalid role/run scope received a session")
    token, csrf, principal = authenticator.create_session(
        "operator",
        run_id=run.run_id,
        tenant_id=run.tenant_id,
        generation=run.generation,
        subject=run.operator_subject,
    )
    authenticator.validate_csrf(principal, csrf)
    other = make_run(suffix=2)
    repository.save_run(other, 100)
    authenticator.create_session(
        "operator",
        run_id=other.run_id,
        tenant_id=other.tenant_id,
        generation=other.generation,
        subject=other.operator_subject,
    )
    repository.reset_run(run.run_id)
    try:
        authenticator.authenticate(None, None, None, None, token)
    except JudgeSessionError as error:
        assert "invalid or expired" in str(error)
    else:
        raise AssertionError("reset session remained valid")
    current_token, _, _ = authenticator.create_session(
        "operator",
        run_id=other.run_id,
        tenant_id=other.tenant_id,
        generation=other.generation,
        subject=f"{other.operator_subject}_second",
    )
    repository._runs[other.run_id] = other.model_copy(update={"status": "reset"})
    try:
        authenticator.authenticate(None, None, None, None, current_token)
    except JudgeSessionError as error:
        assert "invalid or expired" in str(error)
    else:
        raise AssertionError("non-current run session remained valid")


def test_logout_and_secure_cookie_contract() -> None:
    client = TestClient(create_app(settings(), InMemoryStore()))
    started = create_run(client)
    assert client.post("/v1/judge/session/exchange", json={}).status_code == 404
    response = client.post(
        "/v1/judge/session/logout",
        headers={"Origin": "http://testserver", "X-CSRF-Token": str(started["csrf_token"])},
    )
    assert response.status_code == 200 and client.get("/v1/me").status_code == 401

    secure = TestClient(create_app(settings(judge_cookie_secure=True), InMemoryStore()))
    cookie = secure.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    ).headers["set-cookie"]
    assert cookie.startswith("__Host-recallops_operator=")
    assert all(attribute in cookie for attribute in ("HttpOnly", "SameSite=strict", "Secure"))


def test_judge_mode_rejects_manual_attestation_and_operator_supplied_outcome() -> None:
    client = TestClient(create_app(settings(), InMemoryStore()))
    create_run(client)
    incident_id = "00000000-0000-0000-0000-000000000001"
    execution = client.post(
        f"/v1/incidents/{incident_id}/execution",
        json={
            "tenant_id": "untrusted",
            "actor_id": "untrusted",
            "action_hash": "0" * 64,
            "action_taken": "untrusted operator text",
            "evidence_refs": ["manual://claim"],
        },
    )
    outcome = client.post(
        f"/v1/incidents/{incident_id}/outcome",
        json={
            "tenant_id": "untrusted",
            "actor_id": "untrusted",
            "action_taken": "untrusted operator text",
            "outcome": "unverified success claim",
            "outcome_score": 1,
            "confidence": 1,
        },
    )
    assert execution.status_code == 410
    assert outcome.status_code == 410


def test_authenticator_configuration_and_invalid_session_are_rejected() -> None:
    repository = InMemoryJudgeSessionRepository()
    try:
        JudgeSessionAuthenticator(Settings(auth_mode="judge"), repository)
    except ValueError as error:
        assert "rate-limit" in str(error)
    else:
        raise AssertionError("invalid judge authentication configuration was accepted")
    authenticator = JudgeSessionAuthenticator(settings(), repository)
    try:
        authenticator.authenticate(None, None, None, None, "invalid")
    except ValueError as error:
        assert "invalid or expired" in str(error)
    else:
        raise AssertionError("invalid judge session was accepted")
