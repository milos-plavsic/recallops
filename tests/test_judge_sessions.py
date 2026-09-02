import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

from fastapi.testclient import TestClient
from pydantic import SecretStr

from recallops.api import create_app
from recallops.auth import JudgeSessionAuthenticator, JudgeSessionError
from recallops.canonical import content_digest
from recallops.config import Settings
from recallops.domain import Memory, MemoryState
from recallops.embedding import DeterministicEmbedder
from recallops.sessions import (
    InMemoryJudgeSessionRepository,
    JudgeRun,
    JudgeRunCapacityError,
    PostgresJudgeSessionRepository,
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


def test_frozen_webmcp_manifest_proposal_and_activity_are_fail_closed() -> None:
    app = create_app(settings(), InMemoryStore())
    client = TestClient(app)
    started = create_run(client)
    run_data = cast(dict[str, object], started["run"])
    run = app.state.judge_repository.get_run(UUID(str(run_data["run_id"])))
    assert run is not None

    manifest_response = client.get("/v1/webmcp/capabilities")
    assert manifest_response.status_code == 200
    manifest = manifest_response.json()
    assert manifest["available_tools"] == ["inspect_incident", "propose_mitigation"]
    assert {item["name"] for item in manifest["withheld_tools"]} == {
        "record_postcheck_assessment",
        "recall_reviewed_memory",
    }
    assert set(manifest["available_tools"]).isdisjoint(manifest["protected_operations"])
    assert manifest_response.headers["etag"] == manifest["etag"]
    assert (
        client.get(
            "/v1/webmcp/capabilities",
            headers={"If-None-Match": manifest["etag"]},
        ).status_code
        == 304
    )

    inspected = client.get("/v1/webmcp/incident")
    assert inspected.status_code == 200
    evidence = inspected.json()
    assert evidence["incident"] == {
        "service": "checkout",
        "service_version": "v2.4.1",
        "symptom": "checkout-latency-42: p95 latency and error rate exceed the sandbox SLO",
        "status": "open",
    }
    assert len(evidence["candidates"]) <= 3
    assert [(item["similarity"], item["eligible"]) for item in evidence["candidates"]] == [
        (0.94, False),
        (0.81, True),
    ]
    assert evidence["candidates"][0]["rejection_codes"] == [
        "rank_score_below_threshold",
        "service_version_incompatible",
        "outcome_not_positive",
    ]
    assert "incident.symptom" in evidence["untrusted_fields"]
    assert evidence["verified_postcheck"] is None
    assert "verified_postcheck" in evidence["trusted_fields"]

    proposal_payload = {
        "service": evidence["incident"]["service"],
        "service_version": evidence["incident"]["service_version"],
        "symptom": evidence["incident"]["symptom"],
        "rationale": "Bounded proposal derived from the selected eligible memory.",
    }
    precondition = f'"{manifest["run_generation"]}:{manifest["epoch"]}"'
    mutation_headers = {
        "Origin": "http://testserver",
        "Content-Type": "application/json",
        "If-Match": precondition,
        "Idempotency-Key": "proposal-contract-key-0001",
    }
    assert client.post("/v1/webmcp/proposal", json=proposal_payload).status_code == 403
    staged = client.post("/v1/webmcp/proposal", headers=mutation_headers, json=proposal_payload)
    assert staged.status_code == 201
    staged_body = staged.json()
    assert staged_body["requires_human_approval"] is True
    assert staged_body["authority_owner"] == "HUMAN_OPERATOR"
    assert "command" not in staged.text
    assert len(staged_body["proposal_digest"]) == 64

    replay = client.post("/v1/webmcp/proposal", headers=mutation_headers, json=proposal_payload)
    assert replay.status_code == 201 and replay.json() == staged_body
    changed = {**proposal_payload, "rationale": "Different input must conflict."}
    assert (
        client.post("/v1/webmcp/proposal", headers=mutation_headers, json=changed).status_code
        == 409
    )

    after = client.get("/v1/webmcp/capabilities").json()
    assert after["available_tools"] == ["inspect_incident"]
    assert (
        next(item for item in after["withheld_tools"] if item["name"] == "propose_mitigation")[
            "reason_code"
        ]
        == "PROPOSAL_NOT_AVAILABLE_IN_CURRENT_STATE"
    )
    for protected in manifest["protected_operations"]:
        assert client.post(f"/v1/webmcp/{protected}", json={}).status_code == 404

    authority_before = app.state.ledger_repository.list_events(run.run_id, run.tenant_id)
    activity = client.post(
        "/v1/webmcp/activity",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={
            "client_instance_id": "native-client-instance-0001",
            "items": [
                {
                    "activity_type": "tool_withdrawn",
                    "tool_name": "propose_mitigation",
                    "outcome": "observed",
                }
            ],
        },
    )
    assert activity.status_code == 202 and activity.json() == {"accepted": 1}
    assert len(app.state.ledger_repository.list_events(run.run_id, run.tenant_id)) == len(
        authority_before
    )
    timeline = client.get("/v1/evidence/timeline").json()
    browser_entries = [
        item
        for item in timeline["entries"]
        if item.get("evidence_class") == "supporting_observation"
    ]
    assert any(item.get("event_type") == "tool_withdrawn" for item in browser_entries)
    withdrawal_entries = [
        item for item in browser_entries if item.get("event_type") == "tool_withdrawn"
    ]
    assert all(item.get("actor_subject") == "browser-client" for item in withdrawal_entries)


def test_reviewer_document_has_zero_webmcp_surface() -> None:
    client = TestClient(create_app(settings(), InMemoryStore()))
    response = client.get("/reviewer")
    assert response.status_code == 200
    assert "reviewer.js" in response.text
    assert "webmcp.js" not in response.text
    assert "document.modelContext" not in response.text


def test_webmcp_schemas_reject_agent_supplied_metrics_and_unknown_fields() -> None:
    client = TestClient(create_app(settings(), InMemoryStore()))
    create_run(client)
    mutation_headers = {
        "Origin": "http://testserver",
        "Content-Type": "application/json",
        "If-Match": '"1:1"',
        "Idempotency-Key": "assessment-contract-key-0001",
    }
    response = client.post(
        "/v1/webmcp/assessment",
        headers=mutation_headers,
        json={
            "observation_id": "00000000-0000-0000-0000-000000000001",
            "classification": "recovered",
            "rationale": "Agent cannot supply measurements.",
            "latency_after_ms": 1,
        },
    )
    assert response.status_code == 422


def test_four_tool_journey_preserves_three_evidence_layers_and_independent_review() -> None:
    app = create_app(settings(), InMemoryStore())
    operator = TestClient(app)
    started = create_run(operator)
    run_data = cast(dict[str, object], started["run"])
    operator_identity = cast(dict[str, object], started["identity"])
    run = app.state.judge_repository.get_run(UUID(str(run_data["run_id"])))
    assert run is not None

    initial = operator.get("/v1/webmcp/capabilities").json()
    inspected = operator.get("/v1/webmcp/incident").json()
    proposal = operator.post(
        "/v1/webmcp/proposal",
        headers={
            "Origin": "http://testserver",
            "Content-Type": "application/json",
            "If-Match": f'"{initial["run_generation"]}:{initial["epoch"]}"',
            "Idempotency-Key": "journey-proposal-key-0001",
        },
        json={
            "service": inspected["incident"]["service"],
            "service_version": inspected["incident"]["service_version"],
            "symptom": inspected["incident"]["symptom"],
            "rationale": "Use only the eligible reviewed memory.",
        },
    )
    assert proposal.status_code == 201
    proposal_digest = proposal.json()["proposal_digest"]
    ui_headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": str(started["csrf_token"]),
        "X-RecallOps-Channel": "ui",
    }
    approved = operator.post(
        f"/v1/incidents/{run.source_incident_id}/approval",
        headers={**ui_headers, "X-Workflow-Epoch": "2"},
        json={
            "tenant_id": run.tenant_id,
            "approved": True,
            "actor_id": operator_identity["subject"],
            "proposal_hash": proposal_digest,
            "reason": "Operator approved the exact bound proposal digest.",
        },
    )
    assert approved.status_code == 200
    executed = operator.post(
        f"/v1/incidents/{run.source_incident_id}/sandbox-execution",
        headers={**ui_headers, "X-Workflow-Epoch": "3"},
        json={
            "tenant_id": run.tenant_id,
            "actor_id": operator_identity["subject"],
            "proposal_hash": proposal_digest,
            "idempotency_key": "journey-sandbox-key-0001",
        },
    )
    assert executed.status_code == 201
    observation = executed.json()["observation"]
    ready = operator.get("/v1/webmcp/capabilities").json()
    assert ready["available_tools"] == ["inspect_incident", "record_postcheck_assessment"]
    ready_evidence = operator.get("/v1/webmcp/incident").json()
    verified = ready_evidence["verified_postcheck"]
    assert ready_evidence["candidates"] == []
    assert len(json.dumps(ready_evidence, separators=(",", ":"))) <= 1500
    assert verified == {
        "observation_id": observation["id"],
        "proposal_hash": observation["proposal_hash"],
        "observation_digest": observation["observation_digest"],
        "source": observation["source"],
        "observation_window_seconds": observation["observation_window_seconds"],
        "observed_at": observation["observed_at"],
        "measurements": {
            "before": observation["before"],
            "after": observation["after"],
        },
        "policy_verdict": {
            "classification": executed.json()["policy_verdict"]["classification"],
            "policy_version": executed.json()["policy_verdict"]["policy_version"],
            "checks_passed": executed.json()["policy_verdict"]["checks_passed"],
            "checks_failed": executed.json()["policy_verdict"]["checks_failed"],
        },
    }
    assert "tenant_id" not in verified
    assert "actor_id" not in verified

    assessed = operator.post(
        "/v1/webmcp/assessment",
        headers={
            "Origin": "http://testserver",
            "Content-Type": "application/json",
            "If-Match": f'"{ready["run_generation"]}:{ready["epoch"]}"',
            "Idempotency-Key": "journey-assessment-key-0001",
        },
        json={
            "observation_id": observation["id"],
            "classification": "not_recovered",
            "rationale": "Preserve this deliberate disagreement for independent review.",
        },
    )
    assert assessed.status_code == 201
    assessment = assessed.json()
    assert assessment["assessment_policy_agree"] is False
    assert assessment["policy_verdict"]["classification"] == "recovered"
    assert assessment["memory"]["state"] == "pending_review"
    assert assessment["memory"]["retrievable"] is False
    assert operator.get("/v1/webmcp/incident").json()["verified_postcheck"] is None
    operator_evidence = operator.get("/v1/operator/evidence")
    assert operator_evidence.status_code == 200
    assert operator_evidence.json()["proposal_digest"] == proposal_digest
    assert (
        operator_evidence.json()["immutable_observation"]["observation_digest"]
        == observation["observation_digest"]
    )
    assert "embedding" not in operator_evidence.text
    assert operator.get("/v1/webmcp/recurrence").status_code == 409

    handoff = operator.post(
        "/v1/operator/reviewer-handoff",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": str(started["csrf_token"]),
        },
        json={
            "purpose": "initial_review",
            "memory_digest": assessment["memory"]["digest"],
        },
    )
    assert handoff.status_code == 201
    code = urlsplit(handoff.json()["reviewer_url"]).fragment.removeprefix("review=")
    reviewer = TestClient(app)
    exchange = reviewer.post(
        "/v1/judge/reviewer-exchange",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={"code": code},
    )
    assert exchange.status_code == 200
    assert exchange.json()["identity"]["subject"] != operator_identity["subject"]
    evidence = reviewer.get("/v1/reviewer/evidence").json()
    assert (
        evidence["immutable_observation"]["observation_digest"] == observation["observation_digest"]
    )
    assert evidence["agent_assessment"]["classification"] == "not_recovered"
    assert evidence["policy_verdict"]["classification"] == "recovered"
    assert evidence["assessment_policy_agree"] is False
    disposition = reviewer.post(
        "/v1/reviewer/disposition",
        headers={
            "Origin": "http://testserver",
            "Content-Type": "application/json",
            "X-CSRF-Token": exchange.json()["csrf_token"],
            "If-Match": (
                f'"{evidence["precondition"]["generation"]}:{evidence["precondition"]["epoch"]}"'
            ),
        },
        json={
            "decision": "certify",
            "memory_digest": assessment["memory"]["digest"],
            "reason_code": "EVIDENCE_ACCEPTED",
            "note": "Independent reviewer accepts the measurements and policy verdict.",
        },
    )
    assert disposition.status_code == 200
    receipt = disposition.json()["receipt"]
    assert receipt["status"] == "pending"
    pending_receipt = app.state.ledger_repository.receipt_requests[UUID(receipt["receipt_id"])]
    assert (
        pending_receipt["target_ledger_hash"]
        == app.state.ledger_repository.list_events(run.run_id, run.tenant_id)[-1].event_hash
    )
    assert pending_receipt["synthetic"] is True
    assert pending_receipt["publish_public"] is True
    receipt_view = operator.get("/v1/evidence/receipt")
    assert receipt_view.status_code == 200
    receipt_body = receipt_view.json()
    assert receipt_body["receipt"]["receipt_id"] == receipt["receipt_id"]
    assert receipt_body["receipt"]["status"] == "pending"
    assert [node["authority_owner"] for node in receipt_body["chain"]] == [
        "system",
        "agent",
        "operator",
        "operator",
        "system",
        "agent",
        "reviewer",
    ]
    assert receipt_body["chain"][-1]["label"] == "Independent reviewer governed reuse"
    assert receipt_body["public_bundle_url"] is None
    assert "does not prove external truth" in receipt_body["integrity_scope"]
    reviewed = operator.get("/v1/webmcp/capabilities").json()
    assert reviewed["available_tools"] == ["inspect_incident", "recall_reviewed_memory"]
    recurrence = operator.get("/v1/webmcp/recurrence")
    assert recurrence.status_code == 200
    assert recurrence.json()["governed_memory_id"] == assessment["memory"]["id"]
    assert recurrence.json()["reviewed_evidence_changed_authority"] is True
    assert recurrence.json()["pre_review_governed_memory_id"] != assessment["memory"]["id"]
    assert recurrence.json()["reviewed_evidence_changed_action"] is False
    assert "bounded action remained stable" in recurrence.json()["change_explanation"]
    events = app.state.ledger_repository.list_events(run.run_id, run.tenant_id)
    assert events[-1].actor_subject == exchange.json()["identity"]["subject"]
    assert events[-2].actor_subject.startswith("webmcp_agent_")
    assert [event.object_type for event in events] == [
        None,
        "proposal",
        "proposal",
        "execution_binding",
        "observation_binding",
        "outcome_binding",
        "review_binding",
    ]
    assert events[1].object_digest == events[2].object_digest == proposal_digest
    execution = executed.json()["execution"]
    assert events[3].object_digest == content_digest(
        "recallops-execution-binding-v1",
        {
            "execution": execution["execution_digest"],
            "proposal": proposal_digest,
        },
    )
    memory = app.state.service.get_memory(UUID(assessment["memory"]["id"]), run.tenant_id)
    assert memory is not None
    assert events[5].object_digest == content_digest(
        "recallops-outcome-binding-v1",
        {
            "assessment": cast(str, memory.assessment_digest),
            "memory": cast(str, memory.memory_digest),
            "observation": cast(str, memory.observation_digest),
            "policy_verdict": cast(str, memory.verdict_digest),
        },
    )
    assert events[6].object_id is not None and events[6].object_digest == content_digest(
        "recallops-review-binding-v1",
        {
            "disposition": hashlib.sha256(b"certify").hexdigest(),
            "memory": cast(str, memory.memory_digest),
            "review": events[6].object_id,
        },
    )


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


def test_postgres_handoff_lookup_maps_row_and_absence() -> None:
    handoff = ReviewHandoff(
        code_hash="a" * 64,
        run_id=UUID(int=1),
        tenant_id="tenant",
        workflow_id=UUID(int=2),
        memory_id=UUID(int=3),
        memory_digest="b" * 64,
        purpose="initial_review",
        issued_by_subject="operator",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    class Cursor:
        rows = [handoff.model_dump(mode="python"), None]

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, parameters: object) -> None:
            assert "review_handoffs" in query

        def fetchone(self):
            return self.rows.pop(0)

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def cursor(self) -> Cursor:
            return cursor

    class Pool:
        def connection(self) -> Connection:
            return Connection()

    cursor = Cursor()
    repository = PostgresJudgeSessionRepository(Pool())  # type: ignore[arg-type]
    assert repository.get_handoff(handoff.code_hash) == handoff
    assert repository.get_handoff(handoff.code_hash) is None
