from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast
from unittest.mock import MagicMock
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from recallops.api import create_app
from recallops.config import Settings
from recallops.domain import MemoryState
from recallops.public_bundles import FinalizedPublicReceipt
from recallops.resilience import DependencyUnavailable
from recallops.service import IncidentWorkflowError
from recallops.store import InMemoryStore
from recallops.workflow import WorkflowConflict


def judge_settings(**updates: object) -> Settings:
    values: dict[str, object] = {
        "store": "memory",
        "auth_mode": "judge",
        "public_origin": "http://testserver",
        "judge_rate_limit_key": SecretStr("boundary-rate-limit-key-with-enough-entropy"),
        "judge_cookie_secure": False,
    }
    values.update(updates)
    return Settings(**values)  # type: ignore[arg-type]


def launch(app: Any) -> tuple[TestClient, dict[str, object]]:
    client = TestClient(app)
    response = client.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    assert response.status_code == 201
    return client, cast(dict[str, object], response.json())


def proposal_context(
    app: Any,
) -> tuple[TestClient, dict[str, object], dict[str, object], dict[str, str]]:
    client, started = launch(app)
    manifest = cast(dict[str, object], client.get("/v1/webmcp/capabilities").json())
    incident = cast(dict[str, object], client.get("/v1/webmcp/incident").json()["incident"])
    headers = {
        "Origin": "http://testserver",
        "Content-Type": "application/json",
        "If-Match": f'"{manifest["run_generation"]}:{manifest["epoch"]}"',
        "Idempotency-Key": "boundary-proposal-key-0001",
    }
    return client, started, incident, headers


def observation_context(
    app: Any,
) -> tuple[TestClient, dict[str, object], dict[str, object], dict[str, object]]:
    client, started, incident, headers = proposal_context(app)
    proposal = client.post(
        "/v1/webmcp/proposal",
        headers=headers,
        json={
            "service": incident["service"],
            "service_version": incident["service_version"],
            "symptom": incident["symptom"],
        },
    )
    assert proposal.status_code == 201
    run = cast(dict[str, object], started["run"])
    identity = cast(dict[str, object], started["identity"])
    ui_headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": str(started["csrf_token"]),
        "X-RecallOps-Channel": "ui",
    }
    approved = client.post(
        f"/v1/incidents/{run['incident_id']}/approval",
        headers={**ui_headers, "X-Workflow-Epoch": "2"},
        json={
            "tenant_id": app.state.judge_repository.get_run(UUID(str(run["run_id"]))).tenant_id,
            "approved": True,
            "actor_id": identity["subject"],
            "proposal_hash": proposal.json()["proposal_digest"],
            "reason": "Bound exact proposal.",
        },
    )
    assert approved.status_code == 200
    executed = client.post(
        f"/v1/incidents/{run['incident_id']}/sandbox-execution",
        headers={**ui_headers, "X-Workflow-Epoch": "3"},
        json={
            "tenant_id": app.state.judge_repository.get_run(UUID(str(run["run_id"]))).tenant_id,
            "actor_id": identity["subject"],
            "proposal_hash": proposal.json()["proposal_digest"],
            "idempotency_key": "boundary-sandbox-key-0001",
        },
    )
    assert executed.status_code == 201
    ready = cast(dict[str, object], client.get("/v1/webmcp/capabilities").json())
    return client, started, cast(dict[str, object], executed.json()["observation"]), ready


def pending_review_context(
    app: Any,
) -> tuple[TestClient, TestClient, dict[str, object], dict[str, object], dict[str, object]]:
    operator, started, observation, ready = observation_context(app)
    assessed = operator.post(
        "/v1/webmcp/assessment",
        headers={
            "Origin": "http://testserver",
            "Content-Type": "application/json",
            "If-Match": f'"{ready["run_generation"]}:{ready["epoch"]}"',
            "Idempotency-Key": "boundary-pending-assessment-0001",
        },
        json={
            "observation_id": observation["id"],
            "classification": "recovered",
            "rationale": "Verified evidence is ready for independent review.",
        },
    )
    assert assessed.status_code == 201
    memory = cast(dict[str, object], assessed.json()["memory"])
    handoff = operator.post(
        "/v1/operator/reviewer-handoff",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": str(started["csrf_token"]),
        },
        json={"purpose": "initial_review", "memory_digest": memory["digest"]},
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
    return operator, reviewer, started, cast(dict[str, object], exchange.json()), memory


def reviewer_headers(exchange: dict[str, object], epoch: int) -> dict[str, str]:
    return {
        "Origin": "http://testserver",
        "Content-Type": "application/json",
        "X-CSRF-Token": str(exchange["csrf_token"]),
        "If-Match": f'"1:{epoch}"',
    }


def revocation_context(
    app: Any,
) -> tuple[TestClient, dict[str, object], dict[str, object], object]:
    operator, reviewer, started, exchange, memory = pending_review_context(app)
    workflow_id = next(iter(app.state.workflows._repository._workflows))[1]
    workflow = app.state.workflows.get(
        workflow_id, next(iter(app.state.judge_repository._runs.values())).tenant_id
    )
    assert workflow is not None
    certified = reviewer.post(
        "/v1/reviewer/disposition",
        headers=reviewer_headers(exchange, workflow.epoch),
        json={
            "decision": "certify",
            "memory_digest": memory["digest"],
            "reason_code": "EVIDENCE_ACCEPTED",
            "note": "Independent evidence accepted.",
        },
    )
    assert certified.status_code == 200
    active = cast(dict[str, object], certified.json()["memory"])
    handoff = operator.post(
        "/v1/operator/reviewer-handoff",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": str(started["csrf_token"]),
        },
        json={"purpose": "revocation", "memory_digest": active["memory_digest"]},
    )
    assert handoff.status_code == 201
    code = urlsplit(handoff.json()["reviewer_url"]).fragment.removeprefix("review=")
    revoker = TestClient(app)
    exchange_response = revoker.post(
        "/v1/judge/reviewer-exchange",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={"code": code},
    )
    assert exchange_response.status_code == 200
    return revoker, cast(dict[str, object], exchange_response.json()), active, workflow_id


def test_public_bundle_configuration_requires_postgres() -> None:
    with pytest.raises(ValueError, match="PostgreSQL store"):
        create_app(
            Settings(store="memory", authority_bundle_bucket="public-bundles"),
            InMemoryStore(),
        )


def test_judge_launch_rejects_zero_magnitude_incident_embedding() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    app.state.service._embedder.embed = MagicMock(return_value=[0.0] * 1024)
    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    assert response.status_code == 500


def test_webmcp_manifest_and_inspection_fail_closed_when_authority_is_absent() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, started = launch(app)
    run = cast(dict[str, object], started["run"])
    run_id = UUID(str(run["run_id"]))
    authoritative = app.state.judge_repository.get_run(run_id)
    assert authoritative is not None
    repository = app.state.workflows._repository
    key = (authoritative.tenant_id, authoritative.source_incident_id)
    snapshot = repository._workflows[key]
    repository._workflows[key] = snapshot.model_copy(update={"active": False})
    manifest = client.get("/v1/webmcp/capabilities")
    assert manifest.status_code == 200
    assert manifest.json()["available_tools"] == []
    del repository._workflows[key]
    assert client.get("/v1/webmcp/capabilities").status_code == 404
    assert client.get("/v1/webmcp/incident").status_code == 404


def test_webmcp_proposal_validates_media_key_evidence_and_conflicts() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, started, incident, headers = proposal_context(app)
    payload = {
        "service": incident["service"],
        "service_version": incident["service_version"],
        "symptom": incident["symptom"],
        "rationale": "bounded evidence",
    }
    assert (
        client.post(
            "/v1/webmcp/proposal",
            headers={**headers, "Content-Type": "application/problem+json"},
            content=json.dumps(payload),
        ).status_code
        == 415
    )
    no_key = {key: value for key, value in headers.items() if key != "Idempotency-Key"}
    assert client.post("/v1/webmcp/proposal", headers=no_key, json=payload).status_code == 428
    mismatched = {**payload, "service_version": "v0.invalid"}
    assert client.post("/v1/webmcp/proposal", headers=headers, json=mismatched).status_code == 409

    run = cast(dict[str, object], started["run"])
    run_id = UUID(str(run["run_id"]))
    authoritative = app.state.judge_repository.get_run(run_id)
    assert authoritative is not None
    store = app.state.store
    analysis_key = (authoritative.tenant_id, authoritative.source_incident_id)
    analysis = store.analyses[analysis_key]
    store.analyses[analysis_key] = analysis.model_copy(
        update={
            "proposed_action": analysis.proposed_action.model_copy(
                update={"action_hash": None, "requires_approval": False}
            )
        }
    )
    assert client.post("/v1/webmcp/proposal", headers=headers, json=payload).status_code == 409


def test_webmcp_proposal_maps_missing_evidence_and_authority_race() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, started, incident, headers = proposal_context(app)
    payload = {
        "service": incident["service"],
        "service_version": incident["service_version"],
        "symptom": incident["symptom"],
    }
    run = cast(dict[str, object], started["run"])
    authoritative = app.state.judge_repository.get_run(UUID(str(run["run_id"])))
    assert authoritative is not None
    analysis_key = (authoritative.tenant_id, authoritative.source_incident_id)
    analysis = app.state.store.analyses.pop(analysis_key)
    assert client.post("/v1/webmcp/proposal", headers=headers, json=payload).status_code == 404
    app.state.store.analyses[analysis_key] = analysis
    app.state.workflows.transition = MagicMock(side_effect=WorkflowConflict("epoch lost"))
    assert client.post("/v1/webmcp/proposal", headers=headers, json=payload).status_code == 409


def test_reset_requires_an_existing_authoritative_workflow() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, started = launch(app)
    run = cast(dict[str, object], started["run"])
    authoritative = app.state.judge_repository.get_run(UUID(str(run["run_id"])))
    assert authoritative is not None
    del app.state.workflows._repository._workflows[
        (authoritative.tenant_id, authoritative.source_incident_id)
    ]
    response = client.post(
        "/v1/operator/run/reset",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": str(started["csrf_token"]),
        },
    )
    assert response.status_code == 409


def test_reviewer_exchange_requires_json_media_type() -> None:
    client = TestClient(create_app(judge_settings(), InMemoryStore()))
    response = client.post(
        "/v1/judge/reviewer-exchange",
        headers={"Origin": "http://testserver", "Content-Type": "text/plain"},
        content="{}",
    )
    assert response.status_code == 415


def test_demo_reviewer_role_has_no_handoff_authority() -> None:
    client = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    response = client.get(
        "/v1/reviewer/evidence",
        headers={
            "X-Tenant-ID": "demo",
            "X-Actor-ID": "reviewer",
            "X-Roles": "reviewer",
        },
    )
    assert response.status_code == 403


def test_reviewer_scope_binds_run_memory_and_independent_identity() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    _, reviewer, _, exchange, _ = pending_review_context(app)
    repository = app.state.judge_repository
    handoff_hash = next(iter(repository._handoffs))
    handoff = repository._handoffs[handoff_hash]
    repository._handoffs[handoff_hash] = handoff.model_copy(update={"tenant_id": "other"})
    assert reviewer.get("/v1/reviewer/evidence").status_code == 404

    app = create_app(judge_settings(), InMemoryStore())
    _, reviewer, _, _, memory = pending_review_context(app)
    memory_id = UUID(str(memory["id"]))
    app.state.store.memories = [item for item in app.state.store.memories if item.id != memory_id]
    assert reviewer.get("/v1/reviewer/evidence").status_code == 404

    app = create_app(judge_settings(), InMemoryStore())
    _, reviewer, _, exchange, _ = pending_review_context(app)
    reviewer_subject = cast(dict[str, object], exchange["identity"])["subject"]
    repository = app.state.judge_repository
    run_id = next(iter(repository._runs))
    repository._runs[run_id] = repository._runs[run_id].model_copy(
        update={"operator_subject": reviewer_subject}
    )
    assert reviewer.get("/v1/reviewer/evidence").status_code == 403

    app = create_app(judge_settings(), InMemoryStore())
    _, reviewer, _, _, _ = pending_review_context(app)
    repository = app.state.judge_repository
    handoff_hash = next(iter(repository._handoffs))
    repository._handoffs[handoff_hash] = repository._handoffs[handoff_hash].model_copy(
        update={"revoked_at": datetime.now(UTC)}
    )
    assert reviewer.get("/v1/reviewer/evidence").status_code == 403


def test_reviewer_disposition_fails_closed_for_missing_workflow_and_stale_memory() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    _, reviewer, _, exchange, memory = pending_review_context(app)
    repository = app.state.workflows._repository
    snapshot_key = next(iter(repository._workflows))
    snapshot = repository._workflows.pop(snapshot_key)
    payload = {
        "decision": "certify",
        "memory_digest": memory["digest"],
        "reason_code": "EVIDENCE_ACCEPTED",
        "note": "Independent evidence accepted.",
    }
    assert (
        reviewer.post(
            "/v1/reviewer/disposition",
            headers=reviewer_headers(exchange, snapshot.epoch),
            json=payload,
        ).status_code
        == 404
    )

    app = create_app(judge_settings(), InMemoryStore())
    _, reviewer, _, exchange, memory = pending_review_context(app)
    memory_id = UUID(str(memory["id"]))
    current = app.state.store.get_memory(
        memory_id, next(iter(app.state.judge_repository._runs.values())).tenant_id
    )
    assert current is not None
    stale = current.model_copy(update={"state": MemoryState.ACTIVE, "valid": True})
    app.state.store.memories[app.state.store.memories.index(current)] = stale
    app.state.store.outcome_memories[(stale.tenant_id, cast(UUID, stale.source_incident_id))] = (
        stale
    )
    workflow = app.state.workflows.get(cast(UUID, stale.source_incident_id), stale.tenant_id)
    assert workflow is not None
    response = reviewer.post(
        "/v1/reviewer/disposition",
        headers=reviewer_headers(exchange, workflow.epoch),
        json={**payload, "memory_digest": memory["digest"]},
    )
    assert response.status_code == 409


def test_reviewer_mutations_require_exact_digest_and_precondition() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    operator, reviewer, started, exchange, memory = pending_review_context(app)
    run = next(iter(app.state.judge_repository._runs.values()))
    workflow = app.state.workflows.get(run.source_incident_id, run.tenant_id)
    assert workflow is not None
    payload = {
        "decision": "certify",
        "memory_digest": memory["digest"],
        "reason_code": "EVIDENCE_ACCEPTED",
        "note": "Independent evidence accepted.",
    }
    headers = reviewer_headers(exchange, workflow.epoch)
    missing = {key: value for key, value in headers.items() if key != "If-Match"}
    assert (
        reviewer.post("/v1/reviewer/disposition", headers=missing, json=payload).status_code == 428
    )
    assert (
        reviewer.post(
            "/v1/reviewer/disposition",
            headers={**headers, "If-Match": '"1:999"'},
            json=payload,
        ).status_code
        == 412
    )
    assert (
        operator.post(
            "/v1/operator/reviewer-handoff",
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": str(started["csrf_token"]),
            },
            json={"purpose": "initial_review", "memory_digest": "f" * 64},
        ).status_code
        == 409
    )


def test_reviewer_revocation_fails_closed_for_missing_or_stale_authority() -> None:
    payload = {
        "reason_code": "NEW_CONTRADICTORY_EVIDENCE",
        "note": "A later verified observation contradicts this memory.",
    }

    app = create_app(judge_settings(), InMemoryStore())
    reviewer, exchange, active, workflow_id = revocation_context(app)
    run = next(iter(app.state.judge_repository._runs.values()))
    workflow = app.state.workflows.get(cast(UUID, workflow_id), run.tenant_id)
    assert workflow is not None
    del app.state.workflows._repository._workflows[(run.tenant_id, cast(UUID, workflow_id))]
    assert (
        reviewer.post(
            "/v1/reviewer/revocation",
            headers=reviewer_headers(exchange, workflow.epoch),
            json={**payload, "memory_digest": active["memory_digest"]},
        ).status_code
        == 404
    )

    app = create_app(judge_settings(), InMemoryStore())
    reviewer, exchange, active, workflow_id = revocation_context(app)
    run = next(iter(app.state.judge_repository._runs.values()))
    workflow = app.state.workflows.get(cast(UUID, workflow_id), run.tenant_id)
    assert workflow is not None
    app.state.workflows.get = MagicMock(side_effect=[workflow, None])
    assert (
        reviewer.post(
            "/v1/reviewer/revocation",
            headers=reviewer_headers(exchange, workflow.epoch),
            json={**payload, "memory_digest": active["memory_digest"]},
        ).status_code
        == 409
    )

    app = create_app(judge_settings(), InMemoryStore())
    reviewer, exchange, active, workflow_id = revocation_context(app)
    run = next(iter(app.state.judge_repository._runs.values()))
    workflow = app.state.workflows.get(cast(UUID, workflow_id), run.tenant_id)
    assert workflow is not None
    memory = app.state.store.get_memory(UUID(str(active["id"])), run.tenant_id)
    assert memory is not None
    invalid = memory.model_copy(update={"valid": False})
    app.state.store.memories[app.state.store.memories.index(memory)] = invalid
    app.state.store.outcome_memories[(run.tenant_id, cast(UUID, workflow_id))] = invalid
    assert (
        reviewer.post(
            "/v1/reviewer/revocation",
            headers=reviewer_headers(exchange, workflow.epoch),
            json={**payload, "memory_digest": active["memory_digest"]},
        ).status_code
        == 409
    )


def test_reviewer_revocation_rejects_digest_and_commits_valid_evidence() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    reviewer, exchange, active, workflow_id = revocation_context(app)
    run = next(iter(app.state.judge_repository._runs.values()))
    workflow = app.state.workflows.get(cast(UUID, workflow_id), run.tenant_id)
    assert workflow is not None
    headers = reviewer_headers(exchange, workflow.epoch)
    payload = {
        "memory_digest": active["memory_digest"],
        "reason_code": "NEW_CONTRADICTORY_EVIDENCE",
        "note": "A later verified observation contradicts this memory.",
    }
    assert (
        reviewer.post(
            "/v1/reviewer/revocation",
            headers=headers,
            json={**payload, "memory_digest": "f" * 64},
        ).status_code
        == 409
    )
    revoked = reviewer.post("/v1/reviewer/revocation", headers=headers, json=payload)
    assert revoked.status_code == 200
    assert revoked.json()["memory"]["state"] == "revoked"


def test_revocation_handoff_rejects_memory_that_is_no_longer_eligible() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    operator, reviewer, started, exchange, memory = pending_review_context(app)
    run = next(iter(app.state.judge_repository._runs.values()))
    workflow = app.state.workflows.get(run.source_incident_id, run.tenant_id)
    assert workflow is not None
    certified = reviewer.post(
        "/v1/reviewer/disposition",
        headers=reviewer_headers(exchange, workflow.epoch),
        json={
            "decision": "certify",
            "memory_digest": memory["digest"],
            "reason_code": "EVIDENCE_ACCEPTED",
            "note": "Independent evidence accepted.",
        },
    )
    assert certified.status_code == 200
    active = app.state.store.get_memory(UUID(certified.json()["memory"]["id"]), run.tenant_id)
    assert active is not None
    invalid = active.model_copy(update={"valid": False})
    app.state.store.memories[app.state.store.memories.index(active)] = invalid
    app.state.store.outcome_memories[(run.tenant_id, run.source_incident_id)] = invalid
    response = operator.post(
        "/v1/operator/reviewer-handoff",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": str(started["csrf_token"]),
        },
        json={"purpose": "revocation", "memory_digest": invalid.memory_digest},
    )
    assert response.status_code == 409


def test_supporting_activity_failure_does_not_break_inspection_and_rate_limit_closes() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, _ = launch(app)
    app.state.ledger_repository.add_activity = MagicMock(side_effect=RuntimeError("telemetry down"))
    assert client.get("/v1/webmcp/incident").status_code == 200
    app.state.judge_repository.consume_attempt = MagicMock(return_value=False)
    response = client.post(
        "/v1/webmcp/activity",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={
            "client_instance_id": "boundary-client-0001",
            "items": [
                {
                    "activity_type": "tool_registered",
                    "tool_name": "inspect_incident",
                    "outcome": "observed",
                }
            ],
        },
    )
    assert response.status_code == 429
    rate_limit_key = app.state.judge_repository.consume_attempt.call_args.args[0]
    assert len(rate_limit_key) == 64
    assert all(character in "0123456789abcdef" for character in rate_limit_key)


def test_webmcp_assessment_validates_evidence_and_replays_inside_authority_lock() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, _, observation, ready = observation_context(app)
    base_headers = {
        "Origin": "http://testserver",
        "Content-Type": "application/json",
        "If-Match": f'"{ready["run_generation"]}:{ready["epoch"]}"',
        "Idempotency-Key": "boundary-assessment-key-0001",
    }
    payload = {
        "observation_id": observation["id"],
        "classification": "recovered",
        "rationale": "Verified thresholds recovered.",
    }
    wrong = {**payload, "observation_id": "00000000-0000-0000-0000-000000000001"}
    assert client.post("/v1/webmcp/assessment", headers=base_headers, json=wrong).status_code == 409
    no_key = {key: value for key, value in base_headers.items() if key != "Idempotency-Key"}
    assert client.post("/v1/webmcp/assessment", headers=no_key, json=payload).status_code == 428
    assessed = client.post("/v1/webmcp/assessment", headers=base_headers, json=payload)
    assert assessed.status_code == 201
    replay = client.post("/v1/webmcp/assessment", headers=base_headers, json=payload)
    assert replay.status_code == 201 and replay.json() == assessed.json()
    changed = {**payload, "rationale": "A conflicting interpretation."}
    assert (
        client.post("/v1/webmcp/assessment", headers=base_headers, json=changed).status_code == 409
    )


def test_webmcp_assessment_requires_a_verified_postcheck() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, _ = launch(app)
    response = client.post(
        "/v1/webmcp/assessment",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={
            "observation_id": "00000000-0000-0000-0000-000000000001",
            "classification": "recovered",
            "rationale": "No verified observation exists.",
        },
    )
    assert response.status_code == 404


def test_inspection_fails_closed_if_ready_state_has_no_verified_postcheck(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, _, _, _ = observation_context(app)
    monkeypatch.setattr(app.state.service, "get_postcheck", MagicMock(return_value=None))

    evidence = client.get("/v1/webmcp/incident")

    assert evidence.status_code == 200
    assert evidence.json()["workflow"]["state"] == "POSTCHECK_READY"
    assert evidence.json()["verified_postcheck"] is None


def test_webmcp_assessment_maps_prepare_and_persist_failures() -> None:
    app = create_app(judge_settings(), InMemoryStore())
    client, _, observation, ready = observation_context(app)
    payload = {
        "observation_id": observation["id"],
        "classification": "recovered",
        "rationale": "Verified thresholds recovered.",
    }

    def headers(suffix: str) -> dict[str, str]:
        return {
            "Origin": "http://testserver",
            "Content-Type": "application/json",
            "If-Match": f'"{ready["run_generation"]}:{ready["epoch"]}"',
            "Idempotency-Key": f"boundary-assessment-{suffix}-0001",
        }

    original_prepare = app.state.service.prepare_verified_outcome
    app.state.service.prepare_verified_outcome = MagicMock(
        side_effect=DependencyUnavailable("evidence dependency")
    )
    assert (
        client.post(
            "/v1/webmcp/assessment", headers=headers("dependency"), json=payload
        ).status_code
        == 503
    )
    app.state.service.prepare_verified_outcome = MagicMock(return_value=None)
    assert (
        client.post("/v1/webmcp/assessment", headers=headers("missing"), json=payload).status_code
        == 404
    )
    app.state.service.prepare_verified_outcome = original_prepare
    app.state.service.persist_verified_outcome = MagicMock(
        side_effect=IncidentWorkflowError("persistence race")
    )
    assert (
        client.post("/v1/webmcp/assessment", headers=headers("conflict"), json=payload).status_code
        == 409
    )


def test_public_bundle_route_distinguishes_absent_missing_and_unavailable() -> None:
    receipt_id = UUID("60000000-0000-0000-0000-000000000099")
    plain = TestClient(create_app(Settings(store="memory"), InMemoryStore()))
    assert plain.get(f"/public/evidence/{receipt_id}/authority-bundle.zip").status_code == 404

    service = MagicMock()
    service.download.return_value = None
    client = TestClient(
        create_app(Settings(store="memory"), InMemoryStore(), public_bundle_service=service)
    )
    assert client.get(f"/public/evidence/{receipt_id}/authority-bundle.zip").status_code == 404
    service.download.side_effect = DependencyUnavailable("object store unavailable")
    unavailable = client.get(f"/public/evidence/{receipt_id}/authority-bundle.zip")
    assert unavailable.status_code == 503 and unavailable.headers["retry-after"] == "30"

    service.download.side_effect = None
    service.download.return_value = (
        b"zip",
        FinalizedPublicReceipt(
            receipt_id=receipt_id,
            bundle_digest="a" * 64,
            object_key="bundle.zip",
            version_id="v1",
            source_sha="b" * 40,
            image_digest=f"sha256:{'c' * 64}",
        ),
    )
    assert client.get(f"/public/evidence/{receipt_id}/authority-bundle.zip").status_code == 200
