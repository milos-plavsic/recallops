from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from recallops.api import create_app
from recallops.config import Settings
from recallops.domain import GovernanceAction, Memory, MemoryState
from recallops.embedding import DeterministicEmbedder
from recallops.store import InMemoryStore, MemoryGovernanceError
from recallops.workflow import (
    InMemoryWorkflowRepository,
    PostgresWorkflowRepository,
    RequestChannel,
    WorkflowConflict,
    WorkflowCoordinator,
    WorkflowSnapshot,
    WorkflowState,
    manifest,
)


def snapshot(state: WorkflowState = WorkflowState.AWAITING_OPERATOR_APPROVAL) -> WorkflowSnapshot:
    return WorkflowSnapshot(
        workflow_id=uuid4(),
        tenant_id="demo",
        state=state,
        epoch=1,
        proposal_hash="0" * 64,
    )


def test_manifest_is_a_pure_function_of_authoritative_state() -> None:
    investigating = manifest(snapshot(WorkflowState.INVESTIGATING))
    awaiting = manifest(snapshot())
    ready = manifest(snapshot(WorkflowState.POSTCHECK_READY))

    assert investigating.available_tools == ("inspect_incident", "propose_mitigation")
    assert investigating.authority_owner == "AGENT"
    assert awaiting.available_tools == ("inspect_incident",)
    assert awaiting.authority_owner == "HUMAN_OPERATOR"
    assert ready.available_tools == ("inspect_incident", "record_postcheck_assessment")
    assert "approve_proposal" in ready.protected_tools
    assert manifest(snapshot(WorkflowState.OBSERVING_POSTCHECK)).authority_owner == "SYSTEM"
    assert manifest(snapshot(WorkflowState.PENDING_REVIEW)).authority_owner == "HUMAN_REVIEWER"
    assert manifest(snapshot(WorkflowState.REVIEWED)).authority_owner == "GOVERNED_MEMORY"
    inactive = snapshot().model_copy(update={"active": False})
    assert manifest(inactive).authority_owner == "NONE"
    assert manifest(inactive).available_tools == ()


@pytest.mark.parametrize(
    ("state", "channel", "role", "message"),
    [
        (
            WorkflowState.OBSERVING_POSTCHECK,
            RequestChannel.WEBMCP,
            "agent",
            "system authority",
        ),
        (
            WorkflowState.POSTCHECK_READY,
            RequestChannel.UI,
            "agent",
            "WebMCP agent authority",
        ),
    ],
)
def test_evidence_transitions_reject_the_wrong_authority_channel(
    state: WorkflowState,
    channel: RequestChannel,
    role: str,
    message: str,
) -> None:
    current = snapshot(state)
    repository = InMemoryWorkflowRepository()
    repository.ensure(current)
    coordinator = WorkflowCoordinator(repository)
    with pytest.raises(WorkflowConflict, match=message):
        coordinator.validate_transition(
            current.workflow_id,
            current.tenant_id,
            current.epoch,
            current.state,
            channel=channel,
            actor_subject="wrong-authority",
            role=role,
        )


def test_activation_failure_rolls_back_retrieval_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    incident_id = uuid4()
    pending = Memory(
        tenant_id="demo",
        service="checkout",
        service_version="v1",
        symptom="latency",
        action="reduce concurrency",
        outcome="recovered",
        outcome_score=1,
        confidence=0.9,
        valid=False,
        state=MemoryState.PENDING_REVIEW,
        source_incident_id=incident_id,
        observed_by="operator",
        embedding=[0.0] * 1024,
    )
    store = InMemoryStore([pending])
    app = create_app(Settings(store="memory"), store)
    repository = app.state.workflows._repository
    repository.ensure(
        WorkflowSnapshot(
            workflow_id=incident_id,
            tenant_id="demo",
            state=WorkflowState.PENDING_REVIEW,
            epoch=1,
            operator_subject="operator",
        )
    )
    monkeypatch.setattr(
        app.state.service,
        "govern_memory",
        MagicMock(side_effect=MemoryGovernanceError("forced governance failure")),
    )

    response = TestClient(app).post(
        f"/v1/memories/{pending.id}/governance",
        headers={
            "X-Tenant-ID": "demo",
            "X-Actor-ID": "reviewer",
            "X-Roles": "reviewer",
            "X-RecallOps-Channel": "ui",
            "X-Workflow-Epoch": "1",
        },
        json={
            "tenant_id": "demo",
            "actor_id": "reviewer",
            "action": "activate",
            "reason": "force the post-guard failure path",
        },
    )

    assert response.status_code == 409
    guarded = app.state.workflows.get(incident_id, "demo")
    assert guarded is not None and guarded.state is WorkflowState.PENDING_REVIEW
    unchanged = store.get_memory(pending.id, "demo")
    assert unchanged is not None and unchanged.state is MemoryState.PENDING_REVIEW
    assert unchanged.valid is False


def test_epoch_transition_is_single_winner_under_concurrency() -> None:
    repository = InMemoryWorkflowRepository()
    coordinator = WorkflowCoordinator(repository)
    current = repository.ensure(snapshot())

    def approve(_: int) -> str:
        try:
            coordinator.transition(
                current.workflow_id,
                current.tenant_id,
                1,
                WorkflowState.AWAITING_OPERATOR_APPROVAL,
                WorkflowState.APPROVED_AWAITING_EXECUTION,
                channel=RequestChannel.UI,
                actor_subject="operator",
                role="operator",
            )
            return "won"
        except WorkflowConflict:
            return "stale"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(approve, range(16)))

    assert results.count("won") == 1
    assert results.count("stale") == 15
    updated = coordinator.get(current.workflow_id, current.tenant_id)
    assert updated is not None
    assert updated.epoch == 2


def test_channel_role_separation_and_reset_fail_closed() -> None:
    repository = InMemoryWorkflowRepository()
    coordinator = WorkflowCoordinator(repository)
    current = repository.ensure(snapshot())

    with pytest.raises(WorkflowConflict, match="not authorized through WebMCP"):
        coordinator.transition(
            current.workflow_id,
            current.tenant_id,
            1,
            WorkflowState.AWAITING_OPERATOR_APPROVAL,
            WorkflowState.APPROVED_AWAITING_EXECUTION,
            channel=RequestChannel.WEBMCP,
            actor_subject="agent",
            role="operator",
        )
    with pytest.raises(WorkflowConflict, match="operator role required"):
        coordinator.transition(
            current.workflow_id,
            current.tenant_id,
            1,
            WorkflowState.AWAITING_OPERATOR_APPROVAL,
            WorkflowState.APPROVED_AWAITING_EXECUTION,
            channel=RequestChannel.UI,
            actor_subject="reviewer",
            role="reviewer",
        )

    invalidated = coordinator.invalidate(
        current.workflow_id,
        current.tenant_id,
        1,
        channel=RequestChannel.UI,
        role="operator",
    )
    assert invalidated.active is False
    assert manifest(invalidated).available_tools == ()
    with pytest.raises(WorkflowConflict, match="stale workflow state or epoch"):
        coordinator.transition(
            current.workflow_id,
            current.tenant_id,
            2,
            WorkflowState.AWAITING_OPERATOR_APPROVAL,
            WorkflowState.APPROVED_AWAITING_EXECUTION,
            channel=RequestChannel.UI,
            actor_subject="operator",
            role="operator",
        )

    pending = repository.ensure(
        snapshot(WorkflowState.PENDING_REVIEW).model_copy(
            update={"workflow_id": uuid4(), "operator_subject": "same-person"}
        )
    )
    with pytest.raises(WorkflowConflict, match="independent reviewer"):
        coordinator.transition(
            pending.workflow_id,
            pending.tenant_id,
            1,
            WorkflowState.PENDING_REVIEW,
            WorkflowState.REVIEWED,
            channel=RequestChannel.UI,
            actor_subject="same-person",
            role="reviewer",
        )
    reviewed = coordinator.transition(
        pending.workflow_id,
        pending.tenant_id,
        1,
        WorkflowState.PENDING_REVIEW,
        WorkflowState.REVIEWED,
        channel=RequestChannel.UI,
        actor_subject="independent-reviewer",
        role="reviewer",
    )
    assert reviewed.reviewer_subject == "independent-reviewer"
    assert coordinator.capability_manifest(uuid4(), "demo") is None
    with pytest.raises(WorkflowConflict, match="workflow not found"):
        coordinator.validate_transition(
            uuid4(),
            "demo",
            1,
            WorkflowState.INVESTIGATING,
            channel=RequestChannel.WEBMCP,
            actor_subject="agent",
            role="agent",
        )
    with pytest.raises(WorkflowConflict, match="reset requires"):
        coordinator.invalidate(
            pending.workflow_id,
            pending.tenant_id,
            2,
            channel=RequestChannel.WEBMCP,
            role="operator",
        )


def test_in_memory_repository_missing_and_inactive_paths() -> None:
    repository = InMemoryWorkflowRepository()
    missing = uuid4()
    assert repository.get(missing, "demo") is None
    with pytest.raises(WorkflowConflict, match="workflow not found"):
        repository.transition(
            missing,
            "demo",
            1,
            WorkflowState.INVESTIGATING,
            WorkflowState.AWAITING_OPERATOR_APPROVAL,
        )
    with pytest.raises(WorkflowConflict, match="workflow not found"):
        repository.invalidate(missing, "demo", 1)
    current = repository.ensure(snapshot())
    with pytest.raises(WorkflowConflict, match="stale"):
        repository.transition(
            current.workflow_id,
            current.tenant_id,
            99,
            current.state,
            WorkflowState.APPROVED_AWAITING_EXECUTION,
        )
    inactive = repository.invalidate(current.workflow_id, current.tenant_id, 1)
    with pytest.raises(WorkflowConflict, match="inactive"):
        repository.transition(
            inactive.workflow_id,
            inactive.tenant_id,
            2,
            inactive.state,
            WorkflowState.INVESTIGATING,
        )
    with pytest.raises(WorkflowConflict, match="stale"):
        repository.invalidate(inactive.workflow_id, inactive.tenant_id, 1)


class Cursor:
    def __init__(self, rows: list[object | None]) -> None:
        self.rows = rows
        self.executions: list[tuple[str, object]] = []

    def __enter__(self) -> "Cursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, parameters: object = None) -> None:
        self.executions.append((query, parameters))

    def fetchone(self) -> object | None:
        return self.rows.pop(0)


class Connection:
    def __init__(self, cursor: Cursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> "Connection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def cursor(self) -> Cursor:
        return self._cursor


class Pool:
    def __init__(self, rows: list[object | None]) -> None:
        self.cursor = Cursor(rows)

    def connection(self) -> Connection:
        return Connection(self.cursor)


def postgres_repository(rows: list[object | None]) -> PostgresWorkflowRepository:
    repository = object.__new__(PostgresWorkflowRepository)
    repository._pool = Pool(rows)  # type: ignore[assignment]
    return repository


def workflow_row(value: WorkflowSnapshot) -> dict[str, Any]:
    return value.model_dump()


def test_postgres_repository_constructor_and_crud(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()
    captured: dict[str, object] = {}

    def pool_factory(*args: object, **kwargs: object) -> object:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return sentinel

    monkeypatch.setattr("recallops.workflow.ConnectionPool", pool_factory)
    constructed = PostgresWorkflowRepository("postgresql://example", 7, 11)
    assert constructed._pool is sentinel
    assert captured["args"] == ("postgresql://example",)

    current = snapshot()
    assert postgres_repository([workflow_row(current)]).ensure(current) == current
    with pytest.raises(RuntimeError, match="workflow upsert"):
        postgres_repository([None]).ensure(current)

    assert (
        postgres_repository([workflow_row(current)]).get(current.workflow_id, current.tenant_id)
        == current
    )
    assert postgres_repository([None]).get(current.workflow_id, current.tenant_id) is None

    approved = current.model_copy(
        update={
            "state": WorkflowState.APPROVED_AWAITING_EXECUTION,
            "epoch": 2,
            "operator_subject": "operator",
        }
    )
    assert (
        postgres_repository([workflow_row(approved)]).transition(
            current.workflow_id,
            current.tenant_id,
            1,
            current.state,
            approved.state,
            operator_subject="operator",
        )
        == approved
    )
    with pytest.raises(WorkflowConflict, match="stale"):
        postgres_repository([None]).transition(
            current.workflow_id,
            current.tenant_id,
            1,
            current.state,
            approved.state,
        )

    inactive = current.model_copy(update={"active": False, "epoch": 2})
    assert (
        postgres_repository([workflow_row(inactive)]).invalidate(
            current.workflow_id, current.tenant_id, 1
        )
        == inactive
    )
    with pytest.raises(WorkflowConflict, match="stale"):
        postgres_repository([None]).invalidate(current.workflow_id, current.tenant_id, 1)


def test_api_rejects_webmcp_authority_and_stale_epochs() -> None:
    store = InMemoryStore()
    app = create_app(Settings(store="memory"), store)
    client = TestClient(app)
    agent_headers = {
        "X-Tenant-ID": "demo",
        "X-Actor-ID": "demo-agent",
        "X-Roles": "agent",
        "X-RecallOps-Channel": "webmcp",
    }
    created = client.post(
        "/v1/incidents",
        headers=agent_headers,
        json={
            "tenant_id": "demo",
            "service": "checkout",
            "service_version": "v1",
            "symptom": "latency spike",
            "idempotency_key": "webmcp-authority-test",
        },
    )
    assert created.status_code == 201
    incident_id = created.json()["incident_id"]
    capability = client.get(
        f"/v1/incidents/{incident_id}/capabilities", headers=agent_headers
    ).json()
    assert capability["state"] == "INVESTIGATING"

    approval = {
        "tenant_id": "demo",
        "actor_id": "demo-agent",
        "approved": True,
        "proposal_hash": created.json()["proposed_action"]["action_hash"],
        "reason": "agent must never be allowed to approve",
    }
    denied = client.post(
        f"/v1/incidents/{incident_id}/approval",
        headers={**agent_headers, "X-Roles": "agent,operator", "X-Workflow-Epoch": "1"},
        json=approval,
    )
    assert denied.status_code == 403
    assert store.get_approval(UUID(incident_id), "demo") is None

    reset = client.post(
        f"/v1/incidents/{incident_id}/reset",
        headers={
            "X-Tenant-ID": "demo",
            "X-Actor-ID": "demo-operator",
            "X-Roles": "operator",
            "X-RecallOps-Channel": "ui",
            "X-Workflow-Epoch": "1",
        },
    )
    assert reset.status_code == 200
    after = client.get(f"/v1/incidents/{incident_id}/capabilities", headers=agent_headers).json()
    assert after["active"] is False
    assert after["available_tools"] == []
    assert after["epoch"] == 2

    stale_reset = client.post(
        f"/v1/incidents/{incident_id}/reset",
        headers={
            "X-Tenant-ID": "demo",
            "X-Actor-ID": "demo-operator",
            "X-Roles": "operator",
            "X-RecallOps-Channel": "ui",
            "X-Workflow-Epoch": "1",
        },
    )
    assert stale_reset.status_code == 409


def test_authoritative_api_rejects_invalid_channels_roles_and_epochs() -> None:
    embedder = DeterministicEmbedder()
    seed = Memory(
        tenant_id="demo",
        service="checkout",
        service_version="v1",
        symptom="latency spike",
        action="reduce checkout concurrency",
        outcome="latency recovered",
        outcome_score=1,
        confidence=0.95,
        reviewed_by="seed-reviewer",
        embedding=embedder.embed("checkout latency spike"),
    )
    store = InMemoryStore([seed])
    client = TestClient(create_app(Settings(store="memory"), store))
    payload = {
        "tenant_id": "demo",
        "service": "checkout",
        "service_version": "v1",
        "symptom": "latency spike",
        "idempotency_key": "authoritative-edge-cases",
    }
    assert (
        client.post(
            "/v1/incidents",
            headers={"X-Tenant-ID": "demo", "X-RecallOps-Channel": "invalid"},
            json=payload,
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/v1/incidents",
            headers={"X-Tenant-ID": "demo", "X-RecallOps-Channel": "webmcp"},
            json=payload,
        ).status_code
        == 403
    )
    assert (
        client.get(
            f"/v1/incidents/{uuid4()}/capabilities", headers={"X-Tenant-ID": "demo"}
        ).status_code
        == 404
    )

    agent_headers = {
        "X-Tenant-ID": "demo",
        "X-Actor-ID": "agent",
        "X-Roles": "agent",
        "X-RecallOps-Channel": "webmcp",
    }
    incident = client.post("/v1/incidents", headers=agent_headers, json=payload).json()
    incident_id = incident["incident_id"]
    action = incident["proposed_action"]
    approval = {
        "tenant_id": "demo",
        "actor_id": "operator",
        "approved": True,
        "proposal_hash": action["action_hash"],
        "reason": "exact proposal reviewed",
    }
    operator = {"X-Tenant-ID": "demo", "X-Actor-ID": "operator", "X-Roles": "operator"}
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval", headers=operator, json=approval
        ).status_code
        == 428
    )
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval",
            headers={**operator, "X-RecallOps-Channel": "webmcp", "X-Workflow-Epoch": "1"},
            json=approval,
        ).status_code
        == 403
    )
    assert store.get_approval(UUID(incident_id), "demo") is None
    ui_epoch_1 = {**operator, "X-RecallOps-Channel": "ui", "X-Workflow-Epoch": "1"}
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval", headers=ui_epoch_1, json=approval
        ).status_code
        == 200
    )
    conflicting_actor = {
        "tenant_id": "demo",
        "actor_id": "other-operator",
        "approved": True,
        "proposal_hash": action["action_hash"],
        "reason": "cannot replace the recorded operator",
    }
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/approval",
            headers={
                "X-Tenant-ID": "demo",
                "X-Actor-ID": "other-operator",
                "X-Roles": "operator",
                "X-RecallOps-Channel": "ui",
                "X-Workflow-Epoch": "1",
            },
            json=conflicting_actor,
        ).status_code
        == 409
    )

    execution = {
        "tenant_id": "demo",
        "actor_id": "operator",
        "action_hash": action["action_hash"],
        "action_taken": action["command"],
        "evidence_refs": ["test://workflow/execution"],
    }
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/execution",
            headers={**operator, "X-RecallOps-Channel": "webmcp", "X-Workflow-Epoch": "2"},
            json=execution,
        ).status_code
        == 403
    )
    ui_epoch_2 = {**operator, "X-RecallOps-Channel": "ui", "X-Workflow-Epoch": "2"}
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/execution", headers=ui_epoch_2, json=execution
        ).status_code
        == 201
    )
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/execution",
            headers={**operator, "X-RecallOps-Channel": "ui", "X-Workflow-Epoch": "3"},
            json=execution,
        ).status_code
        == 409
    )

    outcome = {
        "tenant_id": "demo",
        "actor_id": "operator",
        "action_taken": action["command"],
        "outcome": "latency recovered",
        "outcome_score": 1,
        "confidence": 0.9,
    }
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/outcome",
            headers={**operator, "X-RecallOps-Channel": "webmcp", "X-Workflow-Epoch": "3"},
            json=outcome,
        ).status_code
        == 403
    )
    memory = client.post(
        f"/v1/incidents/{incident_id}/outcome",
        headers={**operator, "X-RecallOps-Channel": "ui", "X-Workflow-Epoch": "3"},
        json=outcome,
    ).json()
    reviewer = {"X-Tenant-ID": "demo", "X-Actor-ID": "reviewer", "X-Roles": "reviewer"}
    governance = {
        "tenant_id": "demo",
        "actor_id": "reviewer",
        "action": GovernanceAction.SUPERSEDE,
        "reason": "missing replacement is invalid",
    }
    assert (
        client.post(
            f"/v1/memories/{memory['id']}/governance",
            headers={**reviewer, "X-RecallOps-Channel": "webmcp", "X-Workflow-Epoch": "4"},
            json=governance,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/v1/memories/{memory['id']}/governance", headers=reviewer, json=governance
        ).status_code
        == 428
    )
    assert (
        client.post(
            f"/v1/memories/{memory['id']}/governance",
            headers={**reviewer, "X-RecallOps-Channel": "ui", "X-Workflow-Epoch": "4"},
            json=governance,
        ).status_code
        == 409
    )

    standalone = seed.model_copy(update={"id": uuid4()})
    store.add_memory(standalone)
    standalone_governance = {
        "tenant_id": "demo",
        "actor_id": "reviewer",
        "action": GovernanceAction.QUARANTINE,
        "reason": "standalone seed revoked from retrieval",
    }
    assert (
        client.post(
            f"/v1/memories/{standalone.id}/governance",
            headers={**reviewer, "X-RecallOps-Channel": "ui"},
            json=standalone_governance,
        ).status_code
        == 200
    )
    assert (
        client.post(
            f"/v1/incidents/{incident_id}/reset",
            headers={**operator, "X-RecallOps-Channel": "webmcp", "X-Workflow-Epoch": "4"},
        ).status_code
        == 403
    )
