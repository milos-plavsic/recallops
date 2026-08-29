from datetime import UTC, datetime
from uuid import UUID

import pytest

from recallops.ledger import (
    ZERO_EVENT_HASH,
    ActivityObservation,
    AuthorityLedgerConflict,
    InMemoryAuthorityLedgerRepository,
    PostgresAuthorityLedgerRepository,
    authority_event_hash,
    canonical_event_payload,
    verify_event,
)
from recallops.workflow import RequestChannel, WorkflowSnapshot, WorkflowState

RUN_ID = UUID("00000000-0000-0000-0000-000000000042")
WORKFLOW_ID = UUID("10000000-0000-0000-0000-000000000042")


def snapshots() -> tuple[WorkflowSnapshot, WorkflowSnapshot]:
    recorded = datetime(2026, 8, 29, 1, 2, 3, tzinfo=UTC)
    before = WorkflowSnapshot(
        workflow_id=WORKFLOW_ID,
        tenant_id="judge_fixture",
        state=WorkflowState.INVESTIGATING,
        epoch=1,
        created_at=recorded,
        updated_at=recorded,
    )
    return before, before.model_copy(
        update={
            "state": WorkflowState.AWAITING_OPERATOR_APPROVAL,
            "epoch": 2,
            "updated_at": recorded,
        }
    )


def bound_repository(*, fault_at: str | None = None) -> InMemoryAuthorityLedgerRepository:
    def fault(stage: str) -> None:
        if stage == fault_at:
            raise RuntimeError(f"injected at {stage}")

    repository = InMemoryAuthorityLedgerRepository(fault if fault_at else None)
    repository.bind_run("judge_fixture", WORKFLOW_ID, RUN_ID, "build-42", "policy-42")
    return repository


def test_authority_hash_chain_is_independently_recomputable() -> None:
    before, after = snapshots()
    repository = bound_repository()
    first = repository.append_transition(
        before,
        after,
        actor_subject="agent-42",
        actor_role="agent",
        channel=RequestChannel.WEBMCP,
    )
    assert first is not None
    assert verify_event(first, ZERO_EVENT_HASH)
    assert first.event_hash == authority_event_hash(ZERO_EVENT_HASH, canonical_event_payload(first))

    second_after = after.model_copy(update={"state": WorkflowState.INVESTIGATING, "epoch": 3})
    second = repository.append_transition(
        after,
        second_after,
        actor_subject="operator-42",
        actor_role="operator",
        channel=RequestChannel.UI,
    )
    assert second is not None and verify_event(second, first.event_hash)
    assert [item.sequence for item in repository.list_events(RUN_ID, "judge_fixture")] == [1, 2]


def test_genesis_binds_initial_capability_state_as_first_event() -> None:
    initial, _ = snapshots()
    repository = bound_repository()
    genesis = repository.append_genesis(initial)
    assert genesis is not None
    assert genesis.sequence == 1
    assert genesis.event_type == "RUN_GENESIS"
    assert genesis.state_before == "ABSENT" and genesis.epoch_before == 0
    assert genesis.state_after == "INVESTIGATING" and genesis.epoch_after == 1
    assert genesis.capabilities_before == ()
    assert genesis.capabilities_after == initial.available_tools
    assert verify_event(genesis, ZERO_EVENT_HASH)


@pytest.mark.parametrize("stage", ["before_event", "after_event", "before_head", "after_head"])
def test_fault_injection_never_leaves_a_partial_in_memory_append(stage: str) -> None:
    before, after = snapshots()
    repository = bound_repository(fault_at=stage)
    with pytest.raises(RuntimeError, match=stage):
        repository.append_transition(
            before,
            after,
            actor_subject="operator-42",
            actor_role="operator",
            channel=RequestChannel.UI,
        )
    assert repository.list_events(RUN_ID, "judge_fixture") == []


def test_activity_is_visibly_supporting_and_deterministically_merged() -> None:
    before, after = snapshots()
    repository = bound_repository()
    event = repository.append_transition(
        before,
        after,
        actor_subject="agent-42",
        actor_role="agent",
        channel=RequestChannel.WEBMCP,
    )
    assert event is not None
    observation = ActivityObservation(
        activity_id=UUID("00000000-0000-0000-0000-000000000001"),
        run_id=RUN_ID,
        tenant_id="judge_fixture",
        workflow_id=WORKFLOW_ID,
        recorded_at=event.recorded_at,
        source="browser",
        actor_subject="browser-instance",
        activity_type="tool_registered",
        tool_name="inspect_incident",
        outcome="observed",
        display_summary="Browser reports inspect_incident registration",
        build_sha="build-42",
    )
    repository.add_activity(observation)
    timeline = repository.timeline(RUN_ID, "judge_fixture")
    assert [item.entry_id for item in timeline] == [observation.activity_id, event.event_id]
    assert timeline[0].evidence_class == "supporting_observation"
    assert timeline[0].sequence is None and timeline[0].event_hash is None
    assert len(repository.list_events(RUN_ID, "judge_fixture")) == 1


@pytest.mark.parametrize("bad_hash", ["f" * 63, "G" * 64, "F" * 64])
def test_hash_predecessor_is_strict_lowercase_32_byte_hex(bad_hash: str) -> None:
    with pytest.raises(ValueError, match="32 bytes of lowercase hex"):
        authority_event_hash(bad_hash, {})


def test_in_memory_receipt_guards_and_status_absence() -> None:
    before, after = snapshots()
    repository = bound_repository()
    event = repository.append_transition(
        before,
        after,
        actor_subject="agent",
        actor_role="agent",
        channel=RequestChannel.WEBMCP,
    )
    assert event is not None
    with pytest.raises(AuthorityLedgerConflict, match="finalized ledger head"):
        repository.request_receipt(
            event,
            receipt_policy_version="receipt-v1",
            image_digest=f"sha256:{'a' * 64}",
            evaluation_version="evaluation-v1",
            synthetic=True,
            publish_public=True,
        )
    assert repository.receipt_status(RUN_ID, "judge_fixture") is None


class _ScriptedCursor:
    def __init__(self, rows: list[object | None]) -> None:
        self.rows = rows
        self.executions: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, parameters: object) -> None:
        self.executions.append(query)

    def fetchone(self) -> object | None:
        return self.rows.pop(0) if self.rows else None

    def fetchall(self) -> list[object]:
        return []


class _ScriptedConnection:
    def __init__(self, cursor: _ScriptedCursor) -> None:
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def cursor(self) -> _ScriptedCursor:
        return self._cursor


class _ScriptedPool:
    def __init__(self, rows: list[object | None]) -> None:
        self.cursor = _ScriptedCursor(rows)

    def connection(self) -> _ScriptedConnection:
        return _ScriptedConnection(self.cursor)


def _reviewed_event():
    before, _ = snapshots()
    reviewed = before.model_copy(update={"state": WorkflowState.REVIEWED, "epoch": 2})
    repository = bound_repository()
    event = repository.append_transition(
        before,
        reviewed,
        actor_subject="reviewer",
        actor_role="reviewer",
        channel=RequestChannel.UI,
    )
    assert event is not None
    return event


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        (
            [{"run_id": RUN_ID, "build_sha": "build", "capability_policy_version": "v1"}],
            "enclosing serializable",
        ),
        (
            [{"run_id": RUN_ID, "build_sha": "build", "capability_policy_version": "v1"}, None],
            "ledger head unavailable",
        ),
        (
            [
                {"run_id": RUN_ID, "build_sha": "build", "capability_policy_version": "v1"},
                {"closed": True, "last_sequence": 0, "last_event_hash": ZERO_EVENT_HASH},
            ],
            "ledger is closed",
        ),
        (
            [
                {"run_id": RUN_ID, "build_sha": "build", "capability_policy_version": "v1"},
                {"closed": False, "last_sequence": 0, "last_event_hash": ZERO_EVENT_HASH},
                None,
            ],
            "ledger predecessor changed",
        ),
    ],
)
def test_postgres_append_fails_closed_at_each_ledger_boundary(
    rows: list[object | None], message: str
) -> None:
    before, after = snapshots()
    repository = PostgresAuthorityLedgerRepository(_ScriptedPool(rows))
    if message != "enclosing serializable":
        repository._transaction_bound = True
    with pytest.raises((AuthorityLedgerConflict, RuntimeError), match=message):
        repository.append_transition(
            before,
            after,
            actor_subject="agent",
            actor_role="agent",
            channel=RequestChannel.WEBMCP,
        )


def test_postgres_receipt_request_guards_and_status_projection() -> None:
    event = _reviewed_event()
    arguments = {
        "receipt_policy_version": "receipt-v1",
        "image_digest": f"sha256:{'a' * 64}",
        "evaluation_version": "evaluation-v1",
        "synthetic": True,
        "publish_public": True,
    }
    with pytest.raises(RuntimeError, match="enclosing authority transaction"):
        PostgresAuthorityLedgerRepository(_ScriptedPool([])).request_receipt(event, **arguments)
    unreviewed = event.model_copy(update={"state_after": "INVESTIGATING"})
    bound = PostgresAuthorityLedgerRepository(_ScriptedPool([]))
    bound._transaction_bound = True
    with pytest.raises(AuthorityLedgerConflict, match="reviewed workflow"):
        bound.request_receipt(unreviewed, **arguments)
    for head in (None, {"last_sequence": event.sequence + 1, "last_event_hash": event.event_hash}):
        bound = PostgresAuthorityLedgerRepository(_ScriptedPool([head]))
        bound._transaction_bound = True
        with pytest.raises(AuthorityLedgerConflict, match="locked ledger head"):
            bound.request_receipt(event, **arguments)

    successful_pool = _ScriptedPool(
        [
            {"last_sequence": event.sequence, "last_event_hash": event.event_hash},
            event.model_dump(),
        ]
    )
    bound = PostgresAuthorityLedgerRepository(successful_pool)
    bound._transaction_bound = True
    assert isinstance(bound.request_receipt(event, **arguments), UUID)
    assert "FOR UPDATE" in successful_pool.cursor.executions[0]
    assert "authority_events" in successful_pool.cursor.executions[1]
    assert "FOR UPDATE" not in successful_pool.cursor.executions[1]

    assert (
        PostgresAuthorityLedgerRepository(_ScriptedPool([None])).receipt_status(
            RUN_ID, "judge_fixture"
        )
        is None
    )
    row = {
        "receipt_id": UUID(int=9),
        "status": "signed",
        "ledger_last_sequence": 7,
        "ledger_head_hash": "b" * 64,
        "bundle_digest": "c" * 64,
        "key_thumbprint": "k" * 43,
        "signing_algorithm": "Ed25519",
        "public_at": datetime.now(UTC),
        "failure_code": None,
    }
    status = PostgresAuthorityLedgerRepository(_ScriptedPool([row])).receipt_status(
        RUN_ID, "judge_fixture"
    )
    assert status is not None and status.public and status.target_sequence == 7
