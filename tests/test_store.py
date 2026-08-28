from contextlib import nullcontext
from typing import Any
from uuid import uuid4

import pytest

from recallops.domain import (
    EvidenceVerification,
    ExecutionAttestation,
    GovernanceAction,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    MemoryState,
)
from recallops.embedding import DeterministicEmbedder
from recallops.service import DeterministicReasoner, IncidentService
from recallops.store import (
    InMemoryStore,
    MemoryGovernanceError,
    PostgresStore,
    version_compatibility,
)


def active_memory(**updates: object) -> Memory:
    base = Memory(
        tenant_id="demo",
        service="checkout",
        service_version="2.4.1",
        symptom="latency",
        action="inspect",
        outcome="recovered",
        outcome_score=1,
        confidence=0.9,
        embedding=[0.0] * 1024,
    )
    return base.model_copy(update=updates)


def test_store_policy_failure_paths_are_explicit() -> None:
    assert version_compatibility("2.4.1", "2.5.1") == 0.35
    assert version_compatibility("release-a", "2.5.1") == 0.2
    assert version_compatibility("2.5.1", "release-a") == 0.2
    store = InMemoryStore()
    with pytest.raises(ValueError, match="source incident"):
        store.save_outcome_memory(active_memory())

    terminal = active_memory(state=MemoryState.REVOKED, valid=False)
    store = InMemoryStore([terminal])
    with pytest.raises(MemoryGovernanceError, match="cannot transition"):
        store.govern_memory(
            terminal.id,
            MemoryGovernanceRequest(
                tenant_id="demo",
                actor_id="reviewer",
                action=GovernanceAction.ACTIVATE,
                reason="invalid terminal transition",
            ),
        )

    current = active_memory()
    store = InMemoryStore([current])
    with pytest.raises(MemoryGovernanceError, match="replacement memory"):
        store.govern_memory(
            current.id,
            MemoryGovernanceRequest(
                tenant_id="demo",
                actor_id="reviewer",
                action=GovernanceAction.REVOKE,
                reason="replacement does not belong here",
                replacement_memory_id=uuid4(),
            ),
        )
    with pytest.raises(MemoryGovernanceError, match="active same-tenant replacement"):
        store.govern_memory(
            current.id,
            MemoryGovernanceRequest(
                tenant_id="demo",
                actor_id="reviewer",
                action=GovernanceAction.SUPERSEDE,
                reason="missing replacement",
                replacement_memory_id=uuid4(),
            ),
        )


def test_in_memory_execution_replay_rejects_changed_hash() -> None:
    store = InMemoryStore()
    incident_id = uuid4()
    first = ExecutionAttestation(
        incident_id=incident_id,
        tenant_id="demo",
        actor_id="operator",
        action_hash="0" * 64,
        action_taken="inspect",
        evidence_refs=["test://execution"],
        evidence_verification=EvidenceVerification.MANUAL_ATTESTATION,
    )
    assert store.record_execution(first) is first
    assert store.record_execution(first) is first
    with pytest.raises(MemoryGovernanceError, match="different execution"):
        store.record_execution(first.model_copy(update={"action_hash": "1" * 64}))


class Cursor:
    def __init__(self, rows: list[object | None]) -> None:
        self.rows = rows
        self.rowcount = 1

    def __enter__(self) -> "Cursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, parameters: object = None) -> None:
        pass

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

    def transaction(self) -> Any:
        return nullcontext()


class Pool:
    def __init__(self, rows: list[object | None]) -> None:
        self.connection_object = Connection(Cursor(rows))

    def connection(self) -> Connection:
        return self.connection_object


def postgres_with_rows(rows: list[object | None]) -> PostgresStore:
    store = object.__new__(PostgresStore)
    store._pool = Pool(rows)  # type: ignore[assignment]
    store._retrieval_candidate_multiplier = 1
    return store


def database_row(memory: Memory) -> dict[str, Any]:
    row = memory.model_dump()
    row["embedding"] = "[" + ",".join("0" for _ in memory.embedding) + "]"
    return row


def test_postgres_constructor_and_readiness_fail_closed() -> None:
    with pytest.raises(ValueError, match="candidate_multiplier"):
        PostgresStore("postgres://unused", retrieval_candidate_multiplier=0)
    store = object.__new__(PostgresStore)
    store._pool = pytest.raises(RuntimeError)  # type: ignore[assignment]
    assert store.ready() is False


def test_postgres_write_paths_reject_missing_returned_rows() -> None:
    with pytest.raises(ValueError, match="source incident"):
        postgres_with_rows([]).save_outcome_memory(active_memory())
    memory = active_memory(source_incident_id=uuid4())
    with pytest.raises(RuntimeError, match="outcome memory upsert"):
        postgres_with_rows([None]).save_outcome_memory(memory)

    request = MemoryGovernanceRequest(
        tenant_id="demo",
        actor_id="reviewer",
        action=GovernanceAction.REVOKE,
        reason="verified unsafe",
    )
    with pytest.raises(RuntimeError, match="governance update"):
        postgres_with_rows([database_row(memory), None]).govern_memory(memory.id, request)
    missing_replacement = request.model_copy(
        update={
            "action": GovernanceAction.SUPERSEDE,
            "replacement_memory_id": uuid4(),
        }
    )
    with pytest.raises(MemoryGovernanceError, match="active same-tenant replacement"):
        postgres_with_rows([database_row(memory), None]).govern_memory(
            memory.id, missing_replacement
        )

    execution = ExecutionAttestation(
        incident_id=uuid4(),
        tenant_id="demo",
        actor_id="operator",
        action_hash="0" * 64,
        action_taken="inspect",
        evidence_refs=["test://execution"],
    )
    with pytest.raises(RuntimeError, match="attestation upsert"):
        postgres_with_rows([None]).record_execution(execution)
    changed = execution.model_dump()
    changed["action_hash"] = "1" * 64
    changed["evidence_refs"] = {"evidence_refs": ["test://execution"]}
    with pytest.raises(MemoryGovernanceError, match="different execution"):
        postgres_with_rows([changed]).record_execution(execution)


def test_postgres_analysis_upsert_requires_a_returned_row() -> None:
    incident = IncidentCreate(
        tenant_id="demo",
        service="checkout",
        service_version="v1",
        symptom="latency",
        idempotency_key="store-no-row",
    )
    analysis = IncidentService(
        InMemoryStore(), DeterministicEmbedder(), DeterministicReasoner()
    ).analyze(incident)
    with pytest.raises(RuntimeError, match="incident upsert"):
        postgres_with_rows([None]).save_analysis(incident, analysis)


def test_postgres_get_memory_is_tenant_scoped() -> None:
    memory = active_memory()
    assert postgres_with_rows([database_row(memory)]).get_memory(memory.id, "demo") == memory
    assert postgres_with_rows([None]).get_memory(memory.id, "other") is None
