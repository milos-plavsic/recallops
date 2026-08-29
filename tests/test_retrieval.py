from contextlib import AbstractContextManager
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from hypothesis import given, settings
from hypothesis import strategies as st

from recallops.domain import CompatibilityPolicy, IncidentCreate, Memory, MemoryState
from recallops.embedding import DeterministicEmbedder
from recallops.store import (
    InMemoryStore,
    PostgresStore,
    version_compatibility,
)


def _incident(tenant: str = "tenant-a") -> IncidentCreate:
    return IncidentCreate(
        tenant_id=tenant,
        service="checkout",
        service_version="2.4.1",
        symptom="latency spike after pool exhaustion",
        idempotency_key=f"event-for-{tenant}",
    )


def _memory(
    *,
    tenant: str = "tenant-a",
    version: str = "2.4.1",
    outcome_score: float = 1.0,
    state: MemoryState = MemoryState.ACTIVE,
    valid: bool = True,
    symptom: str = "latency spike after pool exhaustion",
) -> Memory:
    embedder = DeterministicEmbedder()
    return Memory(
        tenant_id=tenant,
        service="checkout",
        service_version=version,
        symptom=symptom,
        action=f"action-{tenant}-{version}-{outcome_score}",
        outcome="measured outcome",
        outcome_score=outcome_score,
        confidence=0.95,
        state=state,
        valid=valid,
        embedding_space=embedder.space_id,
        embedding=embedder.embed(f"checkout {symptom}"),
    )


@given(
    major=st.integers(min_value=0, max_value=100),
    minor=st.integers(min_value=0, max_value=100),
    patch=st.integers(min_value=0, max_value=100),
)
def test_exact_versions_are_the_only_fully_compatible_versions(
    major: int, minor: int, patch: int
) -> None:
    version = f"{major}.{minor}.{patch}"

    assert version_compatibility(version, version) == 1.0
    assert version_compatibility(version, f"{major}.{minor}.{patch + 1}") < 1.0


def test_explicit_semver_policies_define_the_only_non_exact_full_compatibility() -> None:
    assert version_compatibility("2.4.1", "2.4.9", CompatibilityPolicy.SEMVER_PATCH) == 1.0
    assert version_compatibility("2.4.1", "2.9.0", CompatibilityPolicy.SEMVER_MINOR) == 1.0
    assert version_compatibility("2.4.1", "3.0.0", CompatibilityPolicy.SEMVER_MINOR) == 0.0
    assert version_compatibility("release-a", "release-b", CompatibilityPolicy.SEMVER_MINOR) < 1


@given(
    foreign_count=st.integers(min_value=0, max_value=30),
    invalid_count=st.integers(min_value=0, max_value=30),
)
@settings(max_examples=40, deadline=None)
def test_tenant_and_governance_filters_hold_for_arbitrary_candidate_counts(
    foreign_count: int, invalid_count: int
) -> None:
    embedder = DeterministicEmbedder()
    eligible = _memory()
    memories = [eligible]
    memories.extend(_memory(tenant=f"foreign-{index}") for index in range(foreign_count))
    memories.extend(
        _memory(state=MemoryState.QUARANTINED, valid=False) for _ in range(invalid_count)
    )

    retrieved = InMemoryStore(memories).find_memories(
        _incident(),
        embedder.embed("checkout latency spike after pool exhaustion"),
        embedder.space_id,
        5,
    )

    assert retrieved
    assert all(item.memory.tenant_id == "tenant-a" for item in retrieved)
    assert all(item.memory.state is MemoryState.ACTIVE for item in retrieved)
    assert all(item.memory.valid for item in retrieved)


class _Cursor(AbstractContextManager["_Cursor"]):
    def __init__(self, result_sets: list[list[dict[str, Any]]]) -> None:
        self.result_sets = result_sets
        self.executions: list[tuple[str, tuple[object, ...] | None]] = []

    def __enter__(self) -> "_Cursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, parameters: tuple[object, ...] | None = None) -> None:
        self.executions.append((query, parameters))

    def fetchall(self) -> list[dict[str, Any]]:
        return self.result_sets[len(self.executions) - 1]


class _Connection(AbstractContextManager["_Connection"]):
    def __init__(self, cursor: _Cursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> "_Connection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def cursor(self) -> _Cursor:
        return self._cursor


class _Pool:
    def __init__(self, cursor: _Cursor) -> None:
        self._connection = _Connection(cursor)

    def connection(self) -> _Connection:
        return self._connection


def _database_row(memory: Memory, similarity: float) -> dict[str, Any]:
    row = memory.model_dump()
    row["embedding"] = "[" + ",".join(str(value) for value in memory.embedding) + "]"
    row["similarity"] = similarity
    return row


def test_postgres_retrieval_unions_safe_compatibility_and_semantic_lanes() -> None:
    safe = _memory(symptom="pool exhaustion during checkout latency")
    failure = _memory(outcome_score=-1.0)
    cursor = _Cursor(
        [
            [_database_row(safe, 0.72)],
            [],
            [_database_row(failure, 1.0)],
        ]
    )
    store = object.__new__(PostgresStore)
    store._pool = _Pool(cursor)  # type: ignore[assignment]
    store._retrieval_candidate_multiplier = 8
    embedder = DeterministicEmbedder()

    retrieved = store.find_memories(
        _incident(),
        embedder.embed("checkout latency spike after pool exhaustion"),
        embedder.space_id,
        1,
    )

    assert retrieved[0].memory.id == safe.id
    assert len(cursor.executions) == 3
    compatible_query, compatible_parameters = cursor.executions[0]
    assert "service_version = %s AND outcome_score > 0" in compatible_query
    assert compatible_parameters is not None
    assert compatible_parameters[-1] == 8
    policy_query, policy_parameters = cursor.executions[1]
    assert "compatibility_policy IN ('semver_patch', 'semver_minor')" in policy_query
    assert policy_parameters is not None and policy_parameters[-1] == 8
    semantic_query, semantic_parameters = cursor.executions[2]
    assert "FROM memories@memories_embedding_v2" in semantic_query
    assert "JOIN nearest USING (id)" in semantic_query
    assert semantic_parameters is not None
    assert semantic_parameters[5] == 32
    assert semantic_parameters[-1] == 8


def test_postgres_retrieval_deduplicates_lane_overlap() -> None:
    memory = _memory()
    row = _database_row(memory, 0.91)
    cursor = _Cursor([[row], [], [row]])
    store = object.__new__(PostgresStore)
    store._pool = _Pool(cursor)  # type: ignore[assignment]
    store._retrieval_candidate_multiplier = 4
    embedder = DeterministicEmbedder()

    retrieved = store.find_memories(
        _incident(),
        embedder.embed("checkout latency spike after pool exhaustion"),
        embedder.space_id,
        5,
    )

    assert [item.memory.id for item in retrieved] == [memory.id]


def test_retrieval_order_is_deterministic_for_equal_scores() -> None:
    embedder = DeterministicEmbedder()
    created_at = datetime(2026, 8, 10, tzinfo=UTC)
    first_payload = _memory().model_dump()
    first_payload.update(
        {"id": UUID(int=1), "created_at": created_at, "action": "first", "memory_digest": None}
    )
    first = Memory.model_validate(first_payload)
    second_payload = _memory().model_dump()
    second_payload.update(
        {"id": UUID(int=2), "created_at": created_at, "action": "second", "memory_digest": None}
    )
    second = Memory.model_validate(second_payload)
    store = InMemoryStore([first, second])

    observed_orders = {
        tuple(
            item.memory.id
            for item in store.find_memories(
                _incident(),
                embedder.embed("checkout latency spike after pool exhaustion"),
                embedder.space_id,
                2,
            )
        )
        for _ in range(10)
    }

    assert observed_orders == {(UUID(int=2), UUID(int=1))}
