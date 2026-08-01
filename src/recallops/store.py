import math
import threading
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from uuid import UUID

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from recallops.domain import (
    GovernanceAction,
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryEvent,
    MemoryGovernanceRequest,
    MemoryState,
    RetrievedMemory,
)


def cosine_similarity(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    return dot / (left_norm * right_norm) if left_norm and right_norm else 0.0


def memory_rank_score(
    similarity: float, outcome_score: float, compatibility: float, confidence: float
) -> float:
    return (
        0.55 * similarity
        + 0.25 * outcome_score
        + 0.15 * compatibility
        + 0.05 * confidence
    )


def rank_memory(
    memory: Memory,
    similarity: float,
    service_version: str,
    *,
    as_of: datetime | None = None,
    half_life_days: float = 180.0,
) -> RetrievedMemory:
    as_of = as_of or datetime.now(UTC)
    age_days = max(0.0, (as_of - memory.created_at).total_seconds() / 86400)
    freshness = 0.5 ** (age_days / half_life_days)
    effective_confidence = memory.confidence * freshness
    effective_outcome = (
        memory.outcome_score * freshness if memory.outcome_score > 0 else memory.outcome_score
    )
    compatibility = 1.0 if memory.service_version == service_version else 0.2
    score = memory_rank_score(
        similarity, effective_outcome, compatibility, effective_confidence
    )
    return RetrievedMemory(
        memory=memory,
        semantic_similarity=max(-1.0, min(1.0, similarity)),
        compatibility=compatibility,
        freshness=freshness,
        effective_confidence=effective_confidence,
        rank_score=score,
    )


class MemoryGovernanceError(ValueError):
    pass


def _governance_target(
    memory: Memory, request: MemoryGovernanceRequest, memories: Iterable[Memory]
) -> MemoryState:
    targets = {
        GovernanceAction.ACTIVATE: MemoryState.ACTIVE,
        GovernanceAction.QUARANTINE: MemoryState.QUARANTINED,
        GovernanceAction.SUPERSEDE: MemoryState.SUPERSEDED,
        GovernanceAction.REVOKE: MemoryState.REVOKED,
    }
    allowed = {
        MemoryState.PENDING_REVIEW: {
            MemoryState.ACTIVE,
            MemoryState.QUARANTINED,
            MemoryState.REVOKED,
        },
        MemoryState.ACTIVE: {
            MemoryState.QUARANTINED,
            MemoryState.SUPERSEDED,
            MemoryState.REVOKED,
        },
        MemoryState.QUARANTINED: {MemoryState.ACTIVE, MemoryState.REVOKED},
        MemoryState.SUPERSEDED: set(),
        MemoryState.REVOKED: set(),
    }
    target = targets[request.action]
    if target not in allowed[memory.state]:
        raise MemoryGovernanceError(f"cannot transition {memory.state} to {target}")
    if target is MemoryState.ACTIVE and memory.observed_by == request.actor_id:
        raise MemoryGovernanceError("independent reviewer required for activation")
    if target is MemoryState.SUPERSEDED:
        replacement = next(
            (
                candidate
                for candidate in memories
                if candidate.id == request.replacement_memory_id
                and candidate.tenant_id == memory.tenant_id
                and candidate.state is MemoryState.ACTIVE
            ),
            None,
        )
        if replacement is None or replacement.id == memory.id:
            raise MemoryGovernanceError("active same-tenant replacement memory required")
    elif request.replacement_memory_id is not None:
        raise MemoryGovernanceError("replacement memory is only valid for supersession")
    return target


class MemoryStore(Protocol):
    def add_memory(self, memory: Memory) -> None: ...
    def find_memories(
        self, incident: IncidentCreate, embedding: list[float], limit: int
    ) -> list[RetrievedMemory]: ...
    def save_analysis(
        self, incident: IncidentCreate, analysis: IncidentAnalysis
    ) -> IncidentAnalysis: ...
    def get_analysis(self, incident_id: UUID, tenant_id: str) -> IncidentAnalysis | None: ...
    def get_incident(self, incident_id: UUID, tenant_id: str) -> IncidentCreate | None: ...
    def save_outcome_memory(self, memory: Memory) -> Memory: ...
    def govern_memory(
        self, memory_id: UUID, request: MemoryGovernanceRequest
    ) -> Memory | None: ...
    def record_approval(
        self, incident_id: UUID, tenant_id: str, actor_id: str, approved: bool, reason: str
    ) -> bool: ...


class InMemoryStore:
    def __init__(self, memories: Iterable[Memory] = ()) -> None:
        self.memories = list(memories)
        self.analyses: dict[tuple[str, UUID], IncidentAnalysis] = {}
        self.idempotency: dict[tuple[str, str], UUID] = {}
        self.incidents: dict[tuple[str, UUID], IncidentCreate] = {}
        self.outcome_memories: dict[tuple[str, UUID], Memory] = {}
        self.memory_events: list[MemoryEvent] = []
        self.approvals: set[tuple[str, UUID]] = set()
        self._lock = threading.RLock()

    def add_memory(self, memory: Memory) -> None:
        self.memories.append(memory)

    def find_memories(
        self, incident: IncidentCreate, embedding: list[float], limit: int
    ) -> list[RetrievedMemory]:
        candidates = (
            rank_memory(
                memory, cosine_similarity(memory.embedding, embedding), incident.service_version
            )
            for memory in self.memories
            if memory.tenant_id == incident.tenant_id
            and memory.service == incident.service
            and memory.valid
            and memory.state is MemoryState.ACTIVE
        )
        return sorted(candidates, key=lambda item: item.rank_score, reverse=True)[:limit]

    def save_analysis(
        self, incident: IncidentCreate, analysis: IncidentAnalysis
    ) -> IncidentAnalysis:
        with self._lock:
            key = (incident.tenant_id, incident.idempotency_key)
            existing_id = self.idempotency.get(key)
            if existing_id is not None:
                return self.analyses[(incident.tenant_id, existing_id)]
            self.idempotency[key] = analysis.incident_id
            self.analyses[(incident.tenant_id, analysis.incident_id)] = analysis
            self.incidents[(incident.tenant_id, analysis.incident_id)] = incident
            return analysis

    def get_analysis(self, incident_id: UUID, tenant_id: str) -> IncidentAnalysis | None:
        return self.analyses.get((tenant_id, incident_id))

    def get_incident(self, incident_id: UUID, tenant_id: str) -> IncidentCreate | None:
        return self.incidents.get((tenant_id, incident_id))

    def save_outcome_memory(self, memory: Memory) -> Memory:
        assert memory.source_incident_id is not None
        key = (memory.tenant_id, memory.source_incident_id)
        existing = self.outcome_memories.get(key)
        if existing is not None:
            return existing
        self.outcome_memories[key] = memory
        self.memories.append(memory)
        return memory

    def govern_memory(
        self, memory_id: UUID, request: MemoryGovernanceRequest
    ) -> Memory | None:
        memory = next(
            (
                candidate
                for candidate in self.memories
                if candidate.id == memory_id and candidate.tenant_id == request.tenant_id
            ),
            None,
        )
        if memory is None:
            return None
        target = _governance_target(memory, request, self.memories)
        updated = memory.model_copy(
            update={
                "state": target,
                "valid": target is MemoryState.ACTIVE,
                "reviewed_by": request.actor_id,
                "reviewed_at": datetime.now(UTC),
                "superseded_by": request.replacement_memory_id,
            }
        )
        self.memories[self.memories.index(memory)] = updated
        if memory.source_incident_id is not None:
            self.outcome_memories[(memory.tenant_id, memory.source_incident_id)] = updated
        self.memory_events.append(
            MemoryEvent(
                memory_id=memory.id,
                tenant_id=memory.tenant_id,
                actor_id=request.actor_id,
                action=request.action,
                reason=request.reason,
                from_state=memory.state,
                to_state=target,
            )
        )
        return updated

    def record_approval(
        self, incident_id: UUID, tenant_id: str, actor_id: str, approved: bool, reason: str
    ) -> bool:
        key = (tenant_id, incident_id)
        if key not in self.analyses or key in self.approvals:
            return False
        self.approvals.add(key)
        return True


class PostgresStore:
    def __init__(
        self,
        database_url: str,
        connect_timeout_seconds: int = 5,
        statement_timeout_seconds: int = 15,
    ) -> None:
        self._pool = ConnectionPool(
            database_url,
            min_size=1,
            max_size=10,
            timeout=connect_timeout_seconds,
            kwargs={
                "row_factory": dict_row,
                "connect_timeout": connect_timeout_seconds,
                "options": f"-c statement_timeout={statement_timeout_seconds * 1000}",
            },
        )

    def close(self) -> None:
        self._pool.close()

    @staticmethod
    def _vector(values: list[float]) -> str:
        return "[" + ",".join(f"{value:.9g}" for value in values) + "]"

    @staticmethod
    def _memory(raw_row: object) -> Memory:
        row = dict(cast(Mapping[str, Any], raw_row))
        row["embedding"] = [float(value) for value in row["embedding"].strip("[]").split(",")]
        return Memory.model_validate(row)

    def add_memory(self, memory: Memory) -> None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO memories
                (id, tenant_id, service, service_version, symptom, action, outcome,
                 outcome_score, confidence, valid, state, superseded_by, source_incident_id,
                 observed_by, reviewed_by, reviewed_at, embedding, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::VECTOR,%s)
                ON CONFLICT (id) DO NOTHING""",
                (
                    memory.id,
                    memory.tenant_id,
                    memory.service,
                    memory.service_version,
                    memory.symptom,
                    memory.action,
                    memory.outcome,
                    memory.outcome_score,
                    memory.confidence,
                    memory.valid,
                    memory.state,
                    memory.superseded_by,
                    memory.source_incident_id,
                    memory.observed_by,
                    memory.reviewed_by,
                    memory.reviewed_at,
                    self._vector(memory.embedding),
                    memory.created_at,
                ),
            )

    def find_memories(
        self, incident: IncidentCreate, embedding: list[float], limit: int
    ) -> list[RetrievedMemory]:
        vector = self._vector(embedding)
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, tenant_id, service, service_version, symptom, action, outcome,
                   outcome_score, confidence, valid, state, superseded_by, source_incident_id,
                   observed_by, reviewed_by, reviewed_at,
                   embedding::STRING AS embedding,
                   created_at, 1 - (embedding <=> %s::VECTOR) AS similarity
                   FROM memories
                   WHERE tenant_id = %s AND service = %s AND valid AND state = 'active'
                   ORDER BY embedding <=> %s::VECTOR LIMIT %s""",
                (vector, incident.tenant_id, incident.service, vector, limit * 3),
            )
            rows = cursor.fetchall()
        ranked = []
        for raw_row in rows:
            row = dict(raw_row)
            similarity = float(row.pop("similarity"))
            ranked.append(
                rank_memory(self._memory(row), similarity, incident.service_version)
            )
        return sorted(ranked, key=lambda item: item.rank_score, reverse=True)[:limit]

    def save_analysis(
        self, incident: IncidentCreate, analysis: IncidentAnalysis
    ) -> IncidentAnalysis:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO incidents
                (id, tenant_id, service, service_version, symptom,
                 idempotency_key, status, analysis)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s::JSONB)
                ON CONFLICT (tenant_id, idempotency_key)
                DO UPDATE SET idempotency_key=excluded.idempotency_key
                RETURNING id, analysis""",
                (
                    analysis.incident_id,
                    incident.tenant_id,
                    incident.service,
                    incident.service_version,
                    incident.symptom,
                    incident.idempotency_key,
                    analysis.status,
                    analysis.model_dump_json(),
                ),
            )
            raw_row = cursor.fetchone()
        assert raw_row is not None
        row = dict(raw_row)
        return IncidentAnalysis.model_validate(row["analysis"])

    def get_analysis(self, incident_id: UUID, tenant_id: str) -> IncidentAnalysis | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                "SELECT analysis FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
            raw_row = cursor.fetchone()
        if raw_row is None:
            return None
        row = dict(raw_row)
        return IncidentAnalysis.model_validate(row["analysis"])

    def get_incident(self, incident_id: UUID, tenant_id: str) -> IncidentCreate | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT tenant_id, service, service_version, symptom, idempotency_key
                FROM incidents WHERE id=%s AND tenant_id=%s""",
                (incident_id, tenant_id),
            )
            raw_row = cursor.fetchone()
        return IncidentCreate.model_validate(dict(raw_row)) if raw_row is not None else None

    def save_outcome_memory(self, memory: Memory) -> Memory:
        assert memory.source_incident_id is not None
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO memories
                (id, tenant_id, service, service_version, symptom, action, outcome,
                 outcome_score, confidence, valid, state, superseded_by, source_incident_id,
                 observed_by, reviewed_by, reviewed_at, embedding, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::VECTOR,%s)
                ON CONFLICT (source_incident_id) DO UPDATE
                SET source_incident_id=excluded.source_incident_id
                RETURNING id, tenant_id, service, service_version, symptom, action, outcome,
                 outcome_score, confidence, valid, state, superseded_by, source_incident_id,
                 observed_by, reviewed_by, reviewed_at, embedding::STRING AS embedding,
                 created_at""",
                (
                    memory.id,
                    memory.tenant_id,
                    memory.service,
                    memory.service_version,
                    memory.symptom,
                    memory.action,
                    memory.outcome,
                    memory.outcome_score,
                    memory.confidence,
                    memory.valid,
                    memory.state,
                    memory.superseded_by,
                    memory.source_incident_id,
                    memory.observed_by,
                    memory.reviewed_by,
                    memory.reviewed_at,
                    self._vector(memory.embedding),
                    memory.created_at,
                ),
            )
            raw_row = cursor.fetchone()
        assert raw_row is not None
        return self._memory(raw_row)

    def govern_memory(
        self, memory_id: UUID, request: MemoryGovernanceRequest
    ) -> Memory | None:
        columns = """id, tenant_id, service, service_version, symptom, action, outcome,
            outcome_score, confidence, valid, state, superseded_by, source_incident_id,
            observed_by, reviewed_by, reviewed_at, embedding::STRING AS embedding, created_at"""
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {columns} FROM memories WHERE id=%s AND tenant_id=%s FOR UPDATE",
                (memory_id, request.tenant_id),
            )
            raw_memory = cursor.fetchone()
            if raw_memory is None:
                return None
            memory = self._memory(raw_memory)
            candidates = [memory]
            if request.replacement_memory_id is not None:
                cursor.execute(
                    f"SELECT {columns} FROM memories WHERE id=%s AND tenant_id=%s",
                    (request.replacement_memory_id, request.tenant_id),
                )
                raw_replacement = cursor.fetchone()
                if raw_replacement is not None:
                    candidates.append(self._memory(raw_replacement))
            target = _governance_target(memory, request, candidates)
            reviewed_at = datetime.now(UTC)
            cursor.execute(
                """UPDATE memories SET state=%s, valid=%s, reviewed_by=%s, reviewed_at=%s,
                superseded_by=%s WHERE id=%s AND tenant_id=%s
                RETURNING """
                + columns,
                (
                    target,
                    target is MemoryState.ACTIVE,
                    request.actor_id,
                    reviewed_at,
                    request.replacement_memory_id,
                    memory_id,
                    request.tenant_id,
                ),
            )
            raw_updated = cursor.fetchone()
            assert raw_updated is not None
            event = MemoryEvent(
                memory_id=memory.id,
                tenant_id=memory.tenant_id,
                actor_id=request.actor_id,
                action=request.action,
                reason=request.reason,
                from_state=memory.state,
                to_state=target,
                created_at=reviewed_at,
            )
            cursor.execute(
                """INSERT INTO memory_events
                (id, memory_id, tenant_id, actor_id, action, reason, from_state, to_state,
                 created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    event.id,
                    event.memory_id,
                    event.tenant_id,
                    event.actor_id,
                    event.action,
                    event.reason,
                    event.from_state,
                    event.to_state,
                    event.created_at,
                ),
            )
        return self._memory(raw_updated)

    def record_approval(
        self, incident_id: UUID, tenant_id: str, actor_id: str, approved: bool, reason: str
    ) -> bool:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO approvals (incident_id, tenant_id, actor_id, approved, reason)
                SELECT id, tenant_id, %s, %s, %s FROM incidents WHERE id=%s AND tenant_id=%s
                ON CONFLICT (incident_id) DO NOTHING RETURNING incident_id""",
                (actor_id, approved, reason, incident_id, tenant_id),
            )
            return cursor.fetchone() is not None
