import math
from collections.abc import Iterable
from typing import Protocol
from uuid import UUID

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from recallops.domain import IncidentAnalysis, IncidentCreate, Memory, RetrievedMemory


def cosine_similarity(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    return dot / (left_norm * right_norm) if left_norm and right_norm else 0.0


def rank_memory(memory: Memory, similarity: float, service_version: str) -> RetrievedMemory:
    compatibility = 1.0 if memory.service_version == service_version else 0.2
    score = (
        0.55 * similarity
        + 0.25 * memory.outcome_score
        + 0.15 * compatibility
        + 0.05 * memory.confidence
    )
    return RetrievedMemory(
        memory=memory,
        semantic_similarity=max(-1.0, min(1.0, similarity)),
        compatibility=compatibility,
        rank_score=score,
    )


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
        self.approvals: set[tuple[str, UUID]] = set()

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
        )
        return sorted(candidates, key=lambda item: item.rank_score, reverse=True)[:limit]

    def save_analysis(
        self, incident: IncidentCreate, analysis: IncidentAnalysis
    ) -> IncidentAnalysis:
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

    def record_approval(
        self, incident_id: UUID, tenant_id: str, actor_id: str, approved: bool, reason: str
    ) -> bool:
        key = (tenant_id, incident_id)
        if key not in self.analyses or key in self.approvals:
            return False
        self.approvals.add(key)
        return True


class PostgresStore:
    def __init__(self, database_url: str) -> None:
        self._pool = ConnectionPool(
            database_url, min_size=1, max_size=10, kwargs={"row_factory": dict_row}
        )

    @staticmethod
    def _vector(values: list[float]) -> str:
        return "[" + ",".join(f"{value:.9g}" for value in values) + "]"

    def add_memory(self, memory: Memory) -> None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO memories
                (id, tenant_id, service, service_version, symptom, action, outcome,
                 outcome_score, confidence, valid, superseded_by, source_incident_id,
                 embedding, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::VECTOR,%s)
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
                    memory.superseded_by,
                    memory.source_incident_id,
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
                   outcome_score, confidence, valid, superseded_by, source_incident_id,
                   embedding::STRING AS embedding,
                   created_at, 1 - (embedding <=> %s::VECTOR) AS similarity
                   FROM memories
                   WHERE tenant_id = %s AND service = %s AND valid
                   ORDER BY embedding <=> %s::VECTOR LIMIT %s""",
                (vector, incident.tenant_id, incident.service, vector, limit * 3),
            )
            rows = cursor.fetchall()
        ranked = []
        for raw_row in rows:
            row = dict(raw_row)
            similarity = float(row.pop("similarity"))
            row["embedding"] = [float(value) for value in row["embedding"].strip("[]").split(",")]
            ranked.append(
                rank_memory(Memory.model_validate(row), similarity, incident.service_version)
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
                 outcome_score, confidence, valid, superseded_by, source_incident_id,
                 embedding, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::VECTOR,%s)
                ON CONFLICT (source_incident_id) DO UPDATE
                SET source_incident_id=excluded.source_incident_id
                RETURNING id, tenant_id, service, service_version, symptom, action, outcome,
                 outcome_score, confidence, valid, superseded_by, source_incident_id,
                 embedding::STRING AS embedding, created_at""",
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
                    memory.superseded_by,
                    memory.source_incident_id,
                    self._vector(memory.embedding),
                    memory.created_at,
                ),
            )
            raw_row = cursor.fetchone()
        assert raw_row is not None
        row = dict(raw_row)
        row["embedding"] = [float(value) for value in row["embedding"].strip("[]").split(",")]
        return Memory.model_validate(row)

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
