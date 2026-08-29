import json
import math
import re
import threading
from collections.abc import Callable, Iterable, Mapping
from contextlib import nullcontext
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from uuid import UUID

from psycopg.errors import UniqueViolation
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from recallops.archive import evidence_payload
from recallops.db_retry import run_serializable
from recallops.domain import (
    ApprovalDecision,
    CompatibilityPolicy,
    ExecutionAttestation,
    GovernanceAction,
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryEvent,
    MemoryGovernanceRequest,
    MemoryOutcome,
    MemoryState,
    PolicyVerdict,
    PostcheckAssessment,
    PostcheckObservation,
    RetrievedMemory,
    ReviewReasonCode,
    SandboxExecution,
)


def cosine_similarity(left: list[float], right: list[float]) -> float:
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    return dot / (left_norm * right_norm) if left_norm and right_norm else 0.0


def memory_rank_score(
    similarity: float, outcome_score: float, compatibility: float, confidence: float
) -> float:
    return 0.55 * similarity + 0.25 * outcome_score + 0.15 * compatibility + 0.05 * confidence


_SEMANTIC_VERSION = re.compile(
    r"^[vV]?(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)"
    r"(?:\.(?P<patch>0|[1-9]\d*))?(?:[-+][0-9A-Za-z.-]+)?$"
)


def version_compatibility(
    memory_version: str,
    incident_version: str,
    policy: CompatibilityPolicy = CompatibilityPolicy.EXACT,
) -> float:
    """Return a conservative, deterministic version proximity score.

    Only an exact version is considered fully compatible by the service's safety
    gate. SemVer-like versions receive partial credit for ranking, while unknown
    version schemes retain the legacy low score. This deliberately does not turn
    version proximity into authorization to reuse a mutating action.
    """
    if memory_version == incident_version:
        return 1.0
    memory_match = _SEMANTIC_VERSION.fullmatch(memory_version)
    incident_match = _SEMANTIC_VERSION.fullmatch(incident_version)
    if memory_match is None or incident_match is None:
        return 0.2
    same_major = memory_match["major"] == incident_match["major"]
    same_minor = same_major and memory_match["minor"] == incident_match["minor"]
    if policy is CompatibilityPolicy.SEMVER_PATCH and same_minor:
        return 1.0
    if policy is CompatibilityPolicy.SEMVER_MINOR and same_major:
        return 1.0
    if not same_major:
        return 0.0
    if not same_minor:
        return 0.35
    return 0.8


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
    compatibility = version_compatibility(
        memory.service_version, service_version, memory.compatibility_policy
    )
    score = memory_rank_score(similarity, effective_outcome, compatibility, effective_confidence)
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


class _BoundConnectionPool:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def connection(self) -> Any:
        return nullcontext(self._connection)


def _governance_target(
    memory: Memory, request: MemoryGovernanceRequest, memories: Iterable[Memory]
) -> MemoryState:
    targets = {
        GovernanceAction.CERTIFY: MemoryState.ACTIVE,
        GovernanceAction.ACTIVATE: MemoryState.ACTIVE,
        GovernanceAction.QUARANTINE: MemoryState.QUARANTINED,
        GovernanceAction.REJECT: MemoryState.REJECTED,
        GovernanceAction.SUPERSEDE: MemoryState.SUPERSEDED,
        GovernanceAction.REVOKE: MemoryState.REVOKED,
        GovernanceAction.EXPIRE: MemoryState.EXPIRED,
    }
    allowed = {
        MemoryState.PENDING_REVIEW: {
            MemoryState.ACTIVE,
            MemoryState.QUARANTINED,
            MemoryState.REJECTED,
        },
        MemoryState.ACTIVE: {
            MemoryState.QUARANTINED,
            MemoryState.SUPERSEDED,
            MemoryState.REVOKED,
            MemoryState.EXPIRED,
        },
        MemoryState.QUARANTINED: {
            MemoryState.ACTIVE,
            MemoryState.REJECTED,
            MemoryState.REVOKED,
            MemoryState.EXPIRED,
        },
        MemoryState.REJECTED: set(),
        MemoryState.SUPERSEDED: set(),
        MemoryState.REVOKED: set(),
        MemoryState.EXPIRED: set(),
    }
    target = targets[request.action]
    if target not in allowed[memory.state]:
        raise MemoryGovernanceError(f"cannot transition {memory.state} to {target}")
    if (
        request.action is GovernanceAction.CERTIFY
        and memory.outcome_semantics is MemoryOutcome.INCONCLUSIVE
    ):
        raise MemoryGovernanceError("inconclusive evidence cannot be certified")
    if request.action is GovernanceAction.CERTIFY and (
        request.reason_code is not ReviewReasonCode.EVIDENCE_ACCEPTED
    ):
        raise MemoryGovernanceError("certification requires EVIDENCE_ACCEPTED")
    revocation_reasons = {
        ReviewReasonCode.NEW_CONTRADICTORY_EVIDENCE,
        ReviewReasonCode.POLICY_CHANGE,
        ReviewReasonCode.COMPATIBILITY_INVALIDATED,
        ReviewReasonCode.DATA_QUALITY,
        ReviewReasonCode.OTHER_BOUNDED,
    }
    if request.action is GovernanceAction.REVOKE and request.reason_code not in revocation_reasons:
        raise MemoryGovernanceError("invalid revocation reason code")
    if target is MemoryState.ACTIVE and memory.observed_by == request.actor_id:
        raise MemoryGovernanceError("independent reviewer required for activation")
    if request.reason_code is ReviewReasonCode.OTHER_BOUNDED and not request.reason.strip():
        raise MemoryGovernanceError("OTHER_BOUNDED requires a reviewer note")
    if target is MemoryState.SUPERSEDED:
        replacement = next(
            (
                candidate
                for candidate in memories
                if candidate.id == request.replacement_memory_id
                and candidate.tenant_id == memory.tenant_id
                and candidate.state is MemoryState.ACTIVE
                and candidate.valid
                and candidate.service == memory.service
                and version_compatibility(
                    candidate.service_version,
                    memory.service_version,
                    candidate.compatibility_policy,
                )
                == 1.0
                and candidate.outcome_semantics is not MemoryOutcome.INCONCLUSIVE
                and (
                    candidate.expires_at is None or candidate.expires_at > datetime.now(UTC)
                )
            ),
            None,
        )
        if replacement is None or replacement.id == memory.id:
            raise MemoryGovernanceError(
                "active same-tenant replacement memory required; replacement must be "
                "same-service, admissible, and conclusive"
            )
    elif request.replacement_memory_id is not None:
        raise MemoryGovernanceError("replacement memory is only valid for supersession")
    return target


class MemoryStore(Protocol):
    transactional_archive: bool

    def ready(self) -> bool: ...
    def add_memory(self, memory: Memory) -> None: ...
    def find_memories(
        self, incident: IncidentCreate, embedding: list[float], embedding_space: str, limit: int
    ) -> list[RetrievedMemory]: ...
    def save_analysis(
        self, incident: IncidentCreate, analysis: IncidentAnalysis
    ) -> IncidentAnalysis: ...
    def get_analysis(self, incident_id: UUID, tenant_id: str) -> IncidentAnalysis | None: ...
    def get_incident(self, incident_id: UUID, tenant_id: str) -> IncidentCreate | None: ...
    def get_memory(self, memory_id: UUID, tenant_id: str) -> Memory | None: ...
    def list_memories(self, tenant_id: str, service: str) -> list[Memory]: ...
    def save_outcome_memory(self, memory: Memory) -> Memory: ...
    def govern_memory(self, memory_id: UUID, request: MemoryGovernanceRequest) -> Memory | None: ...
    def record_approval(
        self,
        incident_id: UUID,
        tenant_id: str,
        actor_id: str,
        approved: bool,
        proposal_hash: str,
        reason: str,
    ) -> bool: ...
    def get_approval(self, incident_id: UUID, tenant_id: str) -> ApprovalDecision | None: ...
    def record_execution(self, execution: ExecutionAttestation) -> ExecutionAttestation: ...
    def get_execution(self, incident_id: UUID, tenant_id: str) -> ExecutionAttestation | None: ...
    def record_sandbox_execution(self, execution: SandboxExecution) -> SandboxExecution: ...
    def get_sandbox_execution(
        self, incident_id: UUID, tenant_id: str
    ) -> SandboxExecution | None: ...
    def record_postcheck(
        self, observation: PostcheckObservation, verdict: PolicyVerdict
    ) -> tuple[PostcheckObservation, PolicyVerdict]: ...
    def get_postcheck(
        self, incident_id: UUID, tenant_id: str
    ) -> tuple[PostcheckObservation, PolicyVerdict] | None: ...
    def record_postcheck_assessment(
        self, assessment: PostcheckAssessment
    ) -> PostcheckAssessment: ...
    def get_postcheck_assessment(
        self, incident_id: UUID, tenant_id: str
    ) -> PostcheckAssessment | None: ...


class InMemoryStore:
    transactional_archive = False

    def __init__(self, memories: Iterable[Memory] = ()) -> None:
        self.memories = list(memories)
        self.analyses: dict[tuple[str, UUID], IncidentAnalysis] = {}
        self.idempotency: dict[tuple[str, str], UUID] = {}
        self.incidents: dict[tuple[str, UUID], IncidentCreate] = {}
        self.outcome_memories: dict[tuple[str, UUID], Memory] = {}
        self.memory_events: list[MemoryEvent] = []
        self.approvals: dict[tuple[str, UUID], ApprovalDecision] = {}
        self.executions: dict[tuple[str, UUID], ExecutionAttestation] = {}
        self.sandbox_executions: dict[tuple[str, UUID], SandboxExecution] = {}
        self.postchecks: dict[
            tuple[str, UUID], tuple[PostcheckObservation, PolicyVerdict]
        ] = {}
        self.postcheck_assessments: dict[tuple[str, UUID], PostcheckAssessment] = {}
        self._lock = threading.RLock()

    def ready(self) -> bool:
        return True

    def add_memory(self, memory: Memory) -> None:
        self.memories.append(memory)

    def find_memories(
        self, incident: IncidentCreate, embedding: list[float], embedding_space: str, limit: int
    ) -> list[RetrievedMemory]:
        as_of = datetime.now(UTC)
        candidates = (
            rank_memory(
                memory,
                cosine_similarity(memory.embedding, embedding),
                incident.service_version,
                as_of=as_of,
            )
            for memory in self.memories
            if memory.tenant_id == incident.tenant_id
            and memory.service == incident.service
            and memory.embedding_space == embedding_space
            and memory.valid
            and memory.state is MemoryState.ACTIVE
            and memory.outcome_semantics is not MemoryOutcome.INCONCLUSIVE
            and (memory.expires_at is None or memory.expires_at > as_of)
            and memory.superseded_at is None
            and memory.revoked_at is None
        )
        return sorted(
            candidates,
            key=lambda item: (
                item.rank_score,
                item.semantic_similarity,
                item.memory.created_at,
                str(item.memory.id),
            ),
            reverse=True,
        )[:limit]

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

    def get_memory(self, memory_id: UUID, tenant_id: str) -> Memory | None:
        return next(
            (
                memory
                for memory in self.memories
                if memory.id == memory_id and memory.tenant_id == tenant_id
            ),
            None,
        )

    def list_memories(self, tenant_id: str, service: str) -> list[Memory]:
        return [
            memory
            for memory in self.memories
            if memory.tenant_id == tenant_id and memory.service == service
        ]

    def save_outcome_memory(self, memory: Memory) -> Memory:
        if memory.source_incident_id is None:
            raise ValueError("outcome memory requires a source incident")
        key = (memory.tenant_id, memory.source_incident_id)
        existing = self.outcome_memories.get(key)
        if existing is not None:
            return existing
        self.outcome_memories[key] = memory
        self.memories.append(memory)
        return memory

    def govern_memory(self, memory_id: UUID, request: MemoryGovernanceRequest) -> Memory | None:
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
        reviewed_at = datetime.now(UTC)
        updated = memory.model_copy(
            update={
                "state": target,
                "valid": target is MemoryState.ACTIVE,
                "reviewed_by": request.actor_id,
                "reviewed_at": reviewed_at,
                "superseded_by": request.replacement_memory_id,
                "governance_version": memory.governance_version + 1,
                "superseded_at": (
                    reviewed_at if target is MemoryState.SUPERSEDED else memory.superseded_at
                ),
                "revoked_at": (
                    reviewed_at if target is MemoryState.REVOKED else memory.revoked_at
                ),
                "expires_at": (
                    memory.expires_at or reviewed_at
                    if target is MemoryState.EXPIRED
                    else memory.expires_at
                ),
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
                reason_code=request.reason_code,
                memory_digest=cast(str, memory.memory_digest),
                from_state=memory.state,
                to_state=target,
            )
        )
        return updated

    def record_approval(
        self,
        incident_id: UUID,
        tenant_id: str,
        actor_id: str,
        approved: bool,
        proposal_hash: str,
        reason: str,
    ) -> bool:
        key = (tenant_id, incident_id)
        if key not in self.analyses or key in self.approvals:
            return False
        self.approvals[key] = ApprovalDecision(
            incident_id=incident_id,
            tenant_id=tenant_id,
            actor_id=actor_id,
            approved=approved,
            proposal_hash=proposal_hash,
            reason=reason,
        )
        return True

    def get_approval(self, incident_id: UUID, tenant_id: str) -> ApprovalDecision | None:
        return self.approvals.get((tenant_id, incident_id))

    def record_execution(self, execution: ExecutionAttestation) -> ExecutionAttestation:
        key = (execution.tenant_id, execution.incident_id)
        existing = self.executions.get(key)
        if existing is not None:
            if existing.action_hash != execution.action_hash:
                raise MemoryGovernanceError("incident already has a different execution")
            return existing
        self.executions[key] = execution
        return execution

    def get_execution(self, incident_id: UUID, tenant_id: str) -> ExecutionAttestation | None:
        return self.executions.get((tenant_id, incident_id))

    def record_sandbox_execution(self, execution: SandboxExecution) -> SandboxExecution:
        key = (execution.tenant_id, execution.incident_id)
        existing = self.sandbox_executions.get(key)
        if existing is not None:
            if (
                existing.proposal_hash != execution.proposal_hash
                or existing.idempotency_key != execution.idempotency_key
            ):
                raise MemoryGovernanceError("incident already has a different sandbox execution")
            return existing
        self.sandbox_executions[key] = execution
        return execution

    def get_sandbox_execution(
        self, incident_id: UUID, tenant_id: str
    ) -> SandboxExecution | None:
        return self.sandbox_executions.get((tenant_id, incident_id))

    def record_postcheck(
        self, observation: PostcheckObservation, verdict: PolicyVerdict
    ) -> tuple[PostcheckObservation, PolicyVerdict]:
        key = (observation.tenant_id, observation.incident_id)
        existing = self.postchecks.get(key)
        if existing is not None:
            if existing[0].observation_digest != observation.observation_digest:
                raise MemoryGovernanceError("incident already has a different postcheck")
            return existing
        if verdict.observation_digest != observation.observation_digest:
            raise MemoryGovernanceError("policy verdict is not bound to the observation")
        self.postchecks[key] = (observation, verdict)
        return observation, verdict

    def get_postcheck(
        self, incident_id: UUID, tenant_id: str
    ) -> tuple[PostcheckObservation, PolicyVerdict] | None:
        return self.postchecks.get((tenant_id, incident_id))

    def record_postcheck_assessment(
        self, assessment: PostcheckAssessment
    ) -> PostcheckAssessment:
        # Match the authoritative database key and retrieval contract: one assessment
        # per incident, with the observation binding validated independently.
        key = (assessment.tenant_id, assessment.incident_id)
        existing = self.postcheck_assessments.get(key)
        if existing is not None:
            if (
                existing.agent_subject != assessment.agent_subject
                or existing.classification != assessment.classification
                or existing.rationale != assessment.rationale
            ):
                raise MemoryGovernanceError("observation already has a different assessment")
            return existing
        self.postcheck_assessments[key] = assessment
        return assessment

    def get_postcheck_assessment(
        self, incident_id: UUID, tenant_id: str
    ) -> PostcheckAssessment | None:
        return self.postcheck_assessments.get((tenant_id, incident_id))


class PostgresStore:
    transactional_archive = True

    def __init__(
        self,
        database_url: str,
        connect_timeout_seconds: int = 5,
        statement_timeout_seconds: int = 15,
        retrieval_candidate_multiplier: int = 8,
    ) -> None:
        if retrieval_candidate_multiplier < 1:
            raise ValueError("retrieval_candidate_multiplier must be at least 1")
        self._retrieval_candidate_multiplier = retrieval_candidate_multiplier
        self._transaction_bound = False
        self._pool: Any = ConnectionPool(
            database_url,
            open=True,
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

    @property
    def pool(self) -> ConnectionPool[Any]:
        return cast(ConnectionPool[Any], self._pool)

    def _run_write[T](self, operation: Callable[[], T]) -> T:
        if getattr(self, "_transaction_bound", False):
            return operation()
        return run_serializable(operation)

    def atomic[T](self, operation: Callable[["PostgresStore", Any], T]) -> T:
        def transact_once() -> T:
            with self._pool.connection() as connection:
                bound = object.__new__(PostgresStore)
                bound.__dict__ = {**self.__dict__}
                bound._pool = _BoundConnectionPool(connection)
                bound._transaction_bound = True
                return operation(bound, connection)

        return run_serializable(transact_once)

    def ready(self) -> bool:
        try:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return cursor.fetchone() is not None
        except Exception:
            return False

    @staticmethod
    def _vector(values: list[float]) -> str:
        return "[" + ",".join(f"{value:.9g}" for value in values) + "]"

    @staticmethod
    def _memory(raw_row: object) -> Memory:
        row = dict(cast(Mapping[str, Any], raw_row))
        row["embedding"] = [float(value) for value in row["embedding"].strip("[]").split(",")]
        return Memory.model_validate(row)

    @staticmethod
    def _sandbox_execution(raw_row: object) -> SandboxExecution:
        row = dict(cast(Mapping[str, Any], raw_row))
        row["before"] = row.pop("before_metrics")
        row["after"] = row.pop("after_metrics")
        return SandboxExecution.model_validate(row)

    @staticmethod
    def _postcheck_observation(raw_row: object) -> PostcheckObservation:
        row = dict(cast(Mapping[str, Any], raw_row))
        row["before"] = row.pop("before_metrics")
        row["after"] = row.pop("after_metrics")
        return PostcheckObservation.model_validate(row)

    def add_memory(self, memory: Memory) -> None:
        def add_once() -> None:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(  # nosec B608  # nosemgrep
                    """INSERT INTO memories
                (id, tenant_id, service, service_version, compatibility_policy,
                 compatibility_policy_version, symptom, action, outcome,
                 outcome_score, confidence, valid, state,
                 superseded_by, source_incident_id,
                 observed_by, evidence_verification, evidence_refs,
                 observation_window_seconds, postconditions, reviewed_by, reviewed_at,
                 observation_digest, assessment_digest, verdict_digest, memory_digest,
                 governance_policy_version, governance_version, expires_at,
                 superseded_at, revoked_at,
                 embedding_space, embedding, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::JSONB,%s,
                        %s::JSONB,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::VECTOR,%s)
                ON CONFLICT (id) DO NOTHING""",
                    (
                        memory.id,
                        memory.tenant_id,
                        memory.service,
                        memory.service_version,
                        memory.compatibility_policy,
                        memory.compatibility_policy_version,
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
                        memory.evidence_verification,
                        json.dumps(memory.evidence_refs),
                        memory.observation_window_seconds,
                        json.dumps(memory.postconditions),
                        memory.reviewed_by,
                        memory.reviewed_at,
                        memory.observation_digest,
                        memory.assessment_digest,
                        memory.verdict_digest,
                        memory.memory_digest,
                        memory.governance_policy_version,
                        memory.governance_version,
                        memory.expires_at,
                        memory.superseded_at,
                        memory.revoked_at,
                        memory.embedding_space,
                        self._vector(memory.embedding),
                        memory.created_at,
                    ),
                )

        self._run_write(add_once)

    def find_memories(
        self, incident: IncidentCreate, embedding: list[float], embedding_space: str, limit: int
    ) -> list[RetrievedMemory]:
        if limit <= 0:
            return []
        vector = self._vector(embedding)
        candidate_limit = limit * self._retrieval_candidate_multiplier
        semantic_pool_limit = candidate_limit * 4
        columns = """id, tenant_id, service, service_version, compatibility_policy,
                   compatibility_policy_version, symptom, action, outcome,
                   outcome_score, outcome_semantics, confidence, valid, state,
                   superseded_by, source_incident_id,
                   observed_by, evidence_verification, evidence_refs,
                   observation_window_seconds, postconditions, reviewed_by, reviewed_at,
                   observation_digest, assessment_digest, verdict_digest, memory_digest,
                   governance_policy_version, governance_version, expires_at,
                   superseded_at, revoked_at,
                   embedding_space,
                   embedding::STRING AS embedding,
                   created_at, 1 - (embedding <=> %s::VECTOR) AS similarity"""
        predicates = """tenant_id = %s AND service = %s AND embedding_space = %s
                     AND valid AND state = 'active'
                     AND outcome_semantics != 'inconclusive'
                     AND (expires_at IS NULL OR expires_at > now())
                     AND superseded_at IS NULL AND revoked_at IS NULL"""
        with self._pool.connection() as connection, connection.cursor() as cursor:
            # Protect safe-candidate recall from a dense cluster of close failures or
            # obsolete versions. The exact-version-success lane is intentionally
            # unioned with the broad semantic lane before application reranking.
            cursor.execute(  # nosec B608  # nosemgrep
                f"""SELECT {columns} FROM memories WHERE {predicates}
                   AND service_version = %s AND outcome_score > 0
                   ORDER BY embedding <=> %s::VECTOR LIMIT %s""",  # nosec B608
                (
                    vector,
                    incident.tenant_id,
                    incident.service,
                    embedding_space,
                    incident.service_version,
                    vector,
                    candidate_limit,
                ),
            )
            compatible_success_rows = cursor.fetchall()
            cursor.execute(  # nosec B608  # nosemgrep
                f"""SELECT {columns} FROM memories WHERE {predicates}
                   AND compatibility_policy IN ('semver_patch', 'semver_minor')
                   AND outcome_score > 0
                   ORDER BY embedding <=> %s::VECTOR LIMIT %s""",  # nosec B608
                (
                    vector,
                    incident.tenant_id,
                    incident.service,
                    embedding_space,
                    vector,
                    candidate_limit,
                ),
            )
            policy_compatible_success_rows = cursor.fetchall()
            cursor.execute(  # nosec B608  # nosemgrep
                f"""WITH nearest AS MATERIALIZED (
                       SELECT id, embedding <=> %s::VECTOR AS distance
                       FROM memories@memories_embedding_v2
                       WHERE tenant_id = %s AND service = %s AND embedding_space = %s
                       ORDER BY embedding <=> %s::VECTOR
                       LIMIT %s
                   )
                   SELECT {columns} FROM memories JOIN nearest USING (id)
                   WHERE {predicates}
                   ORDER BY nearest.distance LIMIT %s""",  # nosec B608
                (
                    vector,
                    incident.tenant_id,
                    incident.service,
                    embedding_space,
                    vector,
                    semantic_pool_limit,
                    vector,
                    incident.tenant_id,
                    incident.service,
                    embedding_space,
                    candidate_limit,
                ),
            )
            semantic_rows = cursor.fetchall()
        ranked: list[RetrievedMemory] = []
        seen: set[UUID] = set()
        as_of = datetime.now(UTC)
        rows = [
            *compatible_success_rows,
            *policy_compatible_success_rows,
            *semantic_rows,
        ]
        for raw_row in rows:
            row = dict(raw_row)
            similarity = float(row.pop("similarity"))
            memory = self._memory(row)
            if memory.id in seen:
                continue
            seen.add(memory.id)
            ranked.append(rank_memory(memory, similarity, incident.service_version, as_of=as_of))
        return sorted(
            ranked,
            key=lambda item: (
                item.rank_score,
                item.semantic_similarity,
                item.memory.created_at,
                str(item.memory.id),
            ),
            reverse=True,
        )[:limit]

    def save_analysis(
        self, incident: IncidentCreate, analysis: IncidentAnalysis
    ) -> IncidentAnalysis:
        def save_once() -> IncidentAnalysis:
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
                if raw_row is None:
                    raise RuntimeError("incident upsert returned no row")
                row = dict(raw_row)
                saved = IncidentAnalysis.model_validate(row["analysis"])
                payload = evidence_payload(incident, saved)
                try:
                    # CockroachDB requires SELECT on the conflict target for
                    # INSERT ... ON CONFLICT. Keep the API role insert-only instead:
                    # a nested transaction creates a savepoint so an idempotent replay
                    # rolls back only the duplicate outbox insert, not the incident.
                    with connection.transaction():
                        cursor.execute(
                            """INSERT INTO evidence_outbox
                            (id, incident_id, tenant_id, service, service_version, payload)
                            VALUES (gen_random_uuid(),%s,%s,%s,%s,%s::JSONB)""",
                            (
                                saved.incident_id,
                                incident.tenant_id,
                                incident.service,
                                incident.service_version,
                                json.dumps(payload, separators=(",", ":")),
                            ),
                        )
                except UniqueViolation:
                    pass
            return saved

        return self._run_write(save_once)

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

    def get_memory(self, memory_id: UUID, tenant_id: str) -> Memory | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, tenant_id, service, service_version, compatibility_policy,
                 compatibility_policy_version, symptom, action, outcome,
                 outcome_score, confidence, valid, state,
                 superseded_by, source_incident_id,
                 observed_by, evidence_verification, evidence_refs,
                 observation_window_seconds, postconditions, reviewed_by, reviewed_at,
                 observation_digest, assessment_digest, verdict_digest, memory_digest,
                 governance_policy_version, governance_version, expires_at,
                 superseded_at, revoked_at,
                 embedding_space, embedding::STRING AS embedding, created_at
                 FROM memories WHERE id=%s AND tenant_id=%s""",
                (memory_id, tenant_id),
            )
            row = cursor.fetchone()
        return self._memory(row) if row is not None else None

    def list_memories(self, tenant_id: str, service: str) -> list[Memory]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, tenant_id, service, service_version, compatibility_policy,
                 compatibility_policy_version, symptom, action, outcome,
                 outcome_score, outcome_semantics, confidence, valid, state,
                 superseded_by, source_incident_id,
                 observed_by, evidence_verification, evidence_refs,
                 observation_window_seconds, postconditions, reviewed_by, reviewed_at,
                 observation_digest, assessment_digest, verdict_digest, memory_digest,
                 governance_policy_version, governance_version, expires_at,
                 superseded_at, revoked_at,
                 embedding_space, embedding::STRING AS embedding, created_at
                 FROM memories WHERE tenant_id=%s AND service=%s
                 ORDER BY created_at DESC, id DESC""",
                (tenant_id, service),
            )
            rows = cursor.fetchall()
        return [self._memory(row) for row in rows]

    def save_outcome_memory(self, memory: Memory) -> Memory:
        if memory.source_incident_id is None:
            raise ValueError("outcome memory requires a source incident")

        def save_once() -> Memory:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO memories
                (id, tenant_id, service, service_version, compatibility_policy,
                 compatibility_policy_version, symptom, action, outcome,
                 outcome_score, confidence, valid, state,
                 superseded_by, source_incident_id,
                 observed_by, evidence_verification, evidence_refs,
                 observation_window_seconds, postconditions, reviewed_by, reviewed_at,
                 observation_digest, assessment_digest, verdict_digest, memory_digest,
                 governance_policy_version, governance_version, expires_at,
                 superseded_at, revoked_at,
                 embedding_space, embedding, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::JSONB,%s,
                        %s::JSONB,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::VECTOR,%s)
                ON CONFLICT (source_incident_id) DO UPDATE
                SET source_incident_id=excluded.source_incident_id
                RETURNING id, tenant_id, service, service_version, compatibility_policy,
                 compatibility_policy_version, symptom, action, outcome,
                 outcome_score, outcome_semantics, confidence, valid, state,
                 superseded_by, source_incident_id,
                 observed_by, evidence_verification, evidence_refs,
                 observation_window_seconds, postconditions, reviewed_by, reviewed_at,
                 observation_digest, assessment_digest, verdict_digest, memory_digest,
                 governance_policy_version, governance_version, expires_at,
                 superseded_at, revoked_at,
                 embedding_space,
                 embedding::STRING AS embedding,
                 created_at""",
                    (
                        memory.id,
                        memory.tenant_id,
                        memory.service,
                        memory.service_version,
                        memory.compatibility_policy,
                        memory.compatibility_policy_version,
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
                        memory.evidence_verification,
                        json.dumps(memory.evidence_refs),
                        memory.observation_window_seconds,
                        json.dumps(memory.postconditions),
                        memory.reviewed_by,
                        memory.reviewed_at,
                        memory.observation_digest,
                        memory.assessment_digest,
                        memory.verdict_digest,
                        memory.memory_digest,
                        memory.governance_policy_version,
                        memory.governance_version,
                        memory.expires_at,
                        memory.superseded_at,
                        memory.revoked_at,
                        memory.embedding_space,
                        self._vector(memory.embedding),
                        memory.created_at,
                    ),
                )
                raw_row = cursor.fetchone()
            if raw_row is None:
                raise RuntimeError("outcome memory upsert returned no row")
            return self._memory(raw_row)

        return self._run_write(save_once)

    def govern_memory(self, memory_id: UUID, request: MemoryGovernanceRequest) -> Memory | None:
        return self._run_write(lambda: self._govern_memory_once(memory_id, request))

    def _govern_memory_once(
        self, memory_id: UUID, request: MemoryGovernanceRequest
    ) -> Memory | None:
        columns = """id, tenant_id, service, service_version, compatibility_policy,
            compatibility_policy_version, symptom, action, outcome,
            outcome_score, outcome_semantics, confidence, valid, state,
            superseded_by, source_incident_id,
            observed_by, evidence_verification, evidence_refs,
            observation_window_seconds, postconditions, reviewed_by, reviewed_at,
            observation_digest, assessment_digest, verdict_digest, memory_digest,
            governance_policy_version, governance_version, expires_at,
            superseded_at, revoked_at,
            embedding_space,
            embedding::STRING AS embedding, created_at"""
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(  # nosec B608  # nosemgrep
                f"SELECT {columns} FROM memories WHERE id=%s AND tenant_id=%s FOR UPDATE",  # nosec B608
                (memory_id, request.tenant_id),
            )
            raw_memory = cursor.fetchone()
            if raw_memory is None:
                return None
            memory = self._memory(raw_memory)
            candidates = [memory]
            if request.replacement_memory_id is not None:
                cursor.execute(  # nosec B608  # nosemgrep
                    f"SELECT {columns} FROM memories WHERE id=%s AND tenant_id=%s",  # nosec B608
                    (request.replacement_memory_id, request.tenant_id),
                )
                raw_replacement = cursor.fetchone()
                if raw_replacement is not None:
                    candidates.append(self._memory(raw_replacement))
            target = _governance_target(memory, request, candidates)
            reviewed_at = datetime.now(UTC)
            cursor.execute(  # nosec B608  # nosemgrep
                """UPDATE memories SET state=%s, valid=%s, reviewed_by=%s, reviewed_at=%s,
                superseded_by=%s, governance_version=governance_version+1,
                superseded_at=CASE WHEN %s='superseded' THEN %s ELSE superseded_at END,
                revoked_at=CASE WHEN %s='revoked' THEN %s ELSE revoked_at END,
                expires_at=CASE WHEN %s='expired' THEN COALESCE(expires_at,%s) ELSE expires_at END
                WHERE id=%s AND tenant_id=%s
                RETURNING """
                + columns,  # nosec B608
                (
                    target,
                    target is MemoryState.ACTIVE,
                    request.actor_id,
                    reviewed_at,
                    request.replacement_memory_id,
                    target,
                    reviewed_at,
                    target,
                    reviewed_at,
                    target,
                    reviewed_at,
                    memory_id,
                    request.tenant_id,
                ),
            )
            raw_updated = cursor.fetchone()
            if raw_updated is None:
                raise RuntimeError("memory governance update returned no row")
            event = MemoryEvent(
                memory_id=memory.id,
                tenant_id=memory.tenant_id,
                actor_id=request.actor_id,
                action=request.action,
                reason=request.reason,
                reason_code=request.reason_code,
                memory_digest=cast(str, memory.memory_digest),
                from_state=memory.state,
                to_state=target,
                created_at=reviewed_at,
            )
            cursor.execute(
                """INSERT INTO memory_events
                (id, memory_id, tenant_id, actor_id, action, reason, reason_code,
                 memory_digest, from_state, to_state, created_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    event.id,
                    event.memory_id,
                    event.tenant_id,
                    event.actor_id,
                    event.action,
                    event.reason,
                    event.reason_code,
                    event.memory_digest,
                    event.from_state,
                    event.to_state,
                    event.created_at,
                ),
            )
        return self._memory(raw_updated)

    def record_approval(
        self,
        incident_id: UUID,
        tenant_id: str,
        actor_id: str,
        approved: bool,
        proposal_hash: str,
        reason: str,
    ) -> bool:
        def record_once() -> bool:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO approvals
                (incident_id, tenant_id, actor_id, approved, proposal_hash, reason)
                SELECT id, tenant_id, %s, %s, %s, %s FROM incidents
                WHERE id=%s AND tenant_id=%s
                ON CONFLICT (incident_id) DO NOTHING RETURNING incident_id""",
                    (actor_id, approved, proposal_hash, reason, incident_id, tenant_id),
                )
                return cursor.fetchone() is not None

        return self._run_write(record_once)

    def get_approval(self, incident_id: UUID, tenant_id: str) -> ApprovalDecision | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT incident_id, tenant_id, actor_id, approved, proposal_hash,
                reason, created_at
                FROM approvals WHERE incident_id=%s AND tenant_id=%s""",
                (incident_id, tenant_id),
            )
            row = cursor.fetchone()
        return ApprovalDecision.model_validate(dict(row)) if row is not None else None

    def record_execution(self, execution: ExecutionAttestation) -> ExecutionAttestation:
        def record_once() -> ExecutionAttestation:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO execution_attestations
                (incident_id, tenant_id, actor_id, action_hash, action_taken, evidence_refs,
                 evidence_verification, created_at) VALUES (%s,%s,%s,%s,%s,%s::JSONB,%s,%s)
                ON CONFLICT (incident_id) DO UPDATE SET incident_id=excluded.incident_id
                RETURNING incident_id, tenant_id, actor_id, action_hash, action_taken,
                  evidence_refs, evidence_verification, created_at""",
                    (
                        execution.incident_id,
                        execution.tenant_id,
                        execution.actor_id,
                        execution.action_hash,
                        execution.action_taken,
                        execution.model_dump_json(include={"evidence_refs"}),
                        execution.evidence_verification,
                        execution.created_at,
                    ),
                )
                row = cursor.fetchone()
            if row is None:
                raise RuntimeError("execution attestation upsert returned no row")
            result = dict(row)
            evidence = result["evidence_refs"]
            result["evidence_refs"] = evidence.get("evidence_refs", evidence)
            recorded = ExecutionAttestation.model_validate(result)
            if recorded.action_hash != execution.action_hash:
                raise MemoryGovernanceError("incident already has a different execution")
            return recorded

        return self._run_write(record_once)

    def get_execution(self, incident_id: UUID, tenant_id: str) -> ExecutionAttestation | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT incident_id, tenant_id, actor_id, action_hash, action_taken,
                  evidence_refs, evidence_verification, created_at FROM execution_attestations
                WHERE incident_id=%s AND tenant_id=%s""",
                (incident_id, tenant_id),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        result = dict(row)
        evidence = result["evidence_refs"]
        result["evidence_refs"] = evidence.get("evidence_refs", evidence)
        return ExecutionAttestation.model_validate(result)

    def record_sandbox_execution(self, execution: SandboxExecution) -> SandboxExecution:
        def record_once() -> SandboxExecution:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO sandbox_executions
                    (id, incident_id, tenant_id, actor_id, proposal_hash, action_id,
                     simulator_version, idempotency_key, before_metrics, after_metrics,
                     execution_digest, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::JSONB,%s::JSONB,%s,%s)
                    ON CONFLICT (incident_id) DO NOTHING
                    RETURNING id, incident_id, tenant_id, actor_id, proposal_hash, action_id,
                     simulator_version, idempotency_key, before_metrics, after_metrics,
                     execution_digest, created_at""",
                    (
                        execution.id,
                        execution.incident_id,
                        execution.tenant_id,
                        execution.actor_id,
                        execution.proposal_hash,
                        execution.action_id,
                        execution.simulator_version,
                        execution.idempotency_key,
                        execution.before.model_dump_json(),
                        execution.after.model_dump_json(),
                        execution.execution_digest,
                        execution.created_at,
                    ),
                )
                row = cursor.fetchone()
                if row is None:
                    cursor.execute(
                        """SELECT id, incident_id, tenant_id, actor_id, proposal_hash,
                         action_id, simulator_version, idempotency_key, before_metrics,
                         after_metrics, execution_digest, created_at
                         FROM sandbox_executions WHERE incident_id=%s AND tenant_id=%s""",
                        (execution.incident_id, execution.tenant_id),
                    )
                    row = cursor.fetchone()
            if row is None:
                raise RuntimeError("sandbox execution upsert returned no row")
            recorded = self._sandbox_execution(row)
            if (
                recorded.proposal_hash != execution.proposal_hash
                or recorded.idempotency_key != execution.idempotency_key
            ):
                raise MemoryGovernanceError("incident already has a different sandbox execution")
            return recorded

        return self._run_write(record_once)

    def get_sandbox_execution(
        self, incident_id: UUID, tenant_id: str
    ) -> SandboxExecution | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, incident_id, tenant_id, actor_id, proposal_hash, action_id,
                 simulator_version, idempotency_key, before_metrics, after_metrics,
                 execution_digest, created_at FROM sandbox_executions
                 WHERE incident_id=%s AND tenant_id=%s""",
                (incident_id, tenant_id),
            )
            row = cursor.fetchone()
        return self._sandbox_execution(row) if row is not None else None

    def record_postcheck(
        self, observation: PostcheckObservation, verdict: PolicyVerdict
    ) -> tuple[PostcheckObservation, PolicyVerdict]:
        if verdict.observation_digest != observation.observation_digest:
            raise MemoryGovernanceError("policy verdict is not bound to the observation")

        def record_once() -> tuple[PostcheckObservation, PolicyVerdict]:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO postcheck_observations
                    (id, execution_id, incident_id, tenant_id, proposal_hash, execution_digest,
                     source, observation_window_seconds, before_metrics, after_metrics,
                     observation_digest, observed_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s::JSONB,%s::JSONB,%s,%s)
                    ON CONFLICT (incident_id) DO NOTHING
                    RETURNING id, execution_id, incident_id, tenant_id, proposal_hash,
                     execution_digest, source, observation_window_seconds, before_metrics,
                     after_metrics, observation_digest, observed_at""",
                    (
                        observation.id,
                        observation.execution_id,
                        observation.incident_id,
                        observation.tenant_id,
                        observation.proposal_hash,
                        observation.execution_digest,
                        observation.source,
                        observation.observation_window_seconds,
                        observation.before.model_dump_json(),
                        observation.after.model_dump_json(),
                        observation.observation_digest,
                        observation.observed_at,
                    ),
                )
                observation_row = cursor.fetchone()
                if observation_row is None:
                    cursor.execute(
                        """SELECT id, execution_id, incident_id, tenant_id, proposal_hash,
                         execution_digest, source, observation_window_seconds, before_metrics,
                         after_metrics, observation_digest, observed_at
                         FROM postcheck_observations
                         WHERE incident_id=%s AND tenant_id=%s""",
                        (observation.incident_id, observation.tenant_id),
                    )
                    observation_row = cursor.fetchone()
                if observation_row is None:
                    raise RuntimeError("postcheck observation upsert returned no row")
                recorded_observation = self._postcheck_observation(observation_row)
                if recorded_observation.observation_digest != observation.observation_digest:
                    raise MemoryGovernanceError("incident already has a different postcheck")
                cursor.execute(
                    """INSERT INTO postcheck_policy_verdicts
                    (observation_id, incident_id, tenant_id, classification, policy_version,
                     checks_passed, checks_failed, observation_digest, computed_at)
                    VALUES (%s,%s,%s,%s,%s,%s::JSONB,%s::JSONB,%s,%s)
                    ON CONFLICT (observation_id) DO NOTHING
                    RETURNING classification, policy_version, checks_passed, checks_failed,
                     observation_digest, computed_at""",
                    (
                        recorded_observation.id,
                        recorded_observation.incident_id,
                        recorded_observation.tenant_id,
                        verdict.classification,
                        verdict.policy_version,
                        json.dumps(verdict.checks_passed),
                        json.dumps(verdict.checks_failed),
                        verdict.observation_digest,
                        verdict.computed_at,
                    ),
                )
                verdict_row = cursor.fetchone()
                if verdict_row is None:
                    cursor.execute(
                        """SELECT classification, policy_version, checks_passed, checks_failed,
                         observation_digest, computed_at FROM postcheck_policy_verdicts
                         WHERE observation_id=%s AND tenant_id=%s""",
                        (recorded_observation.id, recorded_observation.tenant_id),
                    )
                    verdict_row = cursor.fetchone()
            if verdict_row is None:
                raise RuntimeError("postcheck verdict upsert returned no row")
            recorded_verdict = PolicyVerdict.model_validate(dict(verdict_row))
            if recorded_verdict.observation_digest != verdict.observation_digest:
                raise MemoryGovernanceError("observation already has a different policy verdict")
            return recorded_observation, recorded_verdict

        return self._run_write(record_once)

    def get_postcheck(
        self, incident_id: UUID, tenant_id: str
    ) -> tuple[PostcheckObservation, PolicyVerdict] | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT o.id, o.execution_id, o.incident_id, o.tenant_id,
                 o.proposal_hash, o.execution_digest, o.source,
                 o.observation_window_seconds, o.before_metrics, o.after_metrics,
                 o.observation_digest, o.observed_at, v.classification, v.policy_version,
                 v.checks_passed, v.checks_failed, v.computed_at
                 FROM postcheck_observations AS o
                 JOIN postcheck_policy_verdicts AS v ON v.observation_id=o.id
                 WHERE o.incident_id=%s AND o.tenant_id=%s""",
                (incident_id, tenant_id),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        values = dict(row)
        observation = self._postcheck_observation(values)
        verdict = PolicyVerdict.model_validate(values)
        return observation, verdict

    def record_postcheck_assessment(
        self, assessment: PostcheckAssessment
    ) -> PostcheckAssessment:
        def record_once() -> PostcheckAssessment:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO postcheck_assessments
                    (id, observation_id, incident_id, tenant_id, agent_subject,
                     classification, rationale, observation_digest, created_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT (observation_id) DO NOTHING
                    RETURNING id, observation_id, incident_id, tenant_id, agent_subject,
                     classification, rationale, observation_digest, created_at""",
                    (
                        assessment.id,
                        assessment.observation_id,
                        assessment.incident_id,
                        assessment.tenant_id,
                        assessment.agent_subject,
                        assessment.classification,
                        assessment.rationale,
                        assessment.observation_digest,
                        assessment.created_at,
                    ),
                )
                row = cursor.fetchone()
                if row is None:
                    cursor.execute(
                        """SELECT id, observation_id, incident_id, tenant_id, agent_subject,
                         classification, rationale, observation_digest, created_at
                         FROM postcheck_assessments
                         WHERE observation_id=%s AND tenant_id=%s""",
                        (assessment.observation_id, assessment.tenant_id),
                    )
                    row = cursor.fetchone()
            if row is None:
                raise RuntimeError("postcheck assessment upsert returned no row")
            recorded = PostcheckAssessment.model_validate(dict(row))
            if (
                recorded.agent_subject != assessment.agent_subject
                or recorded.classification != assessment.classification
                or recorded.rationale != assessment.rationale
            ):
                raise MemoryGovernanceError("observation already has a different assessment")
            return recorded

        return self._run_write(record_once)

    def get_postcheck_assessment(
        self, incident_id: UUID, tenant_id: str
    ) -> PostcheckAssessment | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT id, observation_id, incident_id, tenant_id, agent_subject,
                 classification, rationale, observation_digest, created_at
                 FROM postcheck_assessments WHERE incident_id=%s AND tenant_id=%s""",
                (incident_id, tenant_id),
            )
            row = cursor.fetchone()
        return PostcheckAssessment.model_validate(dict(row)) if row is not None else None
