from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ActionRisk(StrEnum):
    READ_ONLY = "read_only"
    MUTATING = "mutating"


class IncidentStatus(StrEnum):
    OPEN = "open"
    MITIGATED = "mitigated"


class MemoryState(StrEnum):
    PENDING_REVIEW = "pending_review"
    ACTIVE = "active"
    QUARANTINED = "quarantined"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


class GovernanceAction(StrEnum):
    ACTIVATE = "activate"
    QUARANTINE = "quarantine"
    SUPERSEDE = "supersede"
    REVOKE = "revoke"


class IncidentCreate(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    service: str = Field(min_length=1, max_length=120)
    service_version: str = Field(min_length=1, max_length=80)
    symptom: str = Field(min_length=3, max_length=4000)
    idempotency_key: str = Field(min_length=8, max_length=200)


class Memory(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    tenant_id: str
    service: str
    service_version: str
    symptom: str
    action: str
    outcome: str
    outcome_score: float = Field(ge=-1, le=1)
    confidence: float = Field(ge=0, le=1)
    valid: bool = True
    state: MemoryState = MemoryState.ACTIVE
    superseded_by: UUID | None = None
    source_incident_id: UUID | None = None
    observed_by: str | None = None
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    embedding_space: str = Field(
        default="deterministic:sha256-feature-hash-1024:v1", min_length=3, max_length=300
    )
    embedding: list[float] = Field(min_length=1024, max_length=1024)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RetrievedMemory(BaseModel):
    memory: Memory
    semantic_similarity: float = Field(ge=-1, le=1)
    compatibility: float = Field(ge=0, le=1)
    freshness: float = Field(ge=0, le=1)
    effective_confidence: float = Field(ge=0, le=1)
    rank_score: float


class ProposedAction(BaseModel):
    name: str
    command: str
    risk: ActionRisk
    rationale: str
    requires_approval: bool
    action_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class IncidentAnalysis(BaseModel):
    incident_id: UUID = Field(default_factory=uuid4)
    status: IncidentStatus = IncidentStatus.OPEN
    diagnosis: str
    confidence: float = Field(ge=0, le=1)
    memories: list[RetrievedMemory]
    proposed_action: ProposedAction
    retrieval_abstention_reasons: list[str] = Field(default_factory=list)
    degraded_dependencies: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApprovalRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80)
    approved: bool
    actor_id: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=3, max_length=1000)


class ApprovalDecision(ApprovalRequest):
    incident_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionAttestationRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    actor_id: str = Field(min_length=1, max_length=120)
    action_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    action_taken: str = Field(min_length=3, max_length=2000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)


class ExecutionAttestation(ExecutionAttestationRequest):
    incident_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OutcomeObservation(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    action_taken: str = Field(min_length=3, max_length=2000)
    outcome: str = Field(min_length=3, max_length=4000)
    outcome_score: float = Field(ge=-1, le=1)
    confidence: float = Field(ge=0, le=1)
    actor_id: str = Field(min_length=1, max_length=120)


class MemoryGovernanceRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    actor_id: str = Field(min_length=1, max_length=120)
    action: GovernanceAction
    reason: str = Field(min_length=3, max_length=1000)
    replacement_memory_id: UUID | None = None


class MemoryEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    memory_id: UUID
    tenant_id: str
    actor_id: str
    action: GovernanceAction
    reason: str
    from_state: MemoryState
    to_state: MemoryState
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
