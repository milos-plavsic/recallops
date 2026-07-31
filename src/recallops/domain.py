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
    superseded_by: UUID | None = None
    embedding: list[float] = Field(min_length=1024, max_length=1024)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RetrievedMemory(BaseModel):
    memory: Memory
    semantic_similarity: float = Field(ge=-1, le=1)
    compatibility: float = Field(ge=0, le=1)
    rank_score: float


class ProposedAction(BaseModel):
    name: str
    command: str
    risk: ActionRisk
    rationale: str
    requires_approval: bool


class IncidentAnalysis(BaseModel):
    incident_id: UUID = Field(default_factory=uuid4)
    status: IncidentStatus = IncidentStatus.OPEN
    diagnosis: str
    confidence: float = Field(ge=0, le=1)
    memories: list[RetrievedMemory]
    proposed_action: ProposedAction
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApprovalRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80)
    approved: bool
    actor_id: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=3, max_length=1000)
