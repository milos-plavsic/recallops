import hmac
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from recallops.canonical import content_digest


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
    REJECTED = "rejected"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"
    EXPIRED = "expired"


class GovernanceAction(StrEnum):
    CERTIFY = "certify"
    ACTIVATE = "activate"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    SUPERSEDE = "supersede"
    REVOKE = "revoke"
    EXPIRE = "expire"


class MemoryOutcome(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    INCONCLUSIVE = "inconclusive"


class ReviewReasonCode(StrEnum):
    EVIDENCE_ACCEPTED = "EVIDENCE_ACCEPTED"
    NEEDS_INVESTIGATION = "NEEDS_INVESTIGATION"
    INVALID_BINDING = "INVALID_BINDING"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    POLICY_CONFLICT = "POLICY_CONFLICT"
    NEW_CONTRADICTORY_EVIDENCE = "NEW_CONTRADICTORY_EVIDENCE"
    POLICY_CHANGE = "POLICY_CHANGE"
    COMPATIBILITY_INVALIDATED = "COMPATIBILITY_INVALIDATED"
    DATA_QUALITY = "DATA_QUALITY"
    OTHER_BOUNDED = "OTHER_BOUNDED"


class HandoffPurpose(StrEnum):
    INITIAL_REVIEW = "initial_review"
    REVOCATION = "revocation"


class ReviewerDecision(StrEnum):
    CERTIFY = "certify"
    QUARANTINE = "quarantine"
    REJECT = "reject"


class ToolStatus(StrEnum):
    SUCCEEDED = "succeeded"
    DEGRADED = "degraded"
    SKIPPED = "skipped"


class EvidenceVerification(StrEnum):
    MANUAL_ATTESTATION = "manual_attestation"
    SYSTEM_OBSERVED = "system_observed"
    EXTERNALLY_VERIFIED = "externally_verified"


class CandidateDisposition(StrEnum):
    SELECTED = "selected"
    ELIGIBLE_NOT_SELECTED = "eligible_not_selected"
    REJECTED = "rejected"


class PostcheckClassification(StrEnum):
    RECOVERED = "recovered"
    NOT_RECOVERED = "not_recovered"
    INCONCLUSIVE = "inconclusive"


class CompatibilityPolicy(StrEnum):
    EXACT = "exact"
    SEMVER_PATCH = "semver_patch"
    SEMVER_MINOR = "semver_minor"


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
    compatibility_policy: CompatibilityPolicy = CompatibilityPolicy.EXACT
    compatibility_policy_version: str = Field(default="semver-v1", min_length=3, max_length=80)
    symptom: str
    action: str
    outcome: str
    outcome_score: float = Field(ge=-1, le=1)
    outcome_semantics: MemoryOutcome | None = None
    confidence: float = Field(ge=0, le=1)
    valid: bool = True
    state: MemoryState = MemoryState.ACTIVE
    superseded_by: UUID | None = None
    source_incident_id: UUID | None = None
    observed_by: str | None = None
    evidence_verification: EvidenceVerification = EvidenceVerification.MANUAL_ATTESTATION
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    observation_window_seconds: int | None = Field(default=None, ge=1, le=2_592_000)
    postconditions: list[str] = Field(default_factory=list, max_length=20)
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    observation_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    assessment_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    verdict_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    memory_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    governance_policy_version: str = Field(
        default="memory-governance-v1", min_length=3, max_length=80
    )
    governance_version: int = Field(default=1, ge=1)
    expires_at: datetime | None = None
    superseded_at: datetime | None = None
    revoked_at: datetime | None = None
    embedding_space: str = Field(
        default="deterministic:sha256-feature-hash-1024:v1", min_length=3, max_length=300
    )
    embedding: list[float] = Field(min_length=1024, max_length=1024)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def derive_policy_fields(self) -> "Memory":
        derived_outcome = (
            MemoryOutcome.POSITIVE
            if self.outcome_score > 0
            else MemoryOutcome.NEGATIVE
            if self.outcome_score < 0
            else MemoryOutcome.INCONCLUSIVE
        )
        if self.outcome_semantics is not None and self.outcome_semantics is not derived_outcome:
            raise ValueError("outcome semantics must match the policy-defined outcome score")
        self.outcome_semantics = derived_outcome
        expected_digest = content_digest(
            "recallops-memory-v1",
            {
                "source_incident_id": (
                    str(self.source_incident_id) if self.source_incident_id else None
                ),
                "service": self.service,
                "service_version": self.service_version,
                "action": self.action,
                "observation_digest": self.observation_digest,
                "assessment_digest": self.assessment_digest,
                "verdict_digest": self.verdict_digest,
                "outcome_semantics": self.outcome_semantics.value,
                "outcome_score": self.outcome_score,
                "compatibility_policy": self.compatibility_policy.value,
                "compatibility_policy_version": self.compatibility_policy_version,
                "governance_policy_version": self.governance_policy_version,
                "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            },
        )
        if self.memory_digest is None:
            self.memory_digest = expected_digest
        elif self.governance_policy_version == "memory-governance-v1" and not hmac.compare_digest(
            self.memory_digest, expected_digest
        ):
            raise ValueError("memory digest does not match immutable evidence")
        return self


class RetrievedMemory(BaseModel):
    memory: Memory
    semantic_similarity: float = Field(ge=-1, le=1)
    compatibility: float = Field(ge=0, le=1)
    freshness: float = Field(ge=0, le=1)
    effective_confidence: float = Field(ge=0, le=1)
    rank_score: float


class CandidateDecision(BaseModel):
    memory_id: UUID
    disposition: CandidateDisposition
    reasons: list[str] = Field(default_factory=list, max_length=20)
    rank_score: float


class AgentPlanStep(BaseModel):
    sequence: int = Field(ge=1)
    objective: str = Field(min_length=3, max_length=300)
    tool: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9_]+$")
    risk: ActionRisk = ActionRisk.READ_ONLY
    stop_condition: str = Field(min_length=3, max_length=300)


class ProposedAction(BaseModel):
    name: str
    command: str
    risk: ActionRisk
    rationale: str
    requires_approval: bool
    action_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class AgentToolTrace(BaseModel):
    sequence: int = Field(ge=1)
    tool: str = Field(min_length=3, max_length=80, pattern=r"^[a-z0-9_]+$")
    risk: ActionRisk = ActionRisk.READ_ONLY
    status: ToolStatus
    input_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    max_attempts: int = Field(ge=1, le=10)
    timeout_seconds: float | None = Field(default=None, gt=0, le=120)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    degraded_reason: str | None = Field(default=None, min_length=3, max_length=120)


class IncidentAnalysis(BaseModel):
    incident_id: UUID = Field(default_factory=uuid4)
    status: IncidentStatus = IncidentStatus.OPEN
    diagnosis: str
    confidence: float = Field(ge=0, le=1)
    memories: list[RetrievedMemory]
    proposed_action: ProposedAction
    agent_trace: list[AgentToolTrace] = Field(default_factory=list, max_length=20)
    plan: list[AgentPlanStep] = Field(default_factory=list, max_length=10)
    candidate_decisions: list[CandidateDecision] = Field(default_factory=list, max_length=100)
    retrieval_abstention_reasons: list[str] = Field(default_factory=list)
    degraded_dependencies: list[str] = Field(default_factory=list)
    retrieval_policy_version: str = Field(default="outcome-governance-v2", max_length=80)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApprovalRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80)
    approved: bool
    actor_id: str = Field(min_length=1, max_length=120)
    proposal_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason: str = Field(min_length=3, max_length=1000)


class ApprovalDecision(ApprovalRequest):
    incident_id: UUID
    proposal_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ExecutionAttestationRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    actor_id: str = Field(min_length=1, max_length=120)
    action_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    action_taken: str = Field(min_length=3, max_length=2000)
    evidence_refs: list[str] = Field(min_length=1, max_length=20)
    evidence_verification: EvidenceVerification = EvidenceVerification.MANUAL_ATTESTATION


class ExecutionAttestation(ExecutionAttestationRequest):
    incident_id: UUID
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SandboxExecutionRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    actor_id: str = Field(min_length=1, max_length=120)
    proposal_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    idempotency_key: str = Field(min_length=8, max_length=200)


class PostcheckRetryRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    actor_id: str = Field(min_length=1, max_length=120)


class SandboxMetrics(BaseModel):
    worker_concurrency: int = Field(ge=1, le=1024)
    saturated_connections: int = Field(ge=0, le=100_000)
    latency_p95_ms: int = Field(ge=0, le=120_000)
    error_rate: float = Field(ge=0, le=1)


class SandboxExecution(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    tenant_id: str
    actor_id: str
    proposal_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    action_id: str = Field(pattern=r"^[a-z0-9_.-]+$", max_length=120)
    simulator_version: str = Field(min_length=3, max_length=80)
    idempotency_key: str = Field(min_length=8, max_length=200)
    before: SandboxMetrics
    after: SandboxMetrics
    execution_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PolicyVerdict(BaseModel):
    classification: PostcheckClassification
    policy_version: str = Field(min_length=3, max_length=80)
    checks_passed: list[str] = Field(default_factory=list, max_length=20)
    checks_failed: list[str] = Field(default_factory=list, max_length=20)
    observation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    computed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PostcheckObservation(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    execution_id: UUID
    incident_id: UUID
    tenant_id: str
    proposal_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    execution_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: str = Field(min_length=3, max_length=120)
    observation_window_seconds: int = Field(ge=1, le=3600)
    before: SandboxMetrics
    after: SandboxMetrics
    observation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PostcheckAssessmentRequest(BaseModel):
    observation_id: UUID
    classification: PostcheckClassification
    rationale: str = Field(min_length=3, max_length=1000)


class PostcheckAssessment(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    observation_id: UUID
    incident_id: UUID
    tenant_id: str
    agent_subject: str = Field(min_length=1, max_length=200)
    classification: PostcheckClassification
    rationale: str = Field(min_length=3, max_length=1000)
    observation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class OutcomeObservation(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    action_taken: str = Field(min_length=3, max_length=2000)
    outcome: str = Field(min_length=3, max_length=4000)
    outcome_score: float = Field(ge=-1, le=1)
    confidence: float = Field(ge=0, le=1)
    actor_id: str = Field(min_length=1, max_length=120)
    evidence_verification: EvidenceVerification = EvidenceVerification.MANUAL_ATTESTATION
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    observation_window_seconds: int | None = Field(default=None, ge=1, le=2_592_000)
    postconditions: list[str] = Field(default_factory=list, max_length=20)


class MemoryGovernanceRequest(BaseModel):
    tenant_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    actor_id: str = Field(min_length=1, max_length=120)
    action: GovernanceAction
    reason: str = Field(min_length=3, max_length=1000)
    reason_code: ReviewReasonCode = ReviewReasonCode.OTHER_BOUNDED
    replacement_memory_id: UUID | None = None


class ReviewerHandoffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    purpose: HandoffPurpose
    memory_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReviewerDispositionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: ReviewerDecision
    memory_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason_code: ReviewReasonCode
    note: str = Field(default="", max_length=280)

    @model_validator(mode="after")
    def validate_decision_reason(self) -> "ReviewerDispositionRequest":
        allowed = {
            ReviewerDecision.CERTIFY: {ReviewReasonCode.EVIDENCE_ACCEPTED},
            ReviewerDecision.QUARANTINE: {
                ReviewReasonCode.NEEDS_INVESTIGATION,
                ReviewReasonCode.INSUFFICIENT_EVIDENCE,
                ReviewReasonCode.POLICY_CONFLICT,
                ReviewReasonCode.OTHER_BOUNDED,
            },
            ReviewerDecision.REJECT: {
                ReviewReasonCode.INVALID_BINDING,
                ReviewReasonCode.INSUFFICIENT_EVIDENCE,
                ReviewReasonCode.POLICY_CONFLICT,
                ReviewReasonCode.OTHER_BOUNDED,
            },
        }
        if self.reason_code not in allowed[self.decision]:
            raise ValueError("reason code is not valid for this reviewer decision")
        if self.reason_code is ReviewReasonCode.OTHER_BOUNDED and not self.note.strip():
            raise ValueError("OTHER_BOUNDED requires a reviewer note")
        return self


class ReviewerRevocationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    memory_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    reason_code: ReviewReasonCode
    note: str = Field(default="", max_length=280)

    @model_validator(mode="after")
    def validate_revocation_reason(self) -> "ReviewerRevocationRequest":
        allowed = {
            ReviewReasonCode.NEW_CONTRADICTORY_EVIDENCE,
            ReviewReasonCode.POLICY_CHANGE,
            ReviewReasonCode.COMPATIBILITY_INVALIDATED,
            ReviewReasonCode.DATA_QUALITY,
            ReviewReasonCode.OTHER_BOUNDED,
        }
        if self.reason_code not in allowed:
            raise ValueError("reason code is not valid for revocation")
        if self.reason_code is ReviewReasonCode.OTHER_BOUNDED and not self.note.strip():
            raise ValueError("OTHER_BOUNDED requires a reviewer note")
        return self


class RecurrenceView(BaseModel):
    scenario_id: str = "checkout-latency-43"
    service: str
    service_version: str
    symptom: str
    baseline_memory_id: UUID | None
    baseline_recommendation: str
    governed_memory_id: UUID | None
    governed_recommendation: str
    eligible_memory_ids: list[UUID]
    negative_warning_memory_ids: list[UUID]
    compatibility_policy_version: str


class MemoryEvent(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    memory_id: UUID
    tenant_id: str
    actor_id: str
    action: GovernanceAction
    reason: str
    reason_code: ReviewReasonCode = ReviewReasonCode.OTHER_BOUNDED
    memory_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    from_state: MemoryState
    to_state: MemoryState
    workflow_epoch: int | None = Field(default=None, ge=1)
    run_id: UUID | None = None
    authority_event_id: UUID | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
