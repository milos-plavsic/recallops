import hashlib
from typing import Protocol
from uuid import UUID

import boto3
import structlog
from botocore.exceptions import BotoCoreError, ClientError

from recallops.archive import EvidenceArchive, NullEvidenceArchive
from recallops.domain import (
    ActionRisk,
    AgentToolTrace,
    ApprovalRequest,
    ExecutionAttestation,
    ExecutionAttestationRequest,
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    MemoryState,
    OutcomeObservation,
    ProposedAction,
    RetrievedMemory,
    ToolStatus,
)
from recallops.embedding import Embedder
from recallops.resilience import DependencyUnavailable, aws_client_config
from recallops.store import MemoryStore


class IncidentWorkflowError(ValueError):
    pass


def action_hash(command: str) -> str:
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def trace_input_digest(*values: str) -> str:
    canonical = "\x1f".join(values)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Reasoner(Protocol):
    def diagnosis(self, incident: IncidentCreate, evidence: str) -> str: ...


class DeterministicReasoner:
    def diagnosis(self, incident: IncidentCreate, evidence: str) -> str:
        return (
            f"{incident.service} is exhibiting {incident.symptom}. "
            f"Compatible successful incident memory: {evidence}"
        )


class BedrockReasoner:
    def __init__(
        self,
        region: str,
        model_id: str,
        connect_timeout: float = 2.0,
        read_timeout: float = 15.0,
        max_attempts: int = 3,
    ) -> None:
        self._client = boto3.client(
            "bedrock-runtime",
            region_name=region,
            config=aws_client_config(connect_timeout, read_timeout, max_attempts),
        )
        self._model_id = model_id

    def diagnosis(self, incident: IncidentCreate, evidence: str) -> str:
        try:
            response = self._client.converse(
                modelId=self._model_id,
                system=[
                    {
                        "text": (
                            "Diagnose only from supplied evidence. State uncertainty. "
                            "Never invent telemetry."
                        )
                    }
                ],
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "text": (
                                    f"Incident: {incident.model_dump_json()}\nEvidence: {evidence}"
                                )
                            }
                        ],
                    }
                ],
                inferenceConfig={"maxTokens": 300, "temperature": 0.0},
            )
            blocks = response["output"]["message"]["content"]
            diagnosis = "".join(block.get("text", "") for block in blocks).strip()
            if not diagnosis:
                raise ValueError("empty model response")
            return diagnosis
        except (BotoCoreError, ClientError, KeyError, TypeError, ValueError) as error:
            raise DependencyUnavailable("bedrock_reasoning") from error


class IncidentService:
    def __init__(
        self,
        store: MemoryStore,
        embedder: Embedder,
        reasoner: Reasoner,
        max_memories: int = 5,
        archive: EvidenceArchive | None = None,
        *,
        min_similarity: float = 0.55,
        min_confidence: float = 0.50,
        min_rank_score: float = 0.65,
        min_margin: float = 0.03,
        provider_max_attempts: int = 3,
        provider_timeout_seconds: float = 15,
    ) -> None:
        self._store = store
        self._embedder = embedder
        self._reasoner = reasoner
        self._max_memories = max_memories
        self._archive = archive or NullEvidenceArchive()
        self._min_similarity = min_similarity
        self._min_confidence = min_confidence
        self._min_rank_score = min_rank_score
        self._min_margin = min_margin
        self._provider_max_attempts = provider_max_attempts
        self._provider_timeout_seconds = provider_timeout_seconds

    def _abstention_reasons(self, memories: list[RetrievedMemory]) -> list[str]:
        if not memories:
            return ["no_governed_memory"]
        best = memories[0]
        reasons = []
        if best.semantic_similarity < self._min_similarity:
            reasons.append("similarity_below_threshold")
        if best.effective_confidence < self._min_confidence:
            reasons.append("evidence_confidence_below_threshold")
        if best.rank_score < self._min_rank_score:
            reasons.append("rank_score_below_threshold")
        if best.compatibility < 1.0:
            reasons.append("service_version_incompatible")
        if best.memory.outcome_score <= 0:
            reasons.append("outcome_not_positive")
        if len(memories) > 1 and best.rank_score - memories[1].rank_score < self._min_margin:
            reasons.append("top_candidates_ambiguous")
        return reasons

    def analyze(self, incident: IncidentCreate) -> IncidentAnalysis:
        degraded: list[str] = []
        trace: list[AgentToolTrace] = []
        embedding_input = f"{incident.service} {incident.symptom}"
        try:
            embedding = self._embedder.embed(embedding_input)
            trace.append(
                AgentToolTrace(
                    sequence=1,
                    tool="embed_incident",
                    status=ToolStatus.SUCCEEDED,
                    input_digest=trace_input_digest(embedding_input, self._embedder.space_id),
                    max_attempts=self._provider_max_attempts,
                    timeout_seconds=self._provider_timeout_seconds,
                    evidence_refs=[f"embedding-space:{self._embedder.space_id}"],
                )
            )
        except DependencyUnavailable as error:
            degraded.append(error.dependency)
            structlog.get_logger().warning("dependency_degraded", dependency=error.dependency)
            embedding = None
            trace.append(
                AgentToolTrace(
                    sequence=1,
                    tool="embed_incident",
                    status=ToolStatus.DEGRADED,
                    input_digest=trace_input_digest(embedding_input, self._embedder.space_id),
                    max_attempts=self._provider_max_attempts,
                    timeout_seconds=self._provider_timeout_seconds,
                    degraded_reason=error.dependency,
                )
            )
        memories = (
            self._store.find_memories(
                incident, embedding, self._embedder.space_id, self._max_memories
            )
            if embedding is not None
            else []
        )
        trace.append(
            AgentToolTrace(
                sequence=2,
                tool="retrieve_governed_memory",
                status=ToolStatus.SUCCEEDED if embedding is not None else ToolStatus.SKIPPED,
                input_digest=trace_input_digest(
                    incident.tenant_id,
                    incident.service,
                    incident.service_version,
                    self._embedder.space_id,
                ),
                max_attempts=1,
                evidence_refs=[f"memory:{item.memory.id}" for item in memories],
                degraded_reason=("embedding_unavailable" if embedding is None else None),
            )
        )
        abstention_reasons = self._abstention_reasons(memories)
        best = memories[0] if memories and not abstention_reasons else None
        evidence = best.memory.outcome if best else "No compatible historical memory was found."
        try:
            diagnosis = self._reasoner.diagnosis(incident, evidence)
            trace.append(
                AgentToolTrace(
                    sequence=3,
                    tool="reason_from_evidence",
                    status=ToolStatus.SUCCEEDED,
                    input_digest=trace_input_digest(incident.model_dump_json(), evidence),
                    max_attempts=self._provider_max_attempts,
                    timeout_seconds=self._provider_timeout_seconds,
                    evidence_refs=[f"memory:{best.memory.id}"] if best else [],
                )
            )
        except DependencyUnavailable as error:
            degraded.append(error.dependency)
            structlog.get_logger().warning("dependency_degraded", dependency=error.dependency)
            diagnosis = DeterministicReasoner().diagnosis(incident, evidence)
            trace.append(
                AgentToolTrace(
                    sequence=3,
                    tool="reason_from_evidence",
                    status=ToolStatus.DEGRADED,
                    input_digest=trace_input_digest(incident.model_dump_json(), evidence),
                    max_attempts=self._provider_max_attempts,
                    timeout_seconds=self._provider_timeout_seconds,
                    evidence_refs=[f"memory:{best.memory.id}"] if best else [],
                    degraded_reason=error.dependency,
                )
            )
        if best:
            proposed = ProposedAction(
                name="apply_prior_remediation",
                command=best.memory.action,
                risk=ActionRisk.MUTATING,
                rationale=f"Successful compatible memory {best.memory.id}",
                requires_approval=True,
                action_hash=action_hash(best.memory.action),
            )
            confidence = min(0.95, max(0.1, best.rank_score))
        else:
            proposed = ProposedAction(
                name="collect_diagnostics",
                command=f"inspect logs and metrics for {incident.service}",
                risk=ActionRisk.READ_ONLY,
                rationale="No sufficiently compatible successful remediation exists",
                requires_approval=False,
                action_hash=action_hash(f"inspect logs and metrics for {incident.service}"),
            )
            confidence = 0.25
        saved = self._store.save_analysis(
            incident,
            IncidentAnalysis(
                diagnosis=diagnosis,
                confidence=confidence,
                memories=memories,
                proposed_action=proposed,
                agent_trace=trace,
                retrieval_abstention_reasons=abstention_reasons,
                degraded_dependencies=degraded,
            ),
        )
        if not self._store.transactional_archive:
            try:
                self._archive.archive(incident, saved)
            except DependencyUnavailable as error:
                structlog.get_logger().error(
                    "evidence_archive_failed",
                    dependency=error.dependency,
                    incident_id=str(saved.incident_id),
                )
        return saved

    def decide_approval(self, incident_id: UUID, request: ApprovalRequest) -> bool:
        analysis = self._store.get_analysis(incident_id, request.tenant_id)
        if analysis is None:
            return False
        if not analysis.proposed_action.requires_approval:
            raise IncidentWorkflowError("read-only action does not require approval")
        return self._store.record_approval(
            incident_id,
            request.tenant_id,
            request.actor_id,
            request.approved,
            request.reason,
        )

    def attest_execution(
        self, incident_id: UUID, request: ExecutionAttestationRequest
    ) -> ExecutionAttestation | None:
        analysis = self._store.get_analysis(incident_id, request.tenant_id)
        if analysis is None:
            return None
        proposed = analysis.proposed_action
        if proposed.action_hash is None:
            raise IncidentWorkflowError("legacy analysis lacks an executable action fingerprint")
        if request.action_hash != proposed.action_hash or request.action_taken != proposed.command:
            raise IncidentWorkflowError("execution does not match the analyzed action")
        if proposed.requires_approval:
            approval = self._store.get_approval(incident_id, request.tenant_id)
            if approval is None or not approval.approved:
                raise IncidentWorkflowError("approved decision required before execution")
        return self._store.record_execution(
            ExecutionAttestation(incident_id=incident_id, **request.model_dump())
        )

    def learn_outcome(self, incident_id: UUID, observation: OutcomeObservation) -> Memory | None:
        incident = self._store.get_incident(incident_id, observation.tenant_id)
        if incident is None:
            return None
        execution = self._store.get_execution(incident_id, observation.tenant_id)
        if execution is None:
            raise IncidentWorkflowError("execution attestation required before observation")
        if observation.action_taken != execution.action_taken:
            raise IncidentWorkflowError("observation action does not match execution attestation")
        try:
            embedding = self._embedder.embed(f"{incident.service} {incident.symptom}")
        except DependencyUnavailable as error:
            structlog.get_logger().warning("dependency_degraded", dependency=error.dependency)
            raise
        memory = Memory(
            tenant_id=incident.tenant_id,
            service=incident.service,
            service_version=incident.service_version,
            symptom=incident.symptom,
            action=observation.action_taken,
            outcome=observation.outcome,
            outcome_score=observation.outcome_score,
            confidence=observation.confidence,
            valid=False,
            state=MemoryState.PENDING_REVIEW,
            source_incident_id=incident_id,
            observed_by=observation.actor_id,
            embedding_space=self._embedder.space_id,
            embedding=embedding,
        )
        return self._store.save_outcome_memory(memory)

    def govern_memory(self, memory_id: UUID, request: MemoryGovernanceRequest) -> Memory | None:
        return self._store.govern_memory(memory_id, request)
