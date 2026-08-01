from typing import Protocol
from uuid import UUID

import boto3

from recallops.archive import EvidenceArchive, NullEvidenceArchive
from recallops.domain import (
    ActionRisk,
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    MemoryState,
    OutcomeObservation,
    ProposedAction,
)
from recallops.embedding import Embedder
from recallops.store import MemoryStore


class Reasoner(Protocol):
    def diagnosis(self, incident: IncidentCreate, evidence: str) -> str: ...


class DeterministicReasoner:
    def diagnosis(self, incident: IncidentCreate, evidence: str) -> str:
        return (
            f"{incident.service} is exhibiting {incident.symptom}. "
            f"Compatible successful incident memory: {evidence}"
        )


class BedrockReasoner:
    def __init__(self, region: str, model_id: str) -> None:
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def diagnosis(self, incident: IncidentCreate, evidence: str) -> str:
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
                        {"text": f"Incident: {incident.model_dump_json()}\nEvidence: {evidence}"}
                    ],
                }
            ],
            inferenceConfig={"maxTokens": 300, "temperature": 0.0},
        )
        blocks = response["output"]["message"]["content"]
        return "".join(block.get("text", "") for block in blocks).strip()


class IncidentService:
    def __init__(
        self,
        store: MemoryStore,
        embedder: Embedder,
        reasoner: Reasoner,
        max_memories: int = 5,
        archive: EvidenceArchive | None = None,
    ) -> None:
        self._store = store
        self._embedder = embedder
        self._reasoner = reasoner
        self._max_memories = max_memories
        self._archive = archive or NullEvidenceArchive()

    def analyze(self, incident: IncidentCreate) -> IncidentAnalysis:
        embedding = self._embedder.embed(f"{incident.service} {incident.symptom}")
        memories = self._store.find_memories(incident, embedding, self._max_memories)
        best = memories[0] if memories else None
        evidence = best.memory.outcome if best else "No compatible historical memory was found."
        diagnosis = self._reasoner.diagnosis(incident, evidence)
        if best and best.compatibility == 1.0 and best.memory.outcome_score > 0:
            proposed = ProposedAction(
                name="apply_prior_remediation",
                command=best.memory.action,
                risk=ActionRisk.MUTATING,
                rationale=f"Successful compatible memory {best.memory.id}",
                requires_approval=True,
            )
            confidence = min(0.95, max(0.1, best.rank_score))
        else:
            proposed = ProposedAction(
                name="collect_diagnostics",
                command=f"inspect logs and metrics for {incident.service}",
                risk=ActionRisk.READ_ONLY,
                rationale="No sufficiently compatible successful remediation exists",
                requires_approval=False,
            )
            confidence = 0.25
        saved = self._store.save_analysis(
            incident,
            IncidentAnalysis(
                diagnosis=diagnosis,
                confidence=confidence,
                memories=memories,
                proposed_action=proposed,
            ),
        )
        self._archive.archive(incident, saved)
        return saved

    def learn_outcome(
        self, incident_id: UUID, observation: OutcomeObservation
    ) -> Memory | None:
        incident = self._store.get_incident(incident_id, observation.tenant_id)
        if incident is None:
            return None
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
            embedding=self._embedder.embed(f"{incident.service} {incident.symptom}"),
        )
        return self._store.save_outcome_memory(memory)

    def govern_memory(
        self, memory_id: UUID, request: MemoryGovernanceRequest
    ) -> Memory | None:
        return self._store.govern_memory(memory_id, request)
