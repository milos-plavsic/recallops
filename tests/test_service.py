from datetime import UTC, datetime, timedelta

import pytest

from recallops.domain import (
    ActionRisk,
    ApprovalRequest,
    ExecutionAttestationRequest,
    GovernanceAction,
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    MemoryState,
    OutcomeObservation,
)
from recallops.embedding import DeterministicEmbedder
from recallops.service import DeterministicReasoner, IncidentService, IncidentWorkflowError
from recallops.store import InMemoryStore, rank_memory


class RecordingArchive:
    def __init__(self) -> None:
        self.incident_ids: list[str] = []

    def archive(self, incident: IncidentCreate, analysis: IncidentAnalysis) -> None:
        self.incident_ids.append(str(analysis.incident_id))


def incident(version: str = "2026.07.31") -> IncidentCreate:
    return IncidentCreate(
        tenant_id="demo",
        service="checkout",
        service_version=version,
        symptom="latency spike after connection pool exhaustion",
        idempotency_key="event-0001",
    )


def memory(
    embedder: DeterministicEmbedder, version: str, outcome_score: float, action: str
) -> Memory:
    symptom = "checkout latency spike after connection pool exhaustion"
    return Memory(
        tenant_id="demo",
        service="checkout",
        service_version=version,
        symptom=symptom,
        action=action,
        outcome="latency recovered and error rate returned to baseline",
        outcome_score=outcome_score,
        confidence=0.95,
        embedding=embedder.embed(f"checkout {symptom}"),
    )


def test_compatible_successful_memory_drives_guarded_action() -> None:
    embedder = DeterministicEmbedder()
    store = InMemoryStore(
        [
            memory(embedder, "2025.01", 1.0, "obsolete rollback"),
            memory(embedder, "2026.07.31", 1.0, "reduce worker concurrency"),
        ]
    )
    result = IncidentService(store, embedder, DeterministicReasoner()).analyze(incident())
    assert result.proposed_action.command == "reduce worker concurrency"
    assert result.proposed_action.risk is ActionRisk.MUTATING
    assert result.proposed_action.requires_approval is True


def test_no_cross_tenant_retrieval() -> None:
    embedder = DeterministicEmbedder()
    other = memory(embedder, "2026.07.31", 1.0, "secret remediation")
    other.tenant_id = "other"
    result = IncidentService(InMemoryStore([other]), embedder, DeterministicReasoner()).analyze(
        incident()
    )
    assert result.memories == []
    assert result.proposed_action.risk is ActionRisk.READ_ONLY


def test_retrieval_never_crosses_embedding_spaces() -> None:
    embedder = DeterministicEmbedder()
    incompatible = memory(embedder, "2026.07.31", 1.0, "unsafe cross-space action")
    incompatible.embedding_space = "bedrock:amazon.titan-embed-text-v2:0:v1"
    result = IncidentService(
        InMemoryStore([incompatible]), embedder, DeterministicReasoner()
    ).analyze(incident())

    assert result.memories == []
    assert result.proposed_action.risk is ActionRisk.READ_ONLY


def test_retrieval_abstains_when_evidence_confidence_is_insufficient() -> None:
    embedder = DeterministicEmbedder()
    weak = memory(embedder, "2026.07.31", 1.0, "weakly supported action")
    weak.confidence = 0.2
    result = IncidentService(InMemoryStore([weak]), embedder, DeterministicReasoner()).analyze(
        incident()
    )

    assert "evidence_confidence_below_threshold" in result.retrieval_abstention_reasons
    assert result.proposed_action.risk is ActionRisk.READ_ONLY


def attest(service: IncidentService, analysis: IncidentAnalysis, actor: str) -> str:
    action = analysis.proposed_action
    execution = service.attest_execution(
        analysis.incident_id,
        ExecutionAttestationRequest(
            tenant_id="demo",
            actor_id=actor,
            action_hash=action.action_hash,
            action_taken=action.command,
            evidence_refs=["test://execution/verified"],
        ),
    )
    assert execution is not None
    return execution.action_taken


def test_mutating_execution_requires_approval_for_exact_action() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(
        InMemoryStore([memory(embedder, "2026.07.31", 1.0, "reduce concurrency")]),
        embedder,
        DeterministicReasoner(),
    )
    analysis = service.analyze(incident())
    action = analysis.proposed_action
    request = ExecutionAttestationRequest(
        tenant_id="demo",
        actor_id="operator-1",
        action_hash=action.action_hash,
        action_taken=action.command,
        evidence_refs=["test://execution/verified"],
    )

    with pytest.raises(IncidentWorkflowError, match="approved decision required"):
        service.attest_execution(analysis.incident_id, request)

    assert service.decide_approval(
        analysis.incident_id,
        ApprovalRequest(
            tenant_id="demo",
            actor_id="operator-1",
            approved=True,
            reason="exact action reviewed against current evidence",
        ),
    )
    assert service.attest_execution(analysis.incident_id, request) is not None


def test_execution_rejects_action_substitution() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())

    with pytest.raises(IncidentWorkflowError, match="does not match"):
        service.attest_execution(
            analysis.incident_id,
            ExecutionAttestationRequest(
                tenant_id="demo",
                actor_id="operator-1",
                action_hash=analysis.proposed_action.action_hash,
                action_taken="substituted destructive command",
                evidence_refs=["test://execution/verified"],
            ),
        )


def test_retrieval_abstains_when_top_candidates_are_ambiguous() -> None:
    embedder = DeterministicEmbedder()
    first = memory(embedder, "2026.07.31", 1.0, "action one")
    second = memory(embedder, "2026.07.31", 1.0, "action two")
    result = IncidentService(
        InMemoryStore([first, second]), embedder, DeterministicReasoner()
    ).analyze(incident())

    assert "top_candidates_ambiguous" in result.retrieval_abstention_reasons
    assert result.proposed_action.risk is ActionRisk.READ_ONLY


def test_idempotency_returns_original_analysis() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    first = service.analyze(incident())
    second = service.analyze(incident())
    assert first.incident_id == second.incident_id


def test_analysis_is_archived() -> None:
    embedder = DeterministicEmbedder()
    archive = RecordingArchive()
    result = IncidentService(
        InMemoryStore(), embedder, DeterministicReasoner(), archive=archive
    ).analyze(incident())
    assert archive.incident_ids == [str(result.incident_id)]


def test_observed_outcome_becomes_idempotent_retrievable_memory() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    observation = OutcomeObservation(
        tenant_id="demo",
        action_taken=attest(service, analysis, "operator-observer"),
        outcome="latency recovered without recurrence",
        outcome_score=1.0,
        confidence=0.98,
        actor_id="operator-observer",
    )

    first = service.learn_outcome(analysis.incident_id, observation)
    second = service.learn_outcome(analysis.incident_id, observation)
    assert first is not None
    assert second is not None
    assert first.id == second.id
    assert first.state is MemoryState.PENDING_REVIEW

    before_review = service.analyze(
        incident().model_copy(update={"idempotency_key": "event-0002"})
    )
    assert before_review.memories == []

    activated = service.govern_memory(
        first.id,
        MemoryGovernanceRequest(
            tenant_id="demo",
            actor_id="operator-reviewer",
            action=GovernanceAction.ACTIVATE,
            reason="independent telemetry review confirms sustained recovery",
        ),
    )
    assert activated is not None
    assert activated.state is MemoryState.ACTIVE

    future = service.analyze(
        incident().model_copy(update={"idempotency_key": "event-0003"})
    )
    assert future.memories[0].memory.id == first.id
    assert future.proposed_action.command == observation.action_taken


def test_outcome_learning_enforces_tenant_boundary() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    result = service.learn_outcome(
        analysis.incident_id,
        OutcomeObservation(
            tenant_id="other",
            action_taken="exfiltrate remediation",
            outcome="should never be learned",
            outcome_score=1.0,
            confidence=1.0,
            actor_id="attacker",
        ),
    )
    assert result is None


def test_memory_activation_requires_independent_reviewer() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    action_taken = attest(service, analysis, "operator-1")
    learned = service.learn_outcome(
        analysis.incident_id,
        OutcomeObservation(
            tenant_id="demo",
            action_taken=action_taken,
            outcome="latency recovered",
            outcome_score=1.0,
            confidence=0.9,
            actor_id="operator-1",
        ),
    )
    assert learned is not None
    request = MemoryGovernanceRequest(
        tenant_id="demo",
        actor_id="operator-1",
        action=GovernanceAction.ACTIVATE,
        reason="self review must not activate memory",
    )
    with pytest.raises(ValueError, match="independent reviewer"):
        service.govern_memory(learned.id, request)


def test_memory_can_be_superseded_only_by_active_same_tenant_memory() -> None:
    embedder = DeterministicEmbedder()
    old = memory(embedder, "2026.07.31", 1.0, "old remediation")
    replacement = memory(embedder, "2026.07.31", 1.0, "safer remediation")
    store = InMemoryStore([old, replacement])
    service = IncidentService(store, embedder, DeterministicReasoner())

    updated = service.govern_memory(
        old.id,
        MemoryGovernanceRequest(
            tenant_id="demo",
            actor_id="reviewer-1",
            action=GovernanceAction.SUPERSEDE,
            reason="new remediation has stronger postcondition evidence",
            replacement_memory_id=replacement.id,
        ),
    )
    assert updated is not None
    assert updated.state is MemoryState.SUPERSEDED
    assert updated.valid is False
    assert updated.superseded_by == replacement.id
    assert store.memory_events[-1].from_state is MemoryState.ACTIVE
    assert store.memory_events[-1].to_state is MemoryState.SUPERSEDED


def test_positive_evidence_decays_but_known_failure_penalty_persists() -> None:
    embedder = DeterministicEmbedder()
    as_of = datetime(2026, 8, 1, tzinfo=UTC)
    created_at = as_of - timedelta(days=360)
    success = memory(embedder, "2026.07.31", 1.0, "successful remediation").model_copy(
        update={"confidence": 1.0, "created_at": created_at}
    )
    failure = memory(embedder, "2026.07.31", -1.0, "failed remediation").model_copy(
        update={"confidence": 1.0, "created_at": created_at}
    )

    ranked_success = rank_memory(success, 1.0, "2026.07.31", as_of=as_of)
    ranked_failure = rank_memory(failure, 1.0, "2026.07.31", as_of=as_of)
    assert ranked_success.freshness == pytest.approx(0.25)
    assert ranked_success.effective_confidence == pytest.approx(0.25)
    assert ranked_failure.rank_score < ranked_success.rank_score
