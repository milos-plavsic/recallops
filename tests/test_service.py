from recallops.domain import ActionRisk, IncidentAnalysis, IncidentCreate, Memory
from recallops.embedding import DeterministicEmbedder
from recallops.service import DeterministicReasoner, IncidentService
from recallops.store import InMemoryStore


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
