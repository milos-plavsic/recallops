from concurrent.futures import ThreadPoolExecutor

from recallops.archive import EvidenceArchive
from recallops.domain import IncidentAnalysis, IncidentCreate
from recallops.embedding import DeterministicEmbedder, Embedder
from recallops.resilience import DependencyUnavailable, aws_client_config
from recallops.service import IncidentService, Reasoner
from recallops.store import InMemoryStore


def incident() -> IncidentCreate:
    return IncidentCreate(
        tenant_id="tenant-a",
        service="payments",
        service_version="1.0.0",
        symptom="elevated timeout rate",
        idempotency_key="resilience-key",
    )


class FailedEmbedder:
    def embed(self, text: str) -> list[float]:
        raise DependencyUnavailable("bedrock_embedding")


class FailedReasoner:
    def diagnosis(self, request: IncidentCreate, evidence: str) -> str:
        raise DependencyUnavailable("bedrock_reasoning")


class FailedArchive:
    def archive(self, request: IncidentCreate, analysis: IncidentAnalysis) -> None:
        raise DependencyUnavailable("s3_evidence")


def test_provider_failures_degrade_without_inventing_action() -> None:
    result = IncidentService(
        InMemoryStore(), FailedEmbedder(), FailedReasoner(), archive=FailedArchive()
    ).analyze(incident())

    assert result.degraded_dependencies == ["bedrock_embedding", "bedrock_reasoning"]
    assert result.proposed_action.name == "collect_diagnostics"
    assert result.proposed_action.requires_approval is False
    assert "No compatible historical memory" in result.diagnosis


def test_concurrent_idempotent_requests_return_one_incident() -> None:
    service = IncidentService(
        InMemoryStore(), DeterministicEmbedder(), FailedReasoner()
    )

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(lambda _: service.analyze(incident()), range(64)))

    assert len({result.incident_id for result in results}) == 1


def test_aws_policy_has_finite_timeouts_and_bounded_standard_retries() -> None:
    config = aws_client_config(1.5, 8.0, 4)

    assert config.connect_timeout == 1.5
    assert config.read_timeout == 8.0
    assert config.retries == {"mode": "standard", "total_max_attempts": 4}
    assert config.tcp_keepalive is True


def accepts_resilience_protocols(
    embedder: Embedder, reasoner: Reasoner, archive: EvidenceArchive
) -> None:
    del embedder, reasoner, archive
