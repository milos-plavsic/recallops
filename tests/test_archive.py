from recallops.archive import evidence_payload
from recallops.domain import IncidentCreate
from recallops.embedding import DeterministicEmbedder
from recallops.service import DeterministicReasoner, IncidentService
from recallops.store import InMemoryStore


def test_archive_payload_excludes_raw_embeddings() -> None:
    incident = IncidentCreate(
        tenant_id="tenant-a",
        service="checkout",
        service_version="v1",
        symptom="elevated latency after deployment",
        idempotency_key="archive-test-1",
    )
    analysis = IncidentService(
        InMemoryStore(), DeterministicEmbedder(), DeterministicReasoner()
    ).analyze(incident)

    payload = evidence_payload(incident, analysis)

    assert payload["schema_version"] == 1
    assert "embedding" not in str(payload)
