from typing import Any

import pytest

from recallops import archive as archive_module
from recallops.archive import S3EvidenceArchive, evidence_payload
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


class FakeS3Client:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []

    def put_object(self, **request: Any) -> None:
        self.requests.append(request)


def test_s3_archive_uses_deterministic_encrypted_object(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeS3Client()
    monkeypatch.setattr(archive_module.boto3, "client", lambda *args, **kwargs: client)
    incident = IncidentCreate(
        tenant_id="tenant-a",
        service="checkout",
        service_version="v1",
        symptom="elevated latency after deployment",
        idempotency_key="archive-test-2",
    )
    analysis = IncidentService(
        InMemoryStore(), DeterministicEmbedder(), DeterministicReasoner()
    ).analyze(incident)

    S3EvidenceArchive("us-east-1", "evidence-bucket").archive(incident, analysis)

    request = client.requests[0]
    assert request["Bucket"] == "evidence-bucket"
    assert request["Key"].endswith(f"/{analysis.incident_id}/analysis.json")
    assert request["ServerSideEncryption"] == "AES256"
    assert b'"embedding"' not in request["Body"]
