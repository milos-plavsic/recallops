from typing import Any
from uuid import uuid4

import pytest
from botocore.exceptions import ClientError

from recallops import archive as archive_module
from recallops.archive import S3EvidenceArchive, evidence_payload
from recallops.domain import IncidentCreate
from recallops.embedding import DeterministicEmbedder
from recallops.resilience import DependencyUnavailable
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
    archived_memories = payload["analysis"]["memories"]
    assert all("embedding" not in item["memory"] for item in archived_memories)


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


def test_s3_archive_uses_exact_customer_managed_key(monkeypatch: pytest.MonkeyPatch) -> None:
    client = FakeS3Client()
    monkeypatch.setattr(archive_module.boto3, "client", lambda *args, **kwargs: client)
    archive = S3EvidenceArchive(
        "us-east-1", "evidence-bucket", kms_key_id="arn:aws:kms:us-east-1:123:key/key-id"
    )

    archive.archive_payload("tenant-a", uuid4(), {}, "checkout", "v1")

    request = client.requests[0]
    assert request["ServerSideEncryption"] == "aws:kms"
    assert request["SSEKMSKeyId"] == "arn:aws:kms:us-east-1:123:key/key-id"
    assert request["BucketKeyEnabled"] is True


def test_s3_archive_translates_provider_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class FailingS3:
        def put_object(self, **request: Any) -> None:
            del request
            raise ClientError({"Error": {"Code": "Denied", "Message": "no"}}, "PutObject")

    monkeypatch.setattr(archive_module.boto3, "client", lambda *args, **kwargs: FailingS3())
    archive = S3EvidenceArchive("us-east-1", "evidence-bucket")

    with pytest.raises(DependencyUnavailable, match="s3_evidence"):
        archive.archive_payload("tenant-a", uuid4(), {}, "checkout", "v1")
