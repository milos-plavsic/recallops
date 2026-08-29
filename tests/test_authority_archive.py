from uuid import UUID

import pytest
from botocore.exceptions import BotoCoreError, ClientError

from recallops.authority_archive import S3AuthorityBundleArchive
from recallops.resilience import DependencyUnavailable

RECEIPT_ID = UUID("50000000-0000-0000-0000-000000000042")


class FakeS3:
    def __init__(self) -> None:
        self.put_calls: list[dict[str, object]] = []
        self.head_response: dict[str, object] = {}
        self.put_response: dict[str, object] = {
            "VersionId": "version-1",
            "ServerSideEncryption": "aws:kms",
        }
        self.conflict = False
        self.put_error: Exception | None = None
        self.head_error: Exception | None = None

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.put_calls.append(kwargs)
        if self.put_error:
            raise self.put_error
        if self.conflict:
            raise ClientError(
                {
                    "Error": {"Code": "PreconditionFailed", "Message": "exists"},
                    "ResponseMetadata": {"HTTPStatusCode": 412},
                },
                "PutObject",
            )
        return self.put_response

    def head_object(self, **kwargs: object) -> dict[str, object]:
        assert kwargs["Key"] == S3AuthorityBundleArchive.object_key(RECEIPT_ID)
        if self.head_error:
            raise self.head_error
        return self.head_response


def archive(client: FakeS3) -> S3AuthorityBundleArchive:
    return S3AuthorityBundleArchive(client, "private-versioned-bucket", "alias/bundle-sse")


def test_s3_archive_requires_version_kms_checksum_and_write_once_precondition() -> None:
    client = FakeS3()
    result = archive(client).persist(RECEIPT_ID, b"deterministic-zip", "a" * 64)
    assert result.version_id == "version-1"
    request = client.put_calls[0]
    assert request["IfNoneMatch"] == "*"
    assert request["ServerSideEncryption"] == "aws:kms"
    assert request["SSEKMSKeyId"] == "alias/bundle-sse"
    assert request["ChecksumAlgorithm"] == "SHA256"
    assert request["Metadata"] == {
        "bundle-digest": "a" * 64,
        "receipt-id": str(RECEIPT_ID),
        "synthetic": "true",
    }


def test_retry_reuses_only_exact_existing_immutable_object() -> None:
    client = FakeS3()
    client.conflict = True
    client.head_response = {
        "VersionId": "existing-version",
        "ServerSideEncryption": "aws:kms",
        "Metadata": {"bundle-digest": "a" * 64},
    }
    result = archive(client).persist(RECEIPT_ID, b"deterministic-zip", "a" * 64)
    assert result.version_id == "existing-version"
    client.head_response["Metadata"] = {"bundle-digest": "b" * 64}
    with pytest.raises(DependencyUnavailable, match="conflict"):
        archive(client).persist(RECEIPT_ID, b"deterministic-zip", "a" * 64)


@pytest.mark.parametrize(
    ("response", "dependency"),
    [
        ({"ServerSideEncryption": "aws:kms"}, "versioning"),
        ({"VersionId": "v", "ServerSideEncryption": "AES256"}, "encryption"),
    ],
)
def test_archive_fails_closed_without_versioned_kms_evidence(
    response: dict[str, object], dependency: str
) -> None:
    client = FakeS3()
    client.put_response = response
    with pytest.raises(DependencyUnavailable, match=dependency):
        archive(client).persist(RECEIPT_ID, b"deterministic-zip", "a" * 64)


@pytest.mark.parametrize("bucket,kms", [("", "kms"), ("bucket", "")])
def test_archive_requires_configuration(bucket: str, kms: str) -> None:
    with pytest.raises(ValueError, match="bucket and KMS"):
        S3AuthorityBundleArchive(FakeS3(), bucket, kms)


@pytest.mark.parametrize(
    "payload,digest",
    [(b"", "a" * 64), (b"x", "A" * 64), (b"x", "a" * 63)],
)
def test_archive_rejects_invalid_local_material(payload: bytes, digest: str) -> None:
    with pytest.raises(ValueError):
        archive(FakeS3()).persist(RECEIPT_ID, payload, digest)


def test_archive_rejects_oversized_material() -> None:
    with pytest.raises(ValueError, match="size"):
        archive(FakeS3()).persist(RECEIPT_ID, b"x" * (8 * 1024 * 1024 + 1), "a" * 64)


def test_archive_normalizes_storage_failures_and_conflicts() -> None:
    client = FakeS3()
    client.put_error = ClientError(
        {
            "Error": {"Code": "AccessDenied", "Message": "denied"},
            "ResponseMetadata": {"HTTPStatusCode": 403},
        },
        "PutObject",
    )
    with pytest.raises(DependencyUnavailable, match="s3_authority_bundle"):
        archive(client).persist(RECEIPT_ID, b"zip", "a" * 64)

    client.put_error = BotoCoreError()
    with pytest.raises(DependencyUnavailable, match="s3_authority_bundle"):
        archive(client).persist(RECEIPT_ID, b"zip", "a" * 64)

    client.put_error = ClientError(
        {
            "Error": {"Code": "ConditionalRequestConflict", "Message": "exists"},
            "ResponseMetadata": {"HTTPStatusCode": 400},
        },
        "PutObject",
    )
    client.head_error = ClientError(
        {"Error": {"Code": "Denied", "Message": "denied"}}, "HeadObject"
    )
    with pytest.raises(DependencyUnavailable, match="s3_authority_bundle"):
        archive(client).persist(RECEIPT_ID, b"zip", "a" * 64)

    client.head_error = BotoCoreError()
    with pytest.raises(DependencyUnavailable, match="s3_authority_bundle"):
        archive(client).persist(RECEIPT_ID, b"zip", "a" * 64)


def test_archive_rejects_malformed_existing_metadata_and_empty_version() -> None:
    client = FakeS3()
    client.conflict = True
    client.head_response = {"Metadata": "invalid"}
    with pytest.raises(DependencyUnavailable, match="conflict"):
        archive(client).persist(RECEIPT_ID, b"zip", "a" * 64)
    client.head_response = {
        "Metadata": {"bundle-digest": "a" * 64},
        "VersionId": "",
        "ServerSideEncryption": "aws:kms",
    }
    with pytest.raises(DependencyUnavailable, match="versioning"):
        archive(client).persist(RECEIPT_ID, b"zip", "a" * 64)
