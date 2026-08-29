from uuid import UUID

import pytest
from botocore.exceptions import ClientError

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

    def put_object(self, **kwargs: object) -> dict[str, object]:
        self.put_calls.append(kwargs)
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
