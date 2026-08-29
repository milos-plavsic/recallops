import io
from typing import Any, cast
from uuid import UUID

import pytest
from botocore.exceptions import BotoCoreError, ClientError
from fastapi.testclient import TestClient

from recallops.api import create_app
from recallops.authority_bundle import (
    ALLOWED_PATHS,
    AUXILIARY_PATHS,
    AuthorityBundle,
    EvidenceIndex,
    EvidenceIndexEntry,
    bundle_digest,
    sha256_bytes,
)
from recallops.canonical import canonical_bytes
from recallops.config import Settings
from recallops.public_bundles import (
    FinalizedPublicReceipt,
    PostgresPublicReceiptRepository,
    PublicBundleService,
)
from recallops.resilience import DependencyUnavailable
from recallops.store import InMemoryStore

RECEIPT_ID = UUID("50000000-0000-0000-0000-000000000042")


class Repository:
    def __init__(self, record: FinalizedPublicReceipt | None) -> None:
        self.record = record

    def finalized_public(self, receipt_id: UUID) -> FinalizedPublicReceipt | None:
        assert receipt_id == RECEIPT_ID
        return self.record


class Client:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.request: dict[str, object] | None = None

    def get_object(self, **kwargs: object) -> dict[str, object]:
        self.request = kwargs
        return {"Body": io.BytesIO(self.body)}


def record(digest: str) -> FinalizedPublicReceipt:
    return FinalizedPublicReceipt(
        receipt_id=RECEIPT_ID,
        bundle_digest=digest,
        object_key=f"synthetic-authority-bundles/{RECEIPT_ID}/authority-bundle.zip",
        version_id="immutable-version-1",
        source_sha="a" * 40,
        image_digest=f"sha256:{'b' * 64}",
    )


def valid_outer_bundle() -> AuthorityBundle:
    files = {
        "public.jwk.json": b"{}",
        "events.ndjson": b"{}\n",
        "policy/capability-policy.json": b"{}",
        "policy/receipt-policy.json": b"{}",
        "evaluation/case.json": b"{}",
        "evaluation/result.json": b"{}",
        "release.json": b"{}",
        "claims.json": b"{}",
        "manifest.jcs.json": b"{}",
        "receipt.jws": b"test.test.test",
        "README.md": b"test",
    }
    index = EvidenceIndex(
        entries=tuple(
            EvidenceIndexEntry(path=path, sha256=sha256_bytes(files[path]), size=len(files[path]))
            for path in AUXILIARY_PATHS
        )
    )
    files["evidence-index.jcs.json"] = canonical_bytes(index.model_dump(mode="json"))
    checksums = "".join(
        f"{sha256_bytes(files[path])}  {path}\n"
        for path in sorted(ALLOWED_PATHS - {"checksums.sha256"})
    ).encode()
    files["checksums.sha256"] = checksums
    return AuthorityBundle(
        files=files,
        evidence_index_digest=sha256_bytes(files["evidence-index.jcs.json"]),
        checksums_digest=sha256_bytes(checksums),
        bundle_digest=bundle_digest(checksums),
    )


def test_public_download_reads_exact_version_and_revalidates_bundle() -> None:
    bundle = valid_outer_bundle()
    archive = bundle.deterministic_zip()
    client = Client(archive)
    result = PublicBundleService(
        Repository(record(bundle.bundle_digest)), client, "private-bucket"
    ).download(RECEIPT_ID)
    assert result == (archive, record(bundle.bundle_digest))
    assert client.request == {
        "Bucket": "private-bucket",
        "Key": f"synthetic-authority-bundles/{RECEIPT_ID}/authority-bundle.zip",
        "VersionId": "immutable-version-1",
    }


def test_unknown_or_nonpublic_receipt_never_reads_storage() -> None:
    client = Client(b"must not be read")
    assert (
        PublicBundleService(Repository(None), client, "private-bucket").download(RECEIPT_ID) is None
    )
    assert client.request is None


@pytest.mark.parametrize("tamper", [b"not-a-zip", b"PK\x03\x04"])
def test_public_download_fails_closed_on_storage_tampering(tamper: bytes) -> None:
    client = Client(tamper)
    with pytest.raises(DependencyUnavailable, match="integrity"):
        PublicBundleService(Repository(record("a" * 64)), client, "private-bucket").download(
            RECEIPT_ID
        )


def test_public_http_route_is_credential_free_immutable_and_bounded() -> None:
    bundle = valid_outer_bundle()
    archive = bundle.deterministic_zip()

    class Service:
        def download(self, receipt_id: UUID):
            return (archive, record(bundle.bundle_digest)) if receipt_id == RECEIPT_ID else None

    app = create_app(
        Settings(store="memory", auth_mode="demo"),
        InMemoryStore(),
        public_bundle_service=cast(Any, Service()),
    )
    client = TestClient(app)
    response = client.get(f"/public/evidence/{RECEIPT_ID}/authority-bundle.zip")
    assert response.status_code == 200 and response.content == archive
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert response.headers["etag"] == f'"{bundle.bundle_digest}"'
    assert (
        client.get(
            "/public/evidence/60000000-0000-0000-0000-000000000042/authority-bundle.zip"
        ).status_code
        == 404
    )


def test_public_service_aws_constructs_exact_client(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def client(name: str, **kwargs: object) -> Client:
        seen.update({"name": name, **kwargs})
        return Client(b"")

    monkeypatch.setattr("recallops.public_bundles.boto3.client", client)
    service = PublicBundleService.aws("postgresql://db", "eu-west-1", "bucket")
    assert isinstance(service._repository, PostgresPublicReceiptRepository)
    assert seen["name"] == "s3" and seen["region_name"] == "eu-west-1"


def test_postgres_public_repository_maps_only_returned_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Result:
        value: dict[str, object] | None = {
            "receipt_id": RECEIPT_ID,
            "bundle_digest": "a" * 64,
            "bundle_object_key": "bundle.zip",
            "s3_version_id": "version-1",
            "source_sha": "b" * 40,
            "image_digest": f"sha256:{'c' * 64}",
        }

        def fetchone(self) -> dict[str, object] | None:
            return self.value

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, parameters: tuple[UUID]) -> Result:
            assert "status='signed'" in query and parameters == (RECEIPT_ID,)
            return result

    result = Result()
    monkeypatch.setattr("recallops.public_bundles.psycopg.connect", lambda *a, **k: Connection())
    repository = PostgresPublicReceiptRepository("postgresql://db")
    assert repository.finalized_public(RECEIPT_ID) == FinalizedPublicReceipt(
        receipt_id=RECEIPT_ID,
        bundle_digest="a" * 64,
        object_key="bundle.zip",
        version_id="version-1",
        source_sha="b" * 40,
        image_digest=f"sha256:{'c' * 64}",
    )
    result.value = None
    assert repository.finalized_public(RECEIPT_ID) is None


class RaisingClient:
    def __init__(self, error: Exception) -> None:
        self.error = error

    def get_object(self, **kwargs: object) -> dict[str, object]:
        raise self.error


@pytest.mark.parametrize(
    "error",
    [
        BotoCoreError(),
        ClientError({"Error": {"Code": "Denied", "Message": "x"}}, "GetObject"),
        OSError("read failed"),
    ],
)
def test_public_download_normalizes_storage_errors(error: Exception) -> None:
    with pytest.raises(DependencyUnavailable, match="s3_authority_bundle"):
        PublicBundleService(Repository(record("a" * 64)), RaisingClient(error), "bucket").download(
            RECEIPT_ID
        )


def test_public_download_rejects_nonbytes_and_outer_digest_mismatch() -> None:
    class NonBytes:
        def get_object(self, **kwargs: object) -> dict[str, object]:
            return {"Body": object()}

    with pytest.raises(DependencyUnavailable, match="s3_authority_bundle"):
        PublicBundleService(Repository(record("a" * 64)), NonBytes(), "bucket").download(RECEIPT_ID)

    bundle = valid_outer_bundle()
    with pytest.raises(DependencyUnavailable, match="integrity"):
        PublicBundleService(
            Repository(record("f" * 64)), Client(bundle.deterministic_zip()), "bucket"
        ).download(RECEIPT_ID)
