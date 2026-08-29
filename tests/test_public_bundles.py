import io
from typing import Any, cast
from uuid import UUID

import pytest
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
            EvidenceIndexEntry(
                path=path, sha256=sha256_bytes(files[path]), size=len(files[path])
            )
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
    assert PublicBundleService(Repository(None), client, "private-bucket").download(
        RECEIPT_ID
    ) is None
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
            return (
                (archive, record(bundle.bundle_digest))
                if receipt_id == RECEIPT_ID
                else None
            )

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
    assert client.get(
        "/public/evidence/60000000-0000-0000-0000-000000000042/authority-bundle.zip"
    ).status_code == 404
