from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from recallops.authority_archive import ArchivedBundle
from recallops.authority_bundle import FrozenRelease, read_bundle_zip, sha256_bytes
from recallops.canonical import canonical_bytes
from recallops.receipt_finalizer import (
    FilesystemReceiptDocumentSource,
    ReceiptDocuments,
    ReceiptFinalizationWorker,
    ReceiptMaterial,
    ReceiptMaterialError,
    capability_policy_document,
    receipt_policy_document,
)
from recallops.receipt_outbox import ReceiptRequest
from recallops.receipts import KmsClient, KmsReceiptSigner, ReceiptVerificationError
from recallops.resilience import DependencyUnavailable
from recallops.workflow import CAPABILITIES, WorkflowState


def test_filesystem_documents_require_strict_canonical_matching_evaluation(tmp_path: Path) -> None:
    case = {"case_id": "checkout-latency-42", "evaluation_version": "evaluation-v1"}
    result = {"evaluation_version": "evaluation-v1", "result": "passed"}
    claims = {"claims": [], "schema_version": "claim-registry-v1"}
    for name, value in (
        ("evaluation-case.jcs.json", case),
        ("evaluation-result.jcs.json", result),
        ("claims.jcs.json", claims),
    ):
        (tmp_path / name).write_bytes(canonical_bytes(value))
    loaded = FilesystemReceiptDocumentSource(tmp_path).load("evaluation-v1")
    assert loaded == ReceiptDocuments(
        evaluation_case=case,
        evaluation_result=result,
        claims=claims,
    )
    (tmp_path / "evaluation-result.jcs.json").write_text(
        '{"result": "passed", "evaluation_version": "evaluation-v1"}', encoding="utf-8"
    )
    with pytest.raises(ReceiptVerificationError, match="canonical"):
        FilesystemReceiptDocumentSource(tmp_path).load("evaluation-v1")


def test_filesystem_documents_fail_closed_for_missing_oversized_and_mismatched_files(
    tmp_path: Path,
) -> None:
    source = FilesystemReceiptDocumentSource(tmp_path)
    with pytest.raises(ReceiptMaterialError, match="unavailable"):
        source.load("evaluation-v1")
    (tmp_path / "evaluation-case.jcs.json").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    with pytest.raises(ReceiptMaterialError, match="invalid size"):
        source.load("evaluation-v1")
    (tmp_path / "evaluation-case.jcs.json").write_bytes(
        canonical_bytes({"evaluation_version": "wrong"})
    )
    (tmp_path / "evaluation-result.jcs.json").write_bytes(
        canonical_bytes({"evaluation_version": "evaluation-v1"})
    )
    (tmp_path / "claims.jcs.json").write_bytes(canonical_bytes({"claims": []}))
    with pytest.raises(ReceiptMaterialError, match="version"):
        source.load("evaluation-v1")


def test_generated_policy_documents_are_exactly_the_frozen_verifier_profile() -> None:
    capability = capability_policy_document("capability-v1")
    assert capability == {
        "capabilities": {state.value: list(CAPABILITIES[state]) for state in WorkflowState},
        "policy_version": "capability-v1",
        "protected_transitions": ["approve", "execute", "review"],
    }
    assert receipt_policy_document("receipt-v1") == {
        "algorithm": "Ed25519",
        "policy_version": "receipt-v1",
        "trust_anchor": "repository-pinned",
    }


def test_receipt_material_value_objects_keep_release_and_request_bindings_explicit() -> None:
    from tests.test_authority_bundle import (
        IMAGE_DIGEST,
        RELEASE_ID,
        SOURCE_SHA,
        events_for,
        receipt_digests,
    )

    claims = {"claims": [], "schema_version": "claim-registry-v1"}
    documents = ReceiptDocuments(
        evaluation_case={"evaluation_version": "evaluation-v1"},
        evaluation_result={"evaluation_version": "evaluation-v1"},
        claims=claims,
    )
    release = FrozenRelease(
        release_id=RELEASE_ID,
        source_sha=SOURCE_SHA,
        image_digest=IMAGE_DIGEST,
        capability_policy_version="capability-v1",
        receipt_policy_version="receipt-v1",
        evaluation_version="evaluation-v1",
        claim_registry_digest=sha256_bytes(canonical_bytes(claims)),
        receipt_key_thumbprint="k" * 43,
    )
    material = ReceiptMaterial(
        events=tuple(events_for(receipt_digests())),
        digests=receipt_digests(),
        final_disposition="certify",
        scenario_version="checkout-latency-v1",
        signing_time="2026-08-29T04:00:00Z",
        expires_at="2026-09-05T04:00:00Z",
        release=release,
        documents=documents,
        capability_policy=capability_policy_document("capability-v1"),
        receipt_policy=receipt_policy_document("receipt-v1"),
    )
    assert material.release.claim_registry_digest == sha256_bytes(canonical_bytes(claims))
    request = ReceiptRequest(
        request_id=uuid4(),
        receipt_id=uuid4(),
        run_id=material.events[0].run_id,
        tenant_id=material.events[0].tenant_id,
        target_sequence=len(material.events),
        target_ledger_hash=material.events[-1].event_hash,
        publish_public=True,
        attempts=1,
        created_at=datetime(2026, 8, 29, 4, tzinfo=UTC),
        receipt_policy_version="receipt-v1",
        source_sha=SOURCE_SHA,
        image_digest=IMAGE_DIGEST,
        evaluation_version="evaluation-v1",
        synthetic=True,
    )
    archived = ArchivedBundle(
        bucket="private",
        object_key=f"synthetic-authority-bundles/{request.receipt_id}/authority-bundle.zip",
        version_id="version-1",
        bundle_digest="f" * 64,
    )
    assert request.synthetic and archived.version_id == "version-1"


def finalizer_fixture():
    from tests.test_authority_bundle import (
        IMAGE_DIGEST,
        PSEUDONYM_KEY,
        RELEASE_ID,
        SOURCE_SHA,
        FakeKms,
        events_for,
        private_key,
        receipt_digests,
        registry,
    )

    key = private_key()
    signer = KmsReceiptSigner(
        cast(KmsClient, FakeKms(key)),
        "alias/recallops-bundle-vector",
        RELEASE_ID,
        registry(key),
    )
    kid = signer.preflight()
    digests = receipt_digests()
    events = tuple(events_for(digests))
    claims = {
        "claims": [{"claim_id": "authority.webmcp-boundary", "status": "verified-synthetic"}],
        "schema_version": "claim-registry-v1",
    }
    documents = ReceiptDocuments(
        evaluation_case={
            "case_id": "checkout-latency-42",
            "evaluation_version": "governed-benchmark-v1",
            "synthetic": True,
        },
        evaluation_result={
            "case_id": "checkout-latency-42",
            "evaluation_version": "governed-benchmark-v1",
            "result": "unsafe-similarity-shortcut-rejected",
            "synthetic": True,
        },
        claims=claims,
    )
    release = FrozenRelease(
        release_id=RELEASE_ID,
        source_sha=SOURCE_SHA,
        image_digest=IMAGE_DIGEST,
        capability_policy_version="webmcp-capability-v1",
        receipt_policy_version="authority-receipt-policy-v1",
        evaluation_version="governed-benchmark-v1",
        claim_registry_digest=sha256_bytes(canonical_bytes(claims)),
        receipt_key_thumbprint=kid,
    )
    material = ReceiptMaterial(
        events=events,
        digests=digests,
        final_disposition="certify",
        scenario_version="checkout-latency-v1",
        signing_time="2026-08-29T04:01:00Z",
        expires_at="2026-09-05T04:01:00Z",
        release=release,
        documents=documents,
        capability_policy=capability_policy_document("webmcp-capability-v1"),
        receipt_policy=receipt_policy_document("authority-receipt-policy-v1"),
    )
    request = ReceiptRequest(
        request_id=uuid4(),
        receipt_id=uuid4(),
        run_id=events[0].run_id,
        tenant_id=events[0].tenant_id,
        target_sequence=len(events),
        target_ledger_hash=events[-1].event_hash,
        publish_public=True,
        attempts=1,
        created_at=datetime(2026, 8, 29, 4, 1, tzinfo=UTC),
        receipt_policy_version=release.receipt_policy_version,
        source_sha=release.source_sha,
        image_digest=release.image_digest,
        evaluation_version=release.evaluation_version,
        synthetic=True,
    )
    return request, material, documents, signer, PSEUDONYM_KEY


class StaticDocuments:
    def __init__(self, documents: ReceiptDocuments) -> None:
        self.documents = documents

    def load(self, evaluation_version: str) -> ReceiptDocuments:
        assert evaluation_version == self.documents.evaluation_case["evaluation_version"]
        return self.documents


class StaticLoader:
    def __init__(self, material: ReceiptMaterial) -> None:
        self.material = material

    def load(self, request, *, release_id, key_thumbprint, documents):
        assert request.target_ledger_hash == self.material.events[-1].event_hash
        assert release_id == self.material.release.release_id
        assert key_thumbprint == self.material.release.receipt_key_thumbprint
        assert documents == self.material.documents
        return self.material


class CapturingArchive:
    def __init__(self, *, unavailable: bool = False) -> None:
        self.unavailable = unavailable
        self.files = None

    def persist(self, receipt_id, archive, bundle_digest):
        if self.unavailable:
            raise DependencyUnavailable("s3_authority_bundle")
        self.files = read_bundle_zip(archive)
        return ArchivedBundle(
            bucket="private",
            object_key=f"synthetic-authority-bundles/{receipt_id}/authority-bundle.zip",
            version_id="version-1",
            bundle_digest=bundle_digest,
        )


def test_finalization_worker_builds_signs_archives_and_finalizes_exact_material(
    monkeypatch,
) -> None:
    import recallops.receipt_finalizer as module

    request, material, documents, signer, pseudonym_key = finalizer_fixture()
    archive = CapturingArchive()
    finalized = []
    monkeypatch.setattr(module, "claim_receipt_request", lambda *args: request)

    def finalize(database_url, claimed, worker_id, manifest, result):
        finalized.append((database_url, claimed, worker_id, manifest, result))
        return True

    monkeypatch.setattr(module, "finalize_receipt_request", finalize)
    worker = ReceiptFinalizationWorker(
        database_url="postgresql://unused",
        worker_id="worker-1",
        release_id=material.release.release_id,
        subject_pseudonym_key=pseudonym_key,
        documents=StaticDocuments(documents),
        loader=StaticLoader(material),
        signer=signer,
        archive=archive,
    )
    result = worker.run_once()
    assert result.status == "signed" and result.receipt_id == str(request.receipt_id)
    assert archive.files is not None and len(finalized) == 1
    assert finalized[0][3].ledger_head_hash == request.target_ledger_hash
    assert finalized[0][4].archived.version_id == "version-1"


def test_finalization_worker_distinguishes_idle_transient_and_permanent_failure(
    monkeypatch,
) -> None:
    import recallops.receipt_finalizer as module

    request, material, documents, signer, pseudonym_key = finalizer_fixture()
    monkeypatch.setattr(module, "claim_receipt_request", lambda *args: None)
    idle = ReceiptFinalizationWorker(
        database_url="postgresql://unused",
        worker_id="worker-1",
        release_id=material.release.release_id,
        subject_pseudonym_key=pseudonym_key,
        documents=StaticDocuments(documents),
        loader=StaticLoader(material),
        signer=signer,
        archive=CapturingArchive(),
    )
    assert idle.run_once().status == "idle"

    released = []
    monkeypatch.setattr(module, "claim_receipt_request", lambda *args: request)
    monkeypatch.setattr(
        module,
        "release_receipt_failure",
        lambda *args, **kwargs: released.append((args, kwargs)) or False,
    )
    transient = ReceiptFinalizationWorker(
        database_url="postgresql://unused",
        worker_id="worker-1",
        release_id=material.release.release_id,
        subject_pseudonym_key=pseudonym_key,
        documents=StaticDocuments(documents),
        loader=StaticLoader(material),
        signer=signer,
        archive=CapturingArchive(unavailable=True),
    ).run_once()
    assert transient.status == "retrying"
    assert transient.failure_code == "DEPENDENCY_S3_AUTHORITY_BUNDLE"
    assert released[-1][1]["max_attempts"] == 8

    class InvalidLoader(StaticLoader):
        def load(self, *args, **kwargs):
            raise ReceiptMaterialError("invalid immutable evidence")

    monkeypatch.setattr(
        module,
        "release_receipt_failure",
        lambda *args, **kwargs: released.append((args, kwargs)) or True,
    )
    permanent = ReceiptFinalizationWorker(
        database_url="postgresql://unused",
        worker_id="worker-1",
        release_id=material.release.release_id,
        subject_pseudonym_key=pseudonym_key,
        documents=StaticDocuments(documents),
        loader=InvalidLoader(material),
        signer=signer,
        archive=CapturingArchive(),
    ).run_once()
    assert permanent.status == "dead_lettered"
    assert permanent.failure_code == "RECEIPT_MATERIAL_INVALID"
    assert released[-1][1]["max_attempts"] == 1
