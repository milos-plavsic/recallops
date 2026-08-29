from typing import cast

import pytest

from recallops.config import Settings
from recallops.receipts import ReceiptVerificationError, TrustedKeyRegistry
from recallops.release_evidence import ReleaseIdentity, ReleaseStatement
from recallops.release_status import (
    ReleaseEvidenceRecord,
    ReleaseEvidenceRepository,
    ReleaseStatusService,
)

SHA = "a" * 40
IMAGE = f"sha256:{'b' * 64}"
THUMBPRINT = "C" * 43
DIGEST = "d" * 64


class Repository:
    def __init__(self, record: ReleaseEvidenceRecord | None) -> None:
        self.record = record

    def get(self, release_id: str) -> ReleaseEvidenceRecord | None:
        assert release_id == "release-v1"
        return self.record


def settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "receipt_release_id": "release-v1",
        "build_sha": SHA,
        "release_image_digest": IMAGE,
    }
    values.update(overrides)
    return Settings(**values)  # type: ignore[arg-type]


def record(**overrides: object) -> ReleaseEvidenceRecord:
    values: dict[str, object] = {
        "release_id": "release-v1",
        "source_sha": SHA,
        "image_digest": IMAGE,
        "capability_policy_version": "webmcp-capability-v1",
        "receipt_policy_version": "authority-receipt-policy-v1",
        "evaluation_version": "governed-benchmark-v1",
        "receipt_key_thumbprint": THUMBPRINT,
        "live_proof_artifact_digest": DIGEST,
        "live_proof_status": "passing",
        "assurance_artifact_digest": DIGEST,
        "assurance_status": "passing",
        "release_statement_jws": "signed.statement.value",
    }
    values.update(overrides)
    return ReleaseEvidenceRecord(**values)  # type: ignore[arg-type]


def statement(**overrides: object) -> ReleaseStatement:
    values: dict[str, object] = {
        "identity": ReleaseIdentity(
            release_id="release-v1",
            source_sha=SHA,
            image_digest=IMAGE,
            capability_policy_version="webmcp-capability-v1",
            receipt_policy_version="authority-receipt-policy-v1",
            evaluation_version="governed-benchmark-v1",
            receipt_key_thumbprint=THUMBPRINT,
        ),
        "live_proof_complete": True,
        "live_proof_artifact_digest": DIGEST,
        "assurance_complete": True,
        "assurance_artifact_digest": DIGEST,
        "release_ready": True,
    }
    values.update(overrides)
    return ReleaseStatement(**values)  # type: ignore[arg-type]


def service(item: ReleaseEvidenceRecord | None) -> ReleaseStatusService:
    return ReleaseStatusService(
        settings(),
        cast(ReleaseEvidenceRepository, Repository(item)),
        cast(TrustedKeyRegistry, object()),
    )


def test_unconfigured_and_unpublished_release_stay_pending() -> None:
    unconfigured = ReleaseStatusService(Settings()).current()
    unpublished = service(None).current()

    assert not unconfigured.configured and not unconfigured.release_ready
    assert unconfigured.live_proof.status == "pending"
    assert unpublished.configured and not unpublished.release_ready
    assert unpublished.reason == "release evidence has not been published"


def test_identity_mismatch_forces_both_gates_stale() -> None:
    result = service(record(source_sha="e" * 40)).current()

    assert result.live_proof.status == "stale"
    assert result.assurance.status == "stale"
    assert not result.signed_statement_verified
    assert not result.release_ready


def test_unsigned_or_invalid_statement_never_makes_release_ready(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unsigned = service(record(release_statement_jws=None)).current()
    assert unsigned.live_proof.complete and unsigned.assurance.complete
    assert not unsigned.release_ready

    def reject(*args: object, **kwargs: object) -> ReleaseStatement:
        raise ReceiptVerificationError("bad signature")

    monkeypatch.setattr("recallops.release_status.verify_release_statement_jws", reject)
    invalid = service(record()).current()
    assert not invalid.signed_statement_verified
    assert not invalid.release_ready


def test_only_exact_pinned_statement_completes_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "recallops.release_status.verify_release_statement_jws",
        lambda *args, **kwargs: statement(),
    )
    complete = service(record()).current()

    assert complete.live_proof.complete and complete.assurance.complete
    assert complete.signed_statement_verified
    assert complete.release_ready
    assert "pinned-key" in complete.reason

    mismatch = statement(
        identity=statement().identity.model_copy(
            update={"evaluation_version": "different-evaluation-v1"}
        )
    )
    monkeypatch.setattr(
        "recallops.release_status.verify_release_statement_jws",
        lambda *args, **kwargs: mismatch,
    )
    assert not service(record()).current().release_ready


def test_failed_gate_remains_red_even_with_matching_signed_statement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failed_record = record(
        assurance_status="failed",
        assurance_artifact_digest=None,
    )
    matching = statement(
        assurance_complete=False,
        assurance_artifact_digest="e" * 64,
        release_ready=False,
    )
    monkeypatch.setattr(
        "recallops.release_status.verify_release_statement_jws",
        lambda *args, **kwargs: matching,
    )
    result = service(failed_record).current()

    assert result.assurance.status == "failed"
    assert not result.assurance.complete
    assert not result.signed_statement_verified
    assert not result.release_ready
