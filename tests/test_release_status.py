from __future__ import annotations

from typing import cast

import pytest

from recallops.config import Settings
from recallops.receipts import ReceiptVerificationError, TrustedKeyRegistry
from recallops.release_evidence import ReleaseIdentity, ReleaseStatement
from recallops.release_status import (
    PostgresReleaseEvidenceRepository,
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


def test_postgres_repository_maps_row_and_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    class Result:
        def __init__(self, value: dict[str, object] | None) -> None:
            self.value = value

        def fetchone(self) -> dict[str, object] | None:
            return self.value

    class Connection:
        def __init__(self) -> None:
            self.value: dict[str, object] | None = record().__dict__

        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, parameters: tuple[str]) -> Result:
            assert "release_evidence_records" in query
            assert parameters == ("release-v1",)
            return Result(self.value)

    connection = Connection()
    monkeypatch.setattr("recallops.release_status.psycopg.connect", lambda *a, **k: connection)
    repository = PostgresReleaseEvidenceRepository("postgresql://db")
    assert repository.get("release-v1") == record()
    connection.value = None
    assert repository.get("release-v1") is None


def test_production_composition_loads_repository_pinned_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = cast(TrustedKeyRegistry, object())
    monkeypatch.setattr("recallops.release_status.TrustedKeyRegistry.load", lambda path: sentinel)
    produced = ReleaseStatusService.production(settings())
    assert isinstance(produced._repository, PostgresReleaseEvidenceRepository)
    assert produced._trusted_keys is sentinel


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("release_id", "other-release"),
        ("source_sha", "f" * 40),
        ("image_digest", f"sha256:{'f' * 64}"),
        ("capability_policy_version", "other-capability-v1"),
        ("receipt_policy_version", "other-receipt-v1"),
        ("evaluation_version", "other-evaluation-v1"),
    ],
)
def test_each_release_identity_component_is_fail_closed(field: str, value: str) -> None:
    assert service(record(**{field: value})).current().live_proof.status == "stale"


@pytest.mark.parametrize(
    "update",
    [
        {"receipt_key_thumbprint": "D" * 43},
        {"source_sha": "f" * 40},
        {"image_digest": f"sha256:{'f' * 64}"},
        {"capability_policy_version": "other-capability-v1"},
        {"receipt_policy_version": "other-receipt-v1"},
        {"evaluation_version": "other-evaluation-v1"},
    ],
)
def test_each_signed_identity_component_must_match(
    update: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    signed = statement()
    changed = signed.model_copy(update={"identity": signed.identity.model_copy(update=update)})
    monkeypatch.setattr(
        "recallops.release_status.verify_release_statement_jws",
        lambda *args, **kwargs: changed,
    )
    assert not service(record()).current().signed_statement_verified


@pytest.mark.parametrize(
    "update",
    [
        {"live_proof_complete": False, "release_ready": False},
        {"assurance_complete": False, "release_ready": False},
        {"live_proof_artifact_digest": "e" * 64},
        {"assurance_artifact_digest": "e" * 64},
        {"release_ready": False},
    ],
)
def test_each_signed_gate_component_must_match(
    update: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    changed = statement().model_copy(update=update)
    monkeypatch.setattr(
        "recallops.release_status.verify_release_statement_jws",
        lambda *args, **kwargs: changed,
    )
    assert not service(record()).current().signed_statement_verified
