from __future__ import annotations

import base64
import runpy
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest
from pydantic import SecretStr

import recallops.receipt_finalizer as finalizer
from recallops.authority_archive import ArchivedBundle
from recallops.authority_bundle import BundleError, FrozenRelease
from recallops.canonical import canonical_bytes
from recallops.receipt_finalizer import (
    FilesystemReceiptDocumentSource,
    ReceiptDocuments,
    ReceiptFinalizationWorker,
    ReceiptMaterial,
    ReceiptMaterialError,
    ReceiptWorkerResult,
)
from recallops.receipt_outbox import ReceiptRequest
from recallops.receipts import ReceiptDigestBindings, ReceiptError, TrustedKeyRegistry
from recallops.resilience import DependencyUnavailable

REQUEST_ID = UUID("50000000-0000-0000-0000-000000000001")
RECEIPT_ID = UUID("50000000-0000-0000-0000-000000000002")
RUN_ID = UUID("50000000-0000-0000-0000-000000000003")


def request(attempts: int = 1) -> ReceiptRequest:
    return ReceiptRequest(
        request_id=REQUEST_ID,
        receipt_id=RECEIPT_ID,
        run_id=RUN_ID,
        tenant_id="tenant",
        target_sequence=7,
        target_ledger_hash="a" * 64,
        publish_public=True,
        attempts=attempts,
        created_at=datetime(2026, 8, 29, tzinfo=UTC),
        receipt_policy_version="receipt-v1",
        source_sha="b" * 40,
        image_digest=f"sha256:{'c' * 64}",
        evaluation_version="evaluation-v1",
        synthetic=True,
    )


def documents() -> ReceiptDocuments:
    return ReceiptDocuments(
        evaluation_case={"evaluation_version": "evaluation-v1"},
        evaluation_result={"evaluation_version": "evaluation-v1"},
        claims={"claims": []},
    )


class Documents:
    error: Exception | None = None

    def load(self, evaluation_version: str) -> ReceiptDocuments:
        if self.error:
            raise self.error
        return documents()


class Loader:
    error: Exception | None = None

    def load(self, *args: object, **kwargs: object) -> ReceiptMaterial:
        if self.error:
            raise self.error
        raise AssertionError("success composition is covered by the Cockroach integration proof")


class Signer:
    kid = "K" * 43
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43}
    trusted_keys = cast(TrustedKeyRegistry, object())

    def sign_manifest(self, value: object) -> str:
        return "jws"


class Archive:
    def __init__(self, *args: object) -> None:
        pass

    def persist(self, *args: object) -> ArchivedBundle:
        raise AssertionError("not reached")


def worker(documents_source: Documents, loader: Loader) -> ReceiptFinalizationWorker:
    return ReceiptFinalizationWorker(
        database_url="postgresql://db",
        worker_id="worker",
        release_id="release-v1",
        subject_pseudonym_key=b"p" * 32,
        documents=documents_source,
        loader=loader,
        signer=Signer(),
        archive=Archive(),
    )


def test_document_source_requires_strict_bounded_matching_objects(tmp_path: Path) -> None:
    source = FilesystemReceiptDocumentSource(tmp_path)
    with pytest.raises(ReceiptMaterialError, match="unavailable"):
        source.load("evaluation-v1")
    for name in ("evaluation-case.jcs.json", "evaluation-result.jcs.json", "claims.jcs.json"):
        (tmp_path / name).write_bytes(canonical_bytes({"evaluation_version": "evaluation-v1"}))
    assert source.load("evaluation-v1").claims["evaluation_version"] == "evaluation-v1"
    (tmp_path / "evaluation-case.jcs.json").write_bytes(b"")
    with pytest.raises(ReceiptMaterialError, match="invalid size"):
        source.load("evaluation-v1")
    (tmp_path / "evaluation-case.jcs.json").write_bytes(canonical_bytes([]))
    with pytest.raises(ReceiptMaterialError, match="JSON object"):
        source.load("evaluation-v1")
    (tmp_path / "evaluation-case.jcs.json").write_bytes(
        canonical_bytes({"evaluation_version": "other-v1"})
    )
    with pytest.raises(ReceiptMaterialError, match="version"):
        source.load("evaluation-v1")


def test_material_helpers_reject_ambiguous_cardinality_and_time() -> None:
    with pytest.raises(ReceiptMaterialError, match="UTC offset"):
        finalizer._utc(datetime(2026, 8, 29))
    assert finalizer._utc(datetime(2026, 8, 29, tzinfo=UTC)).endswith("Z")
    for rows in ([], [{"x": 1}, {"x": 2}]):
        with pytest.raises(ReceiptMaterialError, match="exactly one"):
            finalizer._one(rows, "row")
    assert finalizer._one([{"x": 1}], "row") == {"x": 1}
    assert finalizer.capability_policy_document("cap-v1")["policy_version"] == "cap-v1"
    assert finalizer.receipt_policy_document("receipt-v1")["algorithm"] == "Ed25519"


def test_worker_configuration_idle_and_failure_classes(monkeypatch: pytest.MonkeyPatch) -> None:
    docs, loader = Documents(), Loader()
    with pytest.raises(ValueError, match="identity"):
        ReceiptFinalizationWorker(
            database_url="db",
            worker_id="",
            release_id="release",
            subject_pseudonym_key=b"short",
            documents=docs,
            loader=loader,
            signer=Signer(),
            archive=Archive(),
        )
    monkeypatch.setattr(finalizer, "claim_receipt_request", lambda *a, **k: None)
    assert worker(docs, loader).run_once() == ReceiptWorkerResult(status="idle")
    monkeypatch.setattr(finalizer, "claim_receipt_request", lambda *a, **k: request())
    released: list[tuple[str, int]] = []

    def release(*args: object, **kwargs: object) -> bool:
        released.append((cast(str, args[3]), cast(int, kwargs["max_attempts"])))
        return kwargs["max_attempts"] == 1

    monkeypatch.setattr(finalizer, "release_receipt_failure", release)
    for error, status, code, attempts in (
        (DependencyUnavailable("kms"), "retrying", "DEPENDENCY_KMS", 8),
        (ReceiptMaterialError("bad"), "dead_lettered", "RECEIPT_MATERIAL_INVALID", 1),
        (BundleError("bad"), "dead_lettered", "RECEIPT_MATERIAL_INVALID", 1),
        (ValueError("bad"), "dead_lettered", "RECEIPT_MATERIAL_INVALID", 1),
        (ReceiptError("bad"), "retrying", "RECEIPT_SIGNING_FAILED", 8),
    ):
        docs.error = error
        result = worker(docs, loader).run_once()
        assert result.status == status and result.failure_code == code
        assert released[-1] == (code, attempts)


def test_worker_lost_finalization_is_permanent_material_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docs, loader = Documents(), Loader()
    monkeypatch.setattr(finalizer, "claim_receipt_request", lambda *a, **k: request())
    material = SimpleNamespace(
        events=(),
        digests=ReceiptDigestBindings(
            proposal="1" * 64,
            execution="2" * 64,
            observation="3" * 64,
            assessment="4" * 64,
            policy_verdict="5" * 64,
            memory="6" * 64,
            review="7" * 64,
        ),
        final_disposition="certify",
        scenario_version="scenario-v1",
        signing_time="2026-08-29T00:00:00Z",
        expires_at="2026-09-01T00:00:00Z",
        release=FrozenRelease(
            release_id="release-v1",
            source_sha="b" * 40,
            image_digest=f"sha256:{'c' * 64}",
            capability_policy_version="cap-v1",
            receipt_policy_version="receipt-v1",
            evaluation_version="evaluation-v1",
            claim_registry_digest="d" * 64,
            receipt_key_thumbprint="K" * 43,
        ),
        capability_policy={},
        receipt_policy={},
    )
    monkeypatch.setattr(loader, "load", lambda *a, **k: material)
    prepared = SimpleNamespace(index_digest="e" * 64)
    manifest = SimpleNamespace(
        canonical=lambda: b"manifest",
        release=SimpleNamespace(
            release_id="release-v1",
            source_sha="b" * 40,
            image_digest=f"sha256:{'c' * 64}",
            evaluation_version="evaluation-v1",
        ),
        run_id=RUN_ID,
        ledger_head_hash="a" * 64,
        event_count="7",
        receipt_policy_version="receipt-v1",
        key_thumbprint="K" * 43,
    )
    bundle = SimpleNamespace(
        bundle_digest="f" * 64,
        deterministic_zip=lambda: b"zip",
    )
    monkeypatch.setattr(finalizer, "prepare_evidence", lambda **kwargs: prepared)
    monkeypatch.setattr(finalizer, "build_manifest", lambda *a, **k: manifest)
    monkeypatch.setattr(finalizer, "build_authority_bundle", lambda **kwargs: bundle)
    monkeypatch.setattr(Signer, "sign_manifest", lambda self, value: "jws")
    monkeypatch.setattr(
        Archive,
        "persist",
        lambda self, *a: ArchivedBundle("bucket", "key", "version", "f" * 64),
    )
    monkeypatch.setattr(finalizer, "finalize_receipt_request", lambda *a, **k: False)
    monkeypatch.setattr(finalizer, "release_receipt_failure", lambda *a, **k: True)
    result = worker(docs, loader).run_once()
    assert result.status == "dead_lettered"
    assert result.failure_code == "RECEIPT_MATERIAL_INVALID"


def test_worker_status_and_subject_key_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    class Result:
        value: dict[str, int] | None = {"pending": 1, "processing": 2, "dead_lettered": 3}

        def fetchone(self):
            return self.value

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str) -> Result:
            return result

    result = Result()
    monkeypatch.setattr(finalizer.psycopg, "connect", lambda *a, **k: Connection())
    assert finalizer.receipt_worker_status("db") == {
        "pending": 1,
        "processing": 2,
        "dead_lettered": 3,
    }
    result.value = None
    assert finalizer.receipt_worker_status("db") == {
        "pending": 0,
        "processing": 0,
        "dead_lettered": 0,
    }
    valid = base64.urlsafe_b64encode(b"p" * 32).rstrip(b"=").decode()
    assert finalizer._subject_pseudonym_key(valid) == b"p" * 32
    for value, match in (("", "canonical"), ("*", "canonical"), ("AA", "256 bits")):
        with pytest.raises(ReceiptMaterialError, match=match):
            finalizer._subject_pseudonym_key(value)
    monkeypatch.setattr(
        finalizer.base64,
        "b64decode",
        lambda *a, **k: (_ for _ in ()).throw(ValueError()),
    )
    with pytest.raises(ReceiptMaterialError, match="invalid base64url"):
        finalizer._subject_pseudonym_key("AA")


def test_production_worker_composes_only_external_adapters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import recallops.config as config

    incomplete = SimpleNamespace(
        receipt_kms_key_id=None,
        receipt_release_id=None,
        authority_bundle_bucket=None,
        authority_bundle_kms_key_id=None,
        receipt_subject_pseudonym_key_b64=None,
    )
    monkeypatch.setattr(config, "Settings", lambda: incomplete)
    with pytest.raises(ReceiptMaterialError, match="incomplete"):
        finalizer.production_worker("worker")

    values = SimpleNamespace(
        receipt_kms_key_id="alias/key",
        receipt_release_id="release-v1",
        authority_bundle_bucket="bucket",
        authority_bundle_kms_key_id="alias/archive",
        receipt_subject_pseudonym_key_b64=SecretStr(
            base64.urlsafe_b64encode(b"p" * 32).rstrip(b"=").decode()
        ),
        receipt_trusted_keys_path=Path("keys.json"),
        aws_region="eu-west-1",
        database_url="postgresql://db",
        receipt_release_artifacts_path=Path("artifacts/release"),
        outbox_max_attempts=9,
        outbox_lease_seconds=90,
    )
    monkeypatch.setattr(config, "Settings", lambda: values)
    registry = cast(TrustedKeyRegistry, object())
    monkeypatch.setattr(finalizer.TrustedKeyRegistry, "load", lambda path: registry)
    clients = {"kms": object(), "s3": object()}
    monkeypatch.setattr("boto3.client", lambda name, region_name: clients[name])

    class KmsSigner:
        def __init__(self, *args: object) -> None:
            pass

        def preflight(self) -> str:
            return "K" * 43

    monkeypatch.setattr(finalizer, "KmsReceiptSigner", KmsSigner)
    monkeypatch.setattr("recallops.authority_archive.S3AuthorityBundleArchive", Archive)
    produced = finalizer.production_worker("worker")
    assert produced._worker_id == "worker"
    assert produced._max_attempts == 9 and produced._lease_seconds == 90


def test_worker_cli_status_batch_watch_and_argument_guards(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import recallops.config as config

    monkeypatch.setattr(config, "Settings", lambda: SimpleNamespace(database_url="db"))
    monkeypatch.setattr(finalizer, "receipt_worker_status", lambda url: {"pending": 1})
    monkeypatch.setattr(sys, "argv", ["worker", "--status"])
    finalizer.main()
    assert "pending" in capsys.readouterr().out

    class Worker:
        values = [ReceiptWorkerResult(status="signed"), ReceiptWorkerResult(status="idle")]

        def run_once(self) -> ReceiptWorkerResult:
            return self.values.pop(0)

    monkeypatch.setattr(finalizer, "production_worker", lambda worker_id: Worker())
    monkeypatch.setattr(sys, "argv", ["worker", "--limit", "2"])
    finalizer.main()
    assert "signed=1" in capsys.readouterr().out
    Worker.values = [ReceiptWorkerResult(status="signed")]
    monkeypatch.setattr(sys, "argv", ["worker", "--limit", "1"])
    finalizer.main()
    assert "signed=1" in capsys.readouterr().out

    Worker.values = [ReceiptWorkerResult(status="idle")]
    monkeypatch.setattr(sys, "argv", ["worker", "--watch", "--limit", "1"])
    monkeypatch.setattr(
        finalizer.time,
        "sleep",
        lambda seconds: (_ for _ in ()).throw(RuntimeError("watch stopped")),
    )
    with pytest.raises(RuntimeError, match="watch stopped"):
        finalizer.main()
    assert capsys.readouterr().out == ""
    for arguments in (["worker", "--limit", "0"], ["worker", "--poll-seconds", "0"]):
        monkeypatch.setattr(sys, "argv", arguments)
        with pytest.raises(SystemExit):
            finalizer.main()
    monkeypatch.setattr(sys, "argv", ["receipt_finalizer", "--limit", "0"])
    with pytest.raises(SystemExit):
        runpy.run_path(finalizer.__file__, run_name="__main__")


def test_postgres_loader_rejects_identity_prefix_digest_and_disposition_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claimed = replace(request(), target_sequence=1)
    identity = {
        "scenario_version": "scenario-v1",
        "source_incident_id": UUID(int=9),
        "build_sha": claimed.source_sha,
        "capability_policy_version": "cap-v1",
        "source_sha": claimed.source_sha,
        "image_digest": claimed.image_digest,
        "receipt_policy_version": claimed.receipt_policy_version,
        "evaluation_version": claimed.evaluation_version,
        "receipt_key_thumbprint": "K" * 43,
    }
    event = SimpleNamespace(
        event_hash=claimed.target_ledger_hash,
        state_after="REVIEWED",
        object_type="review_binding",
        object_id="7" * 64,
        reason_code="MEMORY_CERTIFY",
    )
    head = {
        "last_sequence": 1,
        "last_event_hash": claimed.target_ledger_hash,
        "closed": False,
    }
    evidence = {
        "proposal_hash": "1" * 64,
        "execution_digest": "2" * 64,
        "observation_digest": "3" * 64,
        "assessment_id": UUID(int=1),
        "observation_id": UUID(int=2),
        "incident_id": UUID(int=3),
        "tenant_id": claimed.tenant_id,
        "agent_subject": "agent",
        "assessment_classification": "recovered",
        "rationale": "bounded rationale",
        "assessment_observation_digest": "3" * 64,
        "assessment_created_at": datetime(2026, 8, 29, tzinfo=UTC),
        "verdict_classification": "recovered",
        "verdict_policy": "policy-v1",
        "checks_passed": [],
        "checks_failed": [],
        "verdict_observation_digest": "3" * 64,
        "computed_at": datetime(2026, 8, 29, tzinfo=UTC),
        "assessment_digest": "4" * 64,
        "verdict_digest": "5" * 64,
        "memory_digest": "6" * 64,
        "expires_at": datetime(2026, 9, 1, tzinfo=UTC),
        "memory_state": "active",
        "memory_valid": True,
        "source_incident_id": UUID(int=3),
        "service": "checkout",
        "service_version": "v1",
        "action": "bounded",
        "outcome_semantics": "positive",
        "outcome_score": 1.0,
        "compatibility_policy": "exact",
        "compatibility_policy_version": "compat-v1",
        "governance_policy_version": "governance-v1",
        "memory_created_at": datetime(2026, 8, 29, tzinfo=UTC),
    }
    rows: dict[str, list[dict[str, object]]] = {
        "identity": [identity],
        "events": [{"event": True}],
        "head": [head],
        "evidence": [evidence],
    }

    class Result:
        def __init__(self, values: list[dict[str, object]]) -> None:
            self.values = values

        def fetchall(self) -> list[dict[str, object]]:
            return self.values

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, parameters: object) -> Result:
            key = (
                "identity"
                if "FROM judge_runs" in query
                else "events"
                if "FROM authority_events" in query
                else "head"
                if "FROM authority_ledger_heads" in query
                else "evidence"
            )
            return Result(rows[key])

    monkeypatch.setattr(finalizer.psycopg, "connect", lambda *a, **k: Connection())
    monkeypatch.setattr(
        finalizer.AuthorityEvent,
        "model_validate",
        lambda value: event,
    )
    monkeypatch.setattr(
        finalizer,
        "PostcheckAssessment",
        lambda **kwargs: SimpleNamespace(
            observation_digest="3" * 64,
            agent_subject="agent",
            classification=SimpleNamespace(value="recovered"),
            rationale="bounded rationale",
            created_at=datetime(2026, 8, 29, tzinfo=UTC),
        ),
    )
    monkeypatch.setattr(finalizer, "PolicyVerdict", lambda **kwargs: SimpleNamespace())
    monkeypatch.setattr(finalizer, "policy_verdict_digest", lambda value: "5" * 64)
    monkeypatch.setattr(
        finalizer,
        "content_digest",
        lambda domain, value: "4" * 64 if domain.endswith("assessment-v1") else "6" * 64,
    )
    loader = finalizer.PostgresReceiptMaterialLoader("db")

    def load() -> ReceiptMaterial:
        return loader.load(
            claimed,
            release_id="release-v1",
            key_thumbprint="K" * 43,
            documents=documents(),
        )

    assert load().final_disposition == "certify"
    identity["build_sha"] = "f" * 40
    with pytest.raises(ReceiptMaterialError, match="identity differ"):
        load()
    identity["build_sha"] = claimed.source_sha
    head["closed"] = True
    with pytest.raises(ReceiptMaterialError, match="review prefix"):
        load()
    head["closed"] = False
    evidence["assessment_digest"] = "f" * 64
    with pytest.raises(ReceiptMaterialError, match="digests or lifetime"):
        load()
    evidence["assessment_digest"] = "4" * 64
    event.reason_code = "UNKNOWN"
    with pytest.raises(ReceiptMaterialError, match="disposition"):
        load()
