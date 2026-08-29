from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

import recallops.receipt_outbox as outbox
from recallops.authority_archive import ArchivedBundle
from recallops.receipt_outbox import ReceiptRequest, SignedReceiptResult
from tests.integration.test_receipt_outbox import manifest

REQUEST_ID = UUID("70000000-0000-0000-0000-000000000001")
RECEIPT_ID = UUID("70000000-0000-0000-0000-000000000002")
RUN_ID = UUID("70000000-0000-0000-0000-000000000003")
WORKFLOW_ID = UUID("70000000-0000-0000-0000-000000000004")


def request() -> ReceiptRequest:
    return ReceiptRequest(
        request_id=REQUEST_ID,
        receipt_id=RECEIPT_ID,
        run_id=RUN_ID,
        tenant_id="tenant",
        target_sequence=1,
        target_ledger_hash="1" * 64,
        publish_public=True,
        attempts=1,
        created_at=datetime(2026, 8, 29, tzinfo=UTC),
        receipt_policy_version="receipt-v1",
        source_sha="b" * 40,
        image_digest=f"sha256:{'c' * 64}",
        evaluation_version="evaluation-v1",
        synthetic=True,
    )


def signed() -> SignedReceiptResult:
    return SignedReceiptResult(
        manifest_digest="2" * 64,
        jws_compact="jws",
        key_thumbprint="k" * 43,
        archived=ArchivedBundle(
            bucket="bucket",
            object_key="bundle.zip",
            version_id="version-1",
            bundle_digest="3" * 64,
        ),
    )


class Result:
    def __init__(self, row: Any = None, rowcount: int = 1) -> None:
        self.row = row
        self.rowcount = rowcount

    def fetchone(self) -> Any:
        return self.row


class Connection:
    def __init__(self, results: list[Result]) -> None:
        self.results = results

    def __enter__(self) -> Connection:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, parameters: object) -> Result:
        return self.results.pop(0)


def connect(monkeypatch: pytest.MonkeyPatch, results: list[Result]) -> None:
    monkeypatch.setattr(outbox.psycopg, "connect", lambda *a, **k: Connection(results))


@pytest.mark.parametrize("worker,lease", [("", 120), ("worker", 29), ("worker", 901)])
def test_claim_rejects_invalid_worker_lease(worker: str, lease: int) -> None:
    with pytest.raises(ValueError, match="lease configuration"):
        outbox.claim_receipt_request("db", worker, lease)


def test_claim_handles_idle_failed_reset_and_missing_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect(monkeypatch, [Result(None)])
    assert outbox.claim_receipt_request("db", "worker") is None
    claimed = {
        key: value
        for key, value in request().__dict__.items()
        if key
        in {
            "request_id",
            "receipt_id",
            "run_id",
            "tenant_id",
            "target_sequence",
            "target_ledger_hash",
            "publish_public",
            "attempts",
            "created_at",
        }
    }
    receipt = {
        "receipt_policy_version": "receipt-v1",
        "source_sha": "b" * 40,
        "image_digest": f"sha256:{'c' * 64}",
        "evaluation_version": "evaluation-v1",
        "synthetic": True,
    }
    connect(monkeypatch, [Result(claimed), Result(receipt)])
    assert outbox.claim_receipt_request("db", "worker") == request()
    connect(monkeypatch, [Result(claimed), Result(None), Result(None)])
    with pytest.raises(RuntimeError, match="no pending receipt"):
        outbox.claim_receipt_request("db", "worker")


@pytest.mark.parametrize(
    "request_update,result_update",
    [
        ({"run_id": UUID(int=99)}, {}),
        ({"target_ledger_hash": "f" * 64}, {}),
        ({"target_sequence": 2}, {}),
        ({"source_sha": "f" * 40}, {}),
        ({"image_digest": f"sha256:{'f' * 64}"}, {}),
        ({"evaluation_version": "other-v1"}, {}),
        ({"receipt_policy_version": "other-v1"}, {}),
        ({}, {"key_thumbprint": "x" * 43}),
        ({}, {"archived": ArchivedBundle("b", "k", "v", "A" * 64)}),
    ],
)
def test_finalize_rejects_every_immutable_binding_mismatch(
    request_update: dict[str, object], result_update: dict[str, object]
) -> None:
    claimed = replace(request(), **request_update)
    result = replace(signed(), **result_update)
    with pytest.raises(ValueError, match="immutable request"):
        outbox.finalize_receipt_request(
            "db", claimed, "worker", manifest(RUN_ID, WORKFLOW_ID, "1" * 64), result
        )


def test_finalize_handles_missing_stale_delivered_and_lost_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    claimed, receipt_manifest, result = (
        request(),
        manifest(RUN_ID, WORKFLOW_ID, "1" * 64),
        signed(),
    )
    connect(monkeypatch, [Result(None)])
    assert not outbox.finalize_receipt_request("db", claimed, "worker", receipt_manifest, result)
    expected = {
        "manifest_digest": result.manifest_digest,
        "bundle_digest": result.archived.bundle_digest,
        "jws_compact": result.jws_compact,
        "key_thumbprint": result.key_thumbprint,
        "bundle_object_key": result.archived.object_key,
        "s3_version_id": result.archived.version_id,
    }
    connect(monkeypatch, [Result({"status": "delivered", "claimed_by": None}), Result(None)])
    assert not outbox.finalize_receipt_request("db", claimed, "worker", receipt_manifest, result)
    connect(
        monkeypatch,
        [Result({"status": "delivered", "claimed_by": None}), Result(expected)],
    )
    assert outbox.finalize_receipt_request("db", claimed, "worker", receipt_manifest, result)
    connect(monkeypatch, [Result({"status": "pending", "claimed_by": "worker"})])
    assert not outbox.finalize_receipt_request("db", claimed, "worker", receipt_manifest, result)
    connect(
        monkeypatch,
        [Result({"status": "processing", "claimed_by": "worker"}), Result(rowcount=0)],
    )
    assert not outbox.finalize_receipt_request("db", claimed, "worker", receipt_manifest, result)
    connect(
        monkeypatch,
        [
            Result({"status": "processing", "claimed_by": "worker"}),
            Result(rowcount=1),
            Result(rowcount=0),
        ],
    )
    with pytest.raises(RuntimeError, match="lease was lost"):
        outbox.finalize_receipt_request("db", claimed, "worker", receipt_manifest, result)


@pytest.mark.parametrize("code,max_attempts", [("", 8), ("X" * 101, 8), ("ERROR", 0)])
def test_release_failure_rejects_invalid_policy(code: str, max_attempts: int) -> None:
    with pytest.raises(ValueError, match="failure policy"):
        outbox.release_receipt_failure("db", request(), "worker", code, max_attempts=max_attempts)


def test_release_failure_handles_lost_request_and_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connect(monkeypatch, [Result(rowcount=0)])
    assert not outbox.release_receipt_failure("db", request(), "worker", "ERROR")
    connect(monkeypatch, [Result(rowcount=1), Result(rowcount=0)])
    with pytest.raises(RuntimeError, match="lost immutable target"):
        outbox.release_receipt_failure("db", request(), "worker", "ERROR")
