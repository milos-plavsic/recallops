"""Lease-safe receipt request finalization against CockroachDB."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

from recallops.authority_archive import ArchivedBundle
from recallops.receipts import JOSE_ALGORITHM, ReceiptManifest


@dataclass(frozen=True)
class ReceiptRequest:
    request_id: UUID
    receipt_id: UUID
    run_id: UUID
    tenant_id: str
    target_sequence: int
    target_ledger_hash: str
    publish_public: bool
    attempts: int
    receipt_policy_version: str
    source_sha: str
    image_digest: str
    evaluation_version: str


@dataclass(frozen=True)
class SignedReceiptResult:
    manifest_digest: str
    jws_compact: str
    key_thumbprint: str
    archived: ArchivedBundle


def claim_receipt_request(
    database_url: str, worker_id: str, lease_seconds: int = 120
) -> ReceiptRequest | None:
    if not worker_id or lease_seconds < 30 or lease_seconds > 900:
        raise ValueError("receipt worker lease configuration is invalid")
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        row = connection.execute(
            """UPDATE receipt_requests SET status='processing',claimed_by=%s,
              claimed_until=now() + (%s * interval '1 second'),attempts=attempts+1,
              last_error_code=NULL
            WHERE request_id = (
              SELECT request_id FROM receipt_requests
              WHERE available_at <= now() AND dead_lettered_at IS NULL
                AND (status='pending' OR (status='processing' AND claimed_until < now()))
              ORDER BY created_at,request_id LIMIT 1 FOR UPDATE
            )
            RETURNING request_id,receipt_id,run_id,tenant_id,target_sequence,
              target_ledger_hash,publish_public,attempts""",
            (worker_id, lease_seconds),
        ).fetchone()
        if row is None:
            return None
        receipt = connection.execute(
            """UPDATE authority_receipts SET status='pending',failure_code=NULL
            WHERE receipt_id=%s AND run_id=%s AND tenant_id=%s AND status='failed'
            RETURNING receipt_policy_version,source_sha,image_digest,evaluation_version""",
            (row["receipt_id"], row["run_id"], row["tenant_id"]),
        ).fetchone()
        if receipt is None:
            receipt = connection.execute(
                """SELECT receipt_policy_version,source_sha,image_digest,evaluation_version
                FROM authority_receipts WHERE receipt_id=%s AND run_id=%s AND tenant_id=%s
                AND status='pending'""",
                (row["receipt_id"], row["run_id"], row["tenant_id"]),
            ).fetchone()
        if receipt is None:
            raise RuntimeError("claimable request has no pending receipt")
    return ReceiptRequest(**dict(row), **dict(receipt))


def finalize_receipt_request(
    database_url: str,
    request: ReceiptRequest,
    worker_id: str,
    manifest: ReceiptManifest,
    result: SignedReceiptResult,
) -> bool:
    """Atomically record one exact signed object and deliver its leased request."""
    if (
        manifest.run_id != request.run_id
        or manifest.ledger_head_hash != request.target_ledger_hash
        or int(manifest.event_count) != request.target_sequence
        or manifest.release.source_sha != request.source_sha
        or manifest.release.image_digest != request.image_digest
        or manifest.release.evaluation_version != request.evaluation_version
        or manifest.receipt_policy_version != request.receipt_policy_version
        or manifest.key_thumbprint != result.key_thumbprint
        or re.fullmatch(r"[a-f0-9]{64}", result.archived.bundle_digest) is None
    ):
        raise ValueError("signed receipt result differs from claimed immutable request")
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        locked = connection.execute(
            """SELECT status,claimed_by FROM receipt_requests
            WHERE request_id=%s AND receipt_id=%s FOR UPDATE""",
            (request.request_id, request.receipt_id),
        ).fetchone()
        if locked is None:
            return False
        if locked["status"] == "delivered":
            existing = connection.execute(
                """SELECT manifest_digest,bundle_digest,jws_compact,key_thumbprint,
                bundle_object_key,s3_version_id FROM authority_receipts WHERE receipt_id=%s""",
                (request.receipt_id,),
            ).fetchone()
            expected = (
                result.manifest_digest,
                result.archived.bundle_digest,
                result.jws_compact,
                result.key_thumbprint,
                result.archived.object_key,
                result.archived.version_id,
            )
            return existing is not None and tuple(existing.values()) == expected
        if locked["status"] != "processing" or locked["claimed_by"] != worker_id:
            return False
        updated = connection.execute(
            """UPDATE authority_receipts SET status='signed',manifest_digest=%s,
              bundle_digest=%s,jws_compact=%s,key_thumbprint=%s,signing_algorithm=%s,
              bundle_object_key=%s,s3_version_id=%s,signed_at=now(),failure_code=NULL,
              public_at=CASE WHEN synthetic AND %s THEN now() ELSE NULL END
            WHERE receipt_id=%s AND run_id=%s AND tenant_id=%s AND status='pending'
              AND ledger_head_hash=%s AND ledger_last_sequence=%s
              AND receipt_policy_version=%s AND source_sha=%s AND image_digest=%s
              AND evaluation_version=%s""",
            (
                result.manifest_digest,
                result.archived.bundle_digest,
                result.jws_compact,
                result.key_thumbprint,
                JOSE_ALGORITHM,
                result.archived.object_key,
                result.archived.version_id,
                request.publish_public,
                request.receipt_id,
                request.run_id,
                request.tenant_id,
                request.target_ledger_hash,
                request.target_sequence,
                request.receipt_policy_version,
                request.source_sha,
                request.image_digest,
                request.evaluation_version,
            ),
        )
        if updated.rowcount != 1:
            return False
        delivered = connection.execute(
            """UPDATE receipt_requests SET status='delivered',delivered_at=now(),
              claimed_by=NULL,claimed_until=NULL,last_error_code=NULL
            WHERE request_id=%s AND status='processing' AND claimed_by=%s""",
            (request.request_id, worker_id),
        )
        if delivered.rowcount != 1:
            raise RuntimeError("receipt request lease was lost during finalization")
        return True


def release_receipt_failure(
    database_url: str,
    request: ReceiptRequest,
    worker_id: str,
    failure_code: str,
    *,
    max_attempts: int = 8,
) -> bool:
    if not failure_code or len(failure_code) > 100 or max_attempts < 1:
        raise ValueError("receipt failure policy is invalid")
    terminal = request.attempts >= max_attempts
    delay = min(300, 2 ** min(request.attempts, 8))
    available = datetime.now(UTC) + timedelta(seconds=delay)
    with psycopg.connect(database_url) as connection:
        request_update = connection.execute(
            """UPDATE receipt_requests SET status=%s,available_at=%s,claimed_by=NULL,
              claimed_until=NULL,last_error_code=%s,dead_lettered_at=%s
            WHERE request_id=%s AND status='processing' AND claimed_by=%s""",
            (
                "dead_lettered" if terminal else "pending",
                available,
                failure_code,
                datetime.now(UTC) if terminal else None,
                request.request_id,
                worker_id,
            ),
        )
        if request_update.rowcount != 1:
            return False
        receipt_update = connection.execute(
            """UPDATE authority_receipts SET status='failed',failure_code=%s
            WHERE receipt_id=%s AND status IN ('pending','failed')""",
            (failure_code, request.receipt_id),
        )
        if receipt_update.rowcount != 1:
            raise RuntimeError("receipt failure update lost immutable target")
    return terminal
