import argparse
import os
import socket
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
import structlog
from psycopg.rows import dict_row

from recallops.archive import S3EvidenceArchive
from recallops.config import Settings
from recallops.resilience import DependencyUnavailable

DEFAULT_MAX_ATTEMPTS = 8


def claim(database_url: str, worker_id: str, lease_seconds: int = 120) -> dict[str, Any] | None:
    with (
        psycopg.connect(database_url, row_factory=dict_row) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            """UPDATE evidence_outbox SET claimed_by=%s,
                claimed_until=now() + (%s * INTERVAL '1 second'), attempts=attempts+1
            WHERE id = (
                SELECT id FROM evidence_outbox
                WHERE delivered_at IS NULL AND available_at <= now()
                  AND dead_lettered_at IS NULL
                  AND (claimed_until IS NULL OR claimed_until < now())
                ORDER BY created_at LIMIT 1
            )
            RETURNING id, incident_id, tenant_id, service, service_version, payload,
              attempts""",
            (worker_id, lease_seconds),
        )
        row = cursor.fetchone()
    return dict(row) if row is not None else None


def mark_delivered(database_url: str, message_id: UUID, worker_id: str) -> bool:
    with psycopg.connect(database_url) as connection, connection.cursor() as cursor:
        cursor.execute(
            """UPDATE evidence_outbox SET delivered_at=now(), claimed_by=NULL,
              claimed_until=NULL, last_error=NULL WHERE id=%s AND claimed_by=%s
              AND delivered_at IS NULL""",
            (message_id, worker_id),
        )
        return cursor.rowcount == 1


def status(database_url: str) -> dict[str, int | float | None]:
    """Return bounded, payload-free outbox signals for logs, alarms, and runbooks."""
    with (
        psycopg.connect(database_url, row_factory=dict_row) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            """
            SELECT
              count(*) FILTER (WHERE delivered_at IS NULL AND dead_lettered_at IS NULL)
                AS pending,
              count(*) FILTER (WHERE dead_lettered_at IS NOT NULL) AS dead_lettered,
              max(attempts) FILTER (WHERE delivered_at IS NULL AND dead_lettered_at IS NULL)
                AS max_pending_attempts,
              extract(epoch FROM now() - min(created_at) FILTER (
                WHERE delivered_at IS NULL AND dead_lettered_at IS NULL
              )) AS oldest_pending_age_seconds
            FROM evidence_outbox
            """
        )
        row = cursor.fetchone() or {}
    return {
        "pending": int(row.get("pending") or 0),
        "dead_lettered": int(row.get("dead_lettered") or 0),
        "max_pending_attempts": int(row.get("max_pending_attempts") or 0),
        "oldest_pending_age_seconds": (
            float(row["oldest_pending_age_seconds"])
            if row.get("oldest_pending_age_seconds") is not None
            else None
        ),
    }


def release_failed(
    database_url: str,
    message_id: UUID,
    worker_id: str,
    attempts: int,
    error: str,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> bool:
    """Release a transient failure or dead-letter a terminal one.

    Returns true only when the message has exhausted its retry budget.  The database
    remains the source of truth, so a worker that lost its lease cannot change state.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be positive")
    delay = min(300, 2 ** min(attempts, 8))
    available_at = datetime.now(UTC) + timedelta(seconds=delay)
    with psycopg.connect(database_url) as connection, connection.cursor() as cursor:
        if attempts >= max_attempts:
            cursor.execute(
                """UPDATE evidence_outbox SET dead_lettered_at=now(), claimed_by=NULL,
                  claimed_until=NULL, last_error=%s WHERE id=%s AND claimed_by=%s
                  AND delivered_at IS NULL AND dead_lettered_at IS NULL""",
                (error[:1000], message_id, worker_id),
            )
            return cursor.rowcount == 1
        cursor.execute(
            """UPDATE evidence_outbox SET available_at=%s, claimed_by=NULL,
              claimed_until=NULL, last_error=%s WHERE id=%s AND claimed_by=%s
              AND delivered_at IS NULL AND dead_lettered_at IS NULL""",
            (available_at, error[:1000], message_id, worker_id),
        )
    return False


def deliver_available(
    database_url: str,
    archive: S3EvidenceArchive,
    worker_id: str,
    limit: int,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    lease_seconds: int = 120,
) -> tuple[int, int]:
    delivered = 0
    failed = 0
    for _ in range(limit):
        message = claim(database_url, worker_id, lease_seconds)
        if message is None:
            break
        try:
            archive.archive_payload(
                message["tenant_id"],
                message["incident_id"],
                message["payload"],
                message["service"],
                message["service_version"],
            )
            if not mark_delivered(database_url, message["id"], worker_id):
                raise RuntimeError("outbox lease lost before delivery acknowledgement")
            delivered += 1
        except (DependencyUnavailable, RuntimeError) as error:
            failed += 1
            dead_lettered = release_failed(
                database_url,
                message["id"],
                worker_id,
                message["attempts"],
                str(error),
                max_attempts,
            )
            structlog.get_logger().error(
                "outbox_delivery_failed",
                message_id=str(message["id"]),
                attempts=message["attempts"],
                dead_lettered=dead_lettered,
                error=str(error),
            )
    return delivered, failed


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliver RecallOps evidence outbox messages")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--status", action="store_true", help="print payload-free backlog and dead-letter signals"
    )
    parser.add_argument(
        "--watch", action="store_true", help="continuously deliver messages for a worker service"
    )
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    arguments = parser.parse_args()
    if arguments.limit < 1 or arguments.limit > 1000:
        parser.error("--limit must be between 1 and 1000")
    if arguments.poll_seconds <= 0 or arguments.poll_seconds > 300:
        parser.error("--poll-seconds must be between 0 and 300")
    settings = Settings()
    if arguments.status:
        print(status(settings.database_url))
        return
    if not settings.evidence_bucket:
        parser.error("RECALLOPS_EVIDENCE_BUCKET is required")
    archive = S3EvidenceArchive(
        settings.aws_region,
        settings.evidence_bucket,
        settings.provider_connect_timeout_seconds,
        settings.provider_read_timeout_seconds,
        settings.provider_max_attempts,
        settings.evidence_kms_key_id,
    )
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    while True:
        delivered, failed = deliver_available(
            settings.database_url,
            archive,
            worker_id,
            arguments.limit,
            settings.outbox_max_attempts,
            settings.outbox_lease_seconds,
        )
        if delivered or failed or not arguments.watch:
            print(f"delivered={delivered} failed={failed}", flush=True)
        if not arguments.watch:
            return
        time.sleep(arguments.poll_seconds)


if __name__ == "__main__":
    main()
