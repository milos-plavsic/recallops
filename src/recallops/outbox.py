import argparse
import os
import socket
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import psycopg
import structlog
from psycopg.rows import dict_row

from recallops.archive import S3EvidenceArchive
from recallops.config import Settings
from recallops.resilience import DependencyUnavailable


def claim(database_url: str, worker_id: str) -> dict[str, Any] | None:
    with psycopg.connect(
        database_url, row_factory=dict_row
    ) as connection, connection.cursor() as cursor:
        cursor.execute(
            """UPDATE evidence_outbox SET claimed_by=%s,
                claimed_until=now() + INTERVAL '2 minutes', attempts=attempts+1
            WHERE id = (
                SELECT id FROM evidence_outbox
                WHERE delivered_at IS NULL AND available_at <= now()
                  AND (claimed_until IS NULL OR claimed_until < now())
                ORDER BY created_at LIMIT 1
            )
            RETURNING id, incident_id, tenant_id, service, service_version, payload,
              attempts""",
            (worker_id,),
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


def release_failed(
    database_url: str, message_id: UUID, worker_id: str, attempts: int, error: str
) -> None:
    delay = min(300, 2 ** min(attempts, 8))
    available_at = datetime.now(UTC) + timedelta(seconds=delay)
    with psycopg.connect(database_url) as connection, connection.cursor() as cursor:
        cursor.execute(
            """UPDATE evidence_outbox SET available_at=%s, claimed_by=NULL,
              claimed_until=NULL, last_error=%s WHERE id=%s AND claimed_by=%s
              AND delivered_at IS NULL""",
            (available_at, error[:1000], message_id, worker_id),
        )


def deliver_available(
    database_url: str, archive: S3EvidenceArchive, worker_id: str, limit: int
) -> tuple[int, int]:
    delivered = 0
    failed = 0
    for _ in range(limit):
        message = claim(database_url, worker_id)
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
            release_failed(
                database_url,
                message["id"],
                worker_id,
                message["attempts"],
                str(error),
            )
            structlog.get_logger().error(
                "outbox_delivery_failed", message_id=str(message["id"]), error=str(error)
            )
    return delivered, failed


def main() -> None:
    parser = argparse.ArgumentParser(description="Deliver RecallOps evidence outbox messages")
    parser.add_argument("--limit", type=int, default=100)
    arguments = parser.parse_args()
    if arguments.limit < 1 or arguments.limit > 1000:
        parser.error("--limit must be between 1 and 1000")
    settings = Settings()
    if not settings.evidence_bucket:
        parser.error("RECALLOPS_EVIDENCE_BUCKET is required")
    archive = S3EvidenceArchive(
        settings.aws_region,
        settings.evidence_bucket,
        settings.provider_connect_timeout_seconds,
        settings.provider_read_timeout_seconds,
        settings.provider_max_attempts,
    )
    worker_id = f"{socket.gethostname()}:{os.getpid()}"
    delivered, failed = deliver_available(
        settings.database_url, archive, worker_id, arguments.limit
    )
    print(f"delivered={delivered} failed={failed}")


if __name__ == "__main__":
    main()
