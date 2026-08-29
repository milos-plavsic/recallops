import hashlib
import os
import time
from collections.abc import Mapping
from pathlib import Path

import psycopg

from recallops.release_evidence import ReleaseIdentity

MAX_SERIALIZATION_RETRIES = 5
RELEASE_IDENTITY_ENVIRONMENT = {
    "source_sha": "RECALLOPS_BUILD_SHA",
    "image_digest": "RECALLOPS_RELEASE_IMAGE_DIGEST",
    "release_id": "RECALLOPS_RECEIPT_RELEASE_ID",
    "receipt_key_thumbprint": "RECALLOPS_RECEIPT_KEY_THUMBPRINT",
    "capability_policy_version": "RECALLOPS_CAPABILITY_POLICY_VERSION",
    "receipt_policy_version": "RECALLOPS_RECEIPT_POLICY_VERSION",
    "evaluation_version": "RECALLOPS_EVALUATION_VERSION",
}


def release_identity_from_environment(
    environment: Mapping[str, str],
) -> ReleaseIdentity | None:
    """Load an all-or-none immutable release identity for deployment bootstrap."""
    present = {
        field: environment[name]
        for field, name in RELEASE_IDENTITY_ENVIRONMENT.items()
        if environment.get(name)
    }
    if not present:
        return None
    if len(present) != len(RELEASE_IDENTITY_ENVIRONMENT):
        missing = sorted(
            name
            for field, name in RELEASE_IDENTITY_ENVIRONMENT.items()
            if field not in present
        )
        raise RuntimeError(
            "release evidence bootstrap identity is incomplete; missing " + ", ".join(missing)
        )
    return ReleaseIdentity.model_validate(present)


def register_release_evidence(database_url: str, identity: ReleaseIdentity) -> bool:
    """Create an immutable pending evidence record or verify an exact existing one.

    Returns ``True`` only when this invocation inserted the record. Conflicting
    reuse of a release identifier fails closed. Serialization retries use fresh
    connections so no aborted transaction state can leak between attempts.
    """
    expected = tuple(identity.model_dump().values())
    attempt = 0
    while True:
        try:
            with psycopg.connect(database_url, autocommit=False) as connection:
                with connection.transaction(), connection.cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO release_evidence_records
                        (release_id,source_sha,image_digest,capability_policy_version,
                         receipt_policy_version,evaluation_version,receipt_key_thumbprint,
                         live_proof_status,assurance_status)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,'pending','pending')
                        ON CONFLICT (release_id) DO NOTHING
                        RETURNING release_id""",
                        expected,
                    )
                    inserted = cursor.fetchone() is not None
                    cursor.execute(
                        """SELECT release_id,source_sha,image_digest,
                        capability_policy_version,receipt_policy_version,
                        evaluation_version,receipt_key_thumbprint
                        FROM release_evidence_records WHERE release_id=%s""",
                        (identity.release_id,),
                    )
                    actual = cursor.fetchone()
                    if actual is None or tuple(actual) != expected:
                        raise RuntimeError(
                            "release evidence identity conflicts with immutable existing record"
                        )
                return inserted
        except psycopg.errors.SerializationFailure:
            if attempt == MAX_SERIALIZATION_RETRIES - 1:
                raise
            time.sleep(0.05 * (2**attempt))
            attempt += 1


def apply_migrations(database_url: str, directory: Path) -> list[str]:
    migrations = [
        (path.name, path.read_text(encoding="utf-8")) for path in sorted(directory.glob("*.sql"))
    ]
    with psycopg.connect(database_url, autocommit=False) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    name STRING PRIMARY KEY,
                    sha256 STRING NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            # A durable singleton row serializes every migrator, including ECS tasks
            # starting a new revision concurrently.  This is portable to CockroachDB
            # and avoids relying on PostgreSQL advisory-lock compatibility.
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migration_lock (
                    id INT8 PRIMARY KEY CHECK (id = 1)
                )
                """
            )
            cursor.execute("UPSERT INTO schema_migration_lock (id) VALUES (1)")
        connection.commit()
        # CockroachDB schema changes must become public between migration files.
        # Commit each file separately, while taking the same durable lock inside
        # every transaction. Concurrent migrators may alternate lock ownership,
        # but the checksum ledger makes each step execute exactly once and keeps
        # the globally sorted order.
        applied: list[str] = []
        for name, sql in migrations:
            digest = hashlib.sha256(sql.encode()).hexdigest()
            attempt = 0
            while True:
                try:
                    with connection.transaction(), connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT id FROM schema_migration_lock WHERE id = 1 FOR UPDATE"
                        )
                        cursor.execute(
                            "SELECT sha256 FROM schema_migrations WHERE name = %s FOR UPDATE",
                            (name,),
                        )
                        row = cursor.fetchone()
                        if row:
                            if row[0] != digest:
                                raise RuntimeError(f"migration changed after application: {name}")
                        else:
                            cursor.execute(sql)
                            cursor.execute(
                                "INSERT INTO schema_migrations (name, sha256) VALUES (%s, %s)",
                                (name, digest),
                            )
                            applied.append(name)
                    break
                except psycopg.errors.SerializationFailure:
                    if attempt == MAX_SERIALIZATION_RETRIES - 1:
                        raise
                    # Bounded exponential backoff gives the holder time to commit while
                    # avoiding an unbounded startup loop during a database incident.
                    time.sleep(0.05 * (2**attempt))
                    attempt += 1
        return applied


def main() -> None:
    database_url = os.environ["RECALLOPS_DATABASE_URL"]
    directory = Path(os.getenv("RECALLOPS_MIGRATIONS_DIR", "/app/migrations"))
    release_identity = release_identity_from_environment(os.environ)
    for name in apply_migrations(database_url, directory):
        print(f"applied {name}")
    if release_identity is not None:
        inserted = register_release_evidence(database_url, release_identity)
        outcome = "registered" if inserted else "verified"
        print(f"{outcome} release evidence {release_identity.release_id}")


if __name__ == "__main__":
    main()
