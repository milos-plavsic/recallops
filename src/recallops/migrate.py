import hashlib
import os
import time
from pathlib import Path

import psycopg

MAX_SERIALIZATION_RETRIES = 5


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
    for name in apply_migrations(database_url, directory):
        print(f"applied {name}")


if __name__ == "__main__":
    main()
