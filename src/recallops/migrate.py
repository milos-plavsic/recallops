import hashlib
import os
from pathlib import Path

import psycopg


def apply_migrations(database_url: str, directory: Path) -> list[str]:
    applied: list[str] = []
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
        connection.commit()
        for path in sorted(directory.glob("*.sql")):
            sql = path.read_text(encoding="utf-8")
            digest = hashlib.sha256(sql.encode()).hexdigest()
            with connection.transaction(), connection.cursor() as cursor:
                cursor.execute(
                    "SELECT sha256 FROM schema_migrations WHERE name = %s FOR UPDATE",
                    (path.name,),
                )
                row = cursor.fetchone()
                if row:
                    if row[0] != digest:
                        raise RuntimeError(f"migration changed after application: {path.name}")
                    continue
                cursor.execute(sql)
                cursor.execute(
                    "INSERT INTO schema_migrations (name, sha256) VALUES (%s, %s)",
                    (path.name, digest),
                )
                applied.append(path.name)
    return applied


def main() -> None:
    database_url = os.environ["RECALLOPS_DATABASE_URL"]
    directory = Path(os.getenv("RECALLOPS_MIGRATIONS_DIR", "/app/migrations"))
    for name in apply_migrations(database_url, directory):
        print(f"applied {name}")
