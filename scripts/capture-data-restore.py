#!/usr/bin/env python3
"""Take an encrypted CockroachDB backup, fully restore it, and compare all table data."""

import argparse
import hashlib
import json
import os
import secrets
import time
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg import sql


def normalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    if isinstance(value, (datetime, date, UUID, Decimal)):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


def table_digest(connection: psycopg.Connection[Any], database: str, table: str) -> dict[str, Any]:
    query = sql.SQL("SELECT * FROM {}.public.{}").format(
        sql.Identifier(database), sql.Identifier(table)
    )
    with connection.cursor(row_factory=psycopg.rows.dict_row) as cursor:
        cursor.execute(query)
        rows = [
            json.dumps(normalize(dict(row)), sort_keys=True, separators=(",", ":"))
            for row in cursor.fetchall()
        ]
    rows.sort()
    digest = hashlib.sha256("\n".join(rows).encode()).hexdigest()
    return {"rows": len(rows), "sha256": digest}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--database-url", default=os.getenv("RECALLOPS_DATABASE_URL"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or RECALLOPS_DATABASE_URL is required")
    passphrase = secrets.token_urlsafe(48)
    suffix = uuid4().hex[:12]
    collection = f"userfile:///recallops-evidence-{suffix}"
    restored_database: str | None = None
    started = time.perf_counter()
    with psycopg.connect(args.database_url, autocommit=True) as connection:
        identity = connection.execute("SELECT current_database()").fetchone()
        if identity is None:
            raise RuntimeError("current_database returned no row")
        source_database = str(identity[0])
        restored_database = f"{source_database}_restored_{suffix}"
        tables = [
            str(row[0])
            for row in connection.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_catalog=current_database() AND table_schema='public' "
                "AND table_type='BASE TABLE' ORDER BY table_name"
            ).fetchall()
        ]
        before = {
            table: table_digest(connection, source_database, table) for table in tables
        }
        backup_started = time.perf_counter()
        connection.execute(
            sql.SQL("BACKUP DATABASE {} INTO {} WITH encryption_passphrase={}").format(
                sql.Identifier(source_database),
                sql.Literal(collection),
                sql.Literal(passphrase),
            )
        ).fetchall()
        backup_seconds = time.perf_counter() - backup_started
        backup_paths = connection.execute(
            sql.SQL("SHOW BACKUPS IN {}").format(sql.Literal(collection))
        ).fetchall()
        restore_started = time.perf_counter()
        connection.execute(
            sql.SQL(
                "RESTORE DATABASE {} FROM LATEST IN {} WITH new_db_name={}, "
                "encryption_passphrase={}"
            ).format(
                sql.Identifier(source_database),
                sql.Literal(collection),
                sql.Identifier(restored_database),
                sql.Literal(passphrase),
            )
        ).fetchall()
        restore_seconds = time.perf_counter() - restore_started
        after = {
            table: table_digest(connection, restored_database, table) for table in tables
        }
        connection.execute(
            sql.SQL("DROP DATABASE {} CASCADE").format(sql.Identifier(restored_database))
        )
        restored_database = None

    assertions = {
        "encrypted_backup_created": bool(backup_paths),
        "full_restore_completed": before == after,
        "all_table_row_counts_match": all(
            before[table]["rows"] == after[table]["rows"] for table in tables
        ),
        "all_table_content_digests_match": all(
            before[table]["sha256"] == after[table]["sha256"] for table in tables
        ),
        "restored_database_removed": restored_database is None,
    }
    payload = {
        "evidence_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "build_sha": args.release_sha,
        "environment_class": "disposable-managed-cockroach-aws-us-east-1",
        "command": "scripts/capture-data-restore.py",
        "backup": {
            "encryption": "passphrase-protected CockroachDB backup",
            "collection_count": len(backup_paths),
            "duration_seconds": round(backup_seconds, 6),
        },
        "restore": {
            "duration_seconds": round(restore_seconds, 6),
            "total_drill_seconds": round(time.perf_counter() - started, 6),
            "table_count": len(tables),
            "row_count": sum(item["rows"] for item in before.values()),
            "tables": {
                hashlib.sha256(table.encode()).hexdigest(): before[table] for table in tables
            },
        },
        "assertions": assertions,
        "passed": all(assertions.values()),
        "redaction": (
            "Database, table, collection, credentials, passphrase, rows, and identifiers omitted; "
            "table names replaced by SHA-256 digests"
        ),
        "limitations": (
            "Disposable single-database encrypted userfile backup and full same-cluster restore; "
            "not a cross-cluster or regional disaster-recovery test. The encrypted backup "
            "collection remains subject to CockroachDB userfile retention."
        ),
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not payload["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
