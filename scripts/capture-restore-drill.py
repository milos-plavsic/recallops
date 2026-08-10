#!/usr/bin/env python3
"""Rebuild a disposable Cockroach database from migrations and verify its ledger."""

import argparse
import hashlib
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from recallops.migrate import apply_migrations


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--admin-url", default=os.getenv("RECALLOPS_DATABASE_URL"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.admin_url:
        parser.error("--admin-url or RECALLOPS_DATABASE_URL is required")
    database = f"recallops_restore_{args.release_sha[:12]}"
    started = time.perf_counter()
    with psycopg.connect(args.admin_url, autocommit=True) as connection:
        connection.execute(sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database)))
        connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    parts: dict[str, Any] = {
        key: value
        for key, value in conninfo_to_dict(args.admin_url).items()
        if value is not None
    }
    parts["dbname"] = database
    restore_url = make_conninfo(**parts)
    try:
        applied_names = apply_migrations(restore_url, Path("migrations"))
        source = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in Path("migrations").glob("*.sql")
        }
        with psycopg.connect(restore_url) as connection:
            applied: dict[str, str] = dict(
                connection.execute(
                    "SELECT name, sha256 FROM schema_migrations ORDER BY name"
                ).fetchall()
            )
            ready = connection.execute("SELECT 1").fetchone() == (1,)
        duration = round(time.perf_counter() - started, 3)
        report = {
            "evidence_version": 1,
            "generated_at": datetime.now(UTC).isoformat(),
            "build_sha": args.release_sha,
            "environment_class": "disposable-managed-cockroach-aws-us-east-1",
            "command": "scripts/capture-restore-drill.py",
            "recovery_time_seconds": duration,
            "migration_count": len(applied),
            "assertions": {
                "migration_process_succeeded": len(applied_names) == len(source),
                "migration_ledger_matches_source": applied == source,
                "database_ready": ready,
            },
            "passed": len(applied_names) == len(source) and applied == source and ready,
            "redaction": "Database name, URL, credentials, cluster, account, and rows omitted",
            "limitations": (
                "Schema reconstruction drill on an empty disposable database; data backup restore "
                "and regional disaster recovery are not claimed."
            ),
        }
    finally:
        with psycopg.connect(args.admin_url, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP DATABASE IF EXISTS {}").format(sql.Identifier(database))
            )
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
