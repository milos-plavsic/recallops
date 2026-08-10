#!/usr/bin/env python3
"""Capture sanitized schema and DVI query-plan evidence from CockroachDB."""

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg

from recallops.embedding import DeterministicEmbedder

QUERY = """WITH nearest AS MATERIALIZED (
    SELECT id, embedding <=> %s::VECTOR AS distance
    FROM memories@memories_embedding_v2
    WHERE tenant_id = %s AND service = %s AND embedding_space = %s
    ORDER BY embedding <=> %s::VECTOR
    LIMIT %s
)
SELECT memories.id
FROM memories JOIN nearest USING (id)
WHERE tenant_id = %s AND service = %s AND embedding_space = %s
  AND valid AND state = 'active'
ORDER BY nearest.distance
LIMIT %s"""


def _sanitize(plan: list[str], database: str) -> list[str]:
    replacements = {
        "plan-tenant": "[TENANT]",
        "plan-service": "[SERVICE]",
        "deterministic:sha256-feature-hash-1024:v1": "[EMBEDDING_SPACE]",
        database: "[DATABASE]",
    }
    sanitized = []
    for line in plan:
        line = re.sub(r"'\[[0-9.,-]+\]'::VECTOR", "'[VECTOR_REDACTED]'::VECTOR", line)
        for source, target in replacements.items():
            line = line.replace(source, target)
        sanitized.append(line)
    return sanitized


def capture(database_url: str, release_sha: str) -> dict[str, Any]:
    embedder = DeterministicEmbedder()
    vector = "[" + ",".join(map(str, embedder.embed("plan-service synthetic plan probe"))) + "]"
    with psycopg.connect(database_url) as connection:
        identity = connection.execute("SELECT current_database(), version()").fetchone()
        if identity is None:
            raise RuntimeError("database identity query returned no row")
        database, version = identity
        indexes = connection.execute(
            """SELECT index_name, seq_in_index, column_name
               FROM [SHOW INDEXES FROM memories]
               WHERE index_name = 'memories_embedding_v2'
               ORDER BY seq_in_index"""
        ).fetchall()
        column = connection.execute(
            """SELECT data_type FROM information_schema.columns
               WHERE table_schema = 'public' AND table_name = 'memories'
                 AND column_name = 'embedding'"""
        ).fetchone()
        create_row = connection.execute("SHOW CREATE TABLE memories").fetchone()
        if create_row is None:
            raise RuntimeError("SHOW CREATE TABLE returned no row")
        create_table = str(create_row[1])
        migrations: dict[str, str] = dict(
            connection.execute(
                "SELECT name, sha256 FROM schema_migrations ORDER BY name"
            ).fetchall()
        )
        cursor = psycopg.ClientCursor(connection)
        cursor.execute(
            "EXPLAIN " + QUERY,
            (
                vector,
                "plan-tenant",
                "plan-service",
                embedder.space_id,
                vector,
                160,
                "plan-tenant",
                "plan-service",
                embedder.space_id,
                40,
            ),
        )
        plan = _sanitize([str(row[0]) for row in cursor.fetchall()], str(database))
    source_migrations = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in Path("migrations").glob("*.sql")
    }
    index_columns = [str(row[2]) for row in indexes]
    plan_text = "\n".join(plan)
    passed = (
        migrations == source_migrations
        and str(column[0] if column else "").lower() == "vector"
        and "embedding VECTOR(1024)" in create_table
        and index_columns == ["tenant_id", "service", "embedding_space", "embedding", "id"]
        and "vector search" in plan_text
        and "memories@memories_embedding_v2" in plan_text
        and "pred:" in plan_text
        and "valid" in plan_text
        and "state = 'active'" in plan_text
    )
    return {
        "evidence_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "build_sha": release_sha,
        "environment_class": "disposable-managed-cockroach-aws-us-east-1",
        "command": "scripts/capture-cockroach-query-plan.py",
        "database_version": str(version).split(" (", 1)[0],
        "provider": embedder.space_id,
        "query_sha256": hashlib.sha256(QUERY.encode()).hexdigest(),
        "embedding_column": str(column[0] if column else "missing"),
        "embedding_dimension": 1024 if "embedding VECTOR(1024)" in create_table else None,
        "vector_index": {
            "name": "memories_embedding_v2",
            "columns": index_columns,
            "prefix_isolation": ["tenant_id", "service", "embedding_space"],
        },
        "migration_count": len(migrations),
        "migration_checksums_match_source": migrations == source_migrations,
        "redacted_plan": plan,
        "assertions": {
            "distributed_vector_index_used": "vector search" in plan_text,
            "expected_index_used": "memories@memories_embedding_v2" in plan_text,
            "governance_filter_in_sql": "pred:" in plan_text
            and "valid" in plan_text
            and "state = 'active'" in plan_text,
            "no_raw_vectors_or_tenant_values": "plan-tenant" not in plan_text
            and "plan-service" not in plan_text
            and "[0.0," not in plan_text,
        },
        "redaction": (
            "Tenant, service, embedding space, database name, query vector, and rows "
            "are omitted."
        ),
        "pass_criteria": (
            "DVI vector-search plan, SQL governance predicate, vector schema, and "
            "matching migration ledger"
        ),
        "passed": passed,
        "limitations": (
            "The plan uses synthetic rows in a disposable database; optimizer choices "
            "vary with cardinality and statistics."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--database-url", default=os.getenv("RECALLOPS_DATABASE_URL"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or RECALLOPS_DATABASE_URL is required")
    report = capture(args.database_url, args.release_sha)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
