"""Direct CockroachDB authorization and tenant-integrity verification.

This verifier deliberately runs below the HTTP and repository layers. It proves that
the runtime roles have exactly the intended grants and that every cross-tenant
relationship is rejected by a named database constraint.
"""

import argparse
import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
from psycopg import sql

EXPECTED_GRANTS = {
    ("recallops_api", "approvals", "INSERT"),
    ("recallops_api", "approvals", "SELECT"),
    ("recallops_api", "evidence_outbox", "INSERT"),
    ("recallops_api", "execution_attestations", "INSERT"),
    ("recallops_api", "execution_attestations", "SELECT"),
    ("recallops_api", "execution_attestations", "UPDATE"),
    ("recallops_api", "incidents", "INSERT"),
    ("recallops_api", "incidents", "SELECT"),
    ("recallops_api", "incidents", "UPDATE"),
    ("recallops_api", "memories", "INSERT"),
    ("recallops_api", "memories", "SELECT"),
    ("recallops_api", "memories", "UPDATE"),
    ("recallops_api", "memory_events", "INSERT"),
    ("recallops_api", "webmcp_workflows", "INSERT"),
    ("recallops_api", "webmcp_workflows", "SELECT"),
    ("recallops_api", "webmcp_workflows", "UPDATE"),
    ("recallops_outbox", "evidence_outbox", "SELECT"),
    ("recallops_outbox", "evidence_outbox", "UPDATE"),
}


def _vector() -> str:
    return "[" + ",".join(["0"] * 1024) + "]"


def _seed_boundary_rows(cursor: psycopg.Cursor[Any]) -> tuple[UUID, UUID, UUID, UUID]:
    incident_a, incident_b = uuid4(), uuid4()
    memory_a, memory_b = uuid4(), uuid4()
    for incident_id, tenant in ((incident_a, "boundary_a"), (incident_b, "boundary_b")):
        cursor.execute(
            """INSERT INTO incidents
               (id, tenant_id, service, service_version, symptom, idempotency_key,
                status, analysis)
               VALUES (%s, %s, 'boundary-service', '1.0.0', 'probe', %s, 'open', '{}'::JSONB)""",
            (incident_id, tenant, f"boundary-{incident_id}"),
        )
    for memory_id, tenant in ((memory_a, "boundary_a"), (memory_b, "boundary_b")):
        cursor.execute(
            """INSERT INTO memories
               (id, tenant_id, service, service_version, symptom, action, outcome,
                outcome_score, confidence, embedding)
               VALUES (%s, %s, 'boundary-service', '1.0.0', 'probe', 'inspect',
                       'probe', 0, 0.5, %s::VECTOR)""",
            (memory_id, tenant, _vector()),
        )
    return incident_a, incident_b, memory_a, memory_b


def _expect_fk_rejection(
    connection: psycopg.Connection[Any],
    statement: str,
    parameters: Sequence[object],
    expected_constraint: str,
) -> dict[str, str]:
    try:
        # Nested transaction contexts are savepoints, allowing every independent
        # boundary probe to run even after the expected statement failure.
        with connection.transaction(), connection.cursor() as cursor:
            cursor.execute(statement, parameters)
    except psycopg.errors.ForeignKeyViolation as error:
        actual_constraint = error.diag.constraint_name
        if actual_constraint != expected_constraint:
            raise AssertionError(
                f"expected {expected_constraint}, got {actual_constraint or 'unnamed constraint'}"
            ) from error
        return {"constraint": expected_constraint, "result": "rejected"}
    raise AssertionError(f"cross-tenant write unexpectedly passed: {expected_constraint}")


def _verify_cross_tenant_constraints(database_url: str) -> list[dict[str, str]]:
    with psycopg.connect(database_url, autocommit=False) as connection:
        try:
            with connection.cursor() as cursor:
                incident_a, _, memory_a, memory_b = _seed_boundary_rows(cursor)
            checks = [
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO approvals
                       (incident_id, tenant_id, actor_id, approved, reason)
                       VALUES (%s, 'boundary_b', 'probe', true, 'boundary probe')""",
                    (incident_a,),
                    "approvals_incident_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO execution_attestations
                       (incident_id, tenant_id, actor_id, action_hash, action_taken,
                        evidence_refs)
                       VALUES (%s, 'boundary_b', 'probe', %s, 'inspect', '[]'::JSONB)""",
                    (incident_a, "0" * 64),
                    "executions_incident_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO evidence_outbox
                       (id, incident_id, tenant_id, service, service_version, payload)
                       VALUES (%s, %s, 'boundary_b', 'boundary-service', '1.0.0', '{}'::JSONB)""",
                    (uuid4(), incident_a),
                    "outbox_incident_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO memory_events
                       (id, memory_id, tenant_id, actor_id, action, reason, from_state,
                        to_state)
                       VALUES (%s, %s, 'boundary_b', 'probe', 'quarantine',
                               'boundary probe', 'active', 'quarantined')""",
                    (uuid4(), memory_a),
                    "memory_events_memory_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO memories
                       (id, tenant_id, service, service_version, symptom, action, outcome,
                        outcome_score, confidence, source_incident_id, embedding)
                       VALUES (%s, 'boundary_b', 'boundary-service', '1.0.0', 'probe',
                               'inspect', 'probe', 0, 0.5, %s, %s::VECTOR)""",
                    (uuid4(), incident_a, _vector()),
                    "memories_source_incident_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    "UPDATE memories SET superseded_by=%s WHERE id=%s",
                    (memory_b, memory_a),
                    "memories_supersession_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO webmcp_workflows
                       (workflow_id, tenant_id, state, epoch)
                       VALUES (%s, 'boundary_b', 'INVESTIGATING', 1)""",
                    (incident_a,),
                    "webmcp_workflow_incident_fk",
                ),
            ]
        finally:
            # Verification is non-destructive even when pointed at a persistent
            # staging database: all synthetic rows exist only in this transaction.
            connection.rollback()
    return checks


def _verify_exact_grants(cursor: psycopg.Cursor[Any]) -> int:
    cursor.execute(
        """SELECT grantee, table_name, privilege_type
           FROM information_schema.table_privileges
           WHERE grantee IN ('recallops_api', 'recallops_outbox')"""
    )
    actual = {(str(row[0]), str(row[1]), str(row[2])) for row in cursor.fetchall()}
    if actual != EXPECTED_GRANTS:
        missing = sorted(EXPECTED_GRANTS - actual)
        unexpected = sorted(actual - EXPECTED_GRANTS)
        raise AssertionError(f"runtime grant drift: missing={missing}, unexpected={unexpected}")
    return len(actual)


def _verify_role_attributes(cursor: psycopg.Cursor[Any]) -> list[dict[str, object]]:
    cursor.execute(
        """SELECT rolname, rolcanlogin, rolcreaterole, rolcreatedb, rolbypassrls
           FROM pg_catalog.pg_roles
           WHERE rolname IN ('recallops_api', 'recallops_outbox')
           ORDER BY rolname"""
    )
    roles = [
        {
            "role": str(row[0]),
            "login": bool(row[1]),
            "create_role": bool(row[2]),
            "create_database": bool(row[3]),
            "bypass_rls": bool(row[4]),
        }
        for row in cursor.fetchall()
    ]
    if len(roles) != 2 or any(
        role[attribute]
        for role in roles
        for attribute in ("login", "create_role", "create_database", "bypass_rls")
    ):
        raise AssertionError(f"unsafe runtime role attributes: {roles}")
    return roles


def _expect_insufficient_privilege(database_url: str, role: str, statement: str) -> None:
    try:
        with (
            psycopg.connect(database_url, autocommit=True) as connection,
            connection.cursor() as cursor,
        ):
            # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query  # noqa: E501
            cursor.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(role)))
            cursor.execute(statement)
    except psycopg.errors.InsufficientPrivilege:
        return
    raise AssertionError(f"{role} unexpectedly executed: {statement}")


def _verify_runtime_denials(database_url: str) -> list[dict[str, str]]:
    probes = (
        ("recallops_api", "DELETE FROM incidents WHERE false"),
        ("recallops_api", "SELECT * FROM schema_migrations LIMIT 0"),
        ("recallops_api", "UPDATE evidence_outbox SET attempts=attempts WHERE false"),
        ("recallops_api", "CREATE TABLE runtime_privilege_escape (id INT PRIMARY KEY)"),
        ("recallops_api", "DELETE FROM webmcp_workflows WHERE false"),
        ("recallops_outbox", "SELECT * FROM incidents LIMIT 0"),
        ("recallops_outbox", "INSERT INTO incidents DEFAULT VALUES"),
        ("recallops_outbox", "CREATE TABLE worker_privilege_escape (id INT PRIMARY KEY)"),
    )
    results = []
    for role, statement in probes:
        _expect_insufficient_privilege(database_url, role, statement)
        results.append({"role": role, "operation": statement.split()[0], "result": "denied"})
    return results


def verify_database_boundaries(database_url: str) -> dict[str, object]:
    with psycopg.connect(database_url) as connection, connection.cursor() as cursor:
        cursor.execute("SELECT current_database(), version()")
        database, version = cursor.fetchone() or (None, None)
        grant_count = _verify_exact_grants(cursor)
        roles = _verify_role_attributes(cursor)
    constraints = _verify_cross_tenant_constraints(database_url)
    denials = _verify_runtime_denials(database_url)
    return {
        "schema": "recallops.database-boundary-evidence.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "database": str(database),
        "database_version": str(version).split(" (", 1)[0],
        "runtime_roles": roles,
        "exact_runtime_grants": grant_count,
        "cross_tenant_constraints": constraints,
        "runtime_denials": denials,
        "passed": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify CockroachDB runtime grants and direct-SQL tenant constraints"
    )
    parser.add_argument(
        "--database-url",
        default=os.getenv("RECALLOPS_DATABASE_URL"),
        help="Admin/migration connection URL (or set RECALLOPS_DATABASE_URL)",
    )
    parser.add_argument("--output", type=Path, help="Optional sanitized JSON evidence path")
    arguments = parser.parse_args()
    if not arguments.database_url:
        parser.error("--database-url or RECALLOPS_DATABASE_URL is required")
    report = verify_database_boundaries(arguments.database_url)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
