"""Direct CockroachDB authorization and tenant-integrity verification.

This verifier deliberately runs below the HTTP and repository layers. It proves that
the runtime roles have exactly the intended grants and that every cross-tenant
relationship is rejected by a named database constraint.
"""

import argparse
import hashlib
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
    ("recallops_api", "activity_observations", "INSERT"),
    ("recallops_api", "activity_observations", "SELECT"),
    ("recallops_api", "approvals", "INSERT"),
    ("recallops_api", "approvals", "SELECT"),
    ("recallops_api", "authority_events", "INSERT"),
    ("recallops_api", "authority_events", "SELECT"),
    ("recallops_api", "authority_ledger_heads", "INSERT"),
    ("recallops_api", "authority_ledger_heads", "SELECT"),
    ("recallops_api", "authority_ledger_heads", "UPDATE"),
    ("recallops_api", "authority_receipts", "INSERT"),
    ("recallops_api", "authority_receipts", "SELECT"),
    ("recallops_api", "authority_receipts", "UPDATE"),
    ("recallops_api", "evidence_outbox", "INSERT"),
    ("recallops_api", "execution_attestations", "INSERT"),
    ("recallops_api", "execution_attestations", "SELECT"),
    ("recallops_api", "execution_attestations", "UPDATE"),
    ("recallops_api", "incidents", "INSERT"),
    ("recallops_api", "incidents", "SELECT"),
    ("recallops_api", "incidents", "UPDATE"),
    ("recallops_api", "judge_auth_attempts", "INSERT"),
    ("recallops_api", "judge_auth_attempts", "SELECT"),
    ("recallops_api", "judge_auth_attempts", "UPDATE"),
    ("recallops_api", "judge_sessions", "INSERT"),
    ("recallops_api", "judge_sessions", "SELECT"),
    ("recallops_api", "judge_sessions", "UPDATE"),
    ("recallops_api", "judge_runs", "INSERT"),
    ("recallops_api", "judge_runs", "SELECT"),
    ("recallops_api", "judge_runs", "UPDATE"),
    ("recallops_api", "memories", "INSERT"),
    ("recallops_api", "memories", "SELECT"),
    ("recallops_api", "memories", "UPDATE"),
    ("recallops_api", "memory_events", "INSERT"),
    ("recallops_api", "postcheck_assessments", "INSERT"),
    ("recallops_api", "postcheck_assessments", "SELECT"),
    ("recallops_api", "postcheck_observations", "INSERT"),
    ("recallops_api", "postcheck_observations", "SELECT"),
    ("recallops_api", "postcheck_policy_verdicts", "INSERT"),
    ("recallops_api", "postcheck_policy_verdicts", "SELECT"),
    ("recallops_api", "review_handoffs", "INSERT"),
    ("recallops_api", "review_handoffs", "SELECT"),
    ("recallops_api", "review_handoffs", "UPDATE"),
    ("recallops_api", "release_evidence_records", "SELECT"),
    ("recallops_api", "receipt_requests", "INSERT"),
    ("recallops_api", "sandbox_executions", "INSERT"),
    ("recallops_api", "sandbox_executions", "SELECT"),
    ("recallops_api", "webmcp_workflows", "INSERT"),
    ("recallops_api", "webmcp_workflows", "SELECT"),
    ("recallops_api", "webmcp_workflows", "UPDATE"),
    ("recallops_api", "webmcp_idempotency", "INSERT"),
    ("recallops_api", "webmcp_idempotency", "SELECT"),
    ("recallops_api", "webmcp_idempotency", "UPDATE"),
    ("recallops_outbox", "evidence_outbox", "SELECT"),
    ("recallops_outbox", "evidence_outbox", "UPDATE"),
    ("recallops_outbox", "authority_events", "SELECT"),
    ("recallops_outbox", "authority_ledger_heads", "SELECT"),
    ("recallops_outbox", "authority_receipts", "INSERT"),
    ("recallops_outbox", "authority_receipts", "SELECT"),
    ("recallops_outbox", "authority_receipts", "UPDATE"),
    ("recallops_outbox", "judge_runs", "SELECT"),
    ("recallops_outbox", "release_evidence_records", "INSERT"),
    ("recallops_outbox", "release_evidence_records", "SELECT"),
    ("recallops_outbox", "release_evidence_records", "UPDATE"),
    ("recallops_outbox", "receipt_requests", "SELECT"),
    ("recallops_outbox", "receipt_requests", "UPDATE"),
}


def _vector() -> str:
    return "[" + ",".join(["0"] * 1024) + "]"


def _seed_boundary_rows(
    cursor: psycopg.Cursor[Any],
) -> tuple[UUID, UUID, UUID, UUID, UUID, UUID, UUID, UUID, UUID]:
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
                outcome_score, confidence, memory_digest, embedding)
               VALUES (%s, %s, 'boundary-service', '1.0.0', 'probe', 'inspect',
                       'probe', 1, 0.5, %s, %s::VECTOR)""",
            (memory_id, tenant, hashlib.sha256(str(memory_id).encode()).hexdigest(), _vector()),
        )
    execution_id, observation_id = uuid4(), uuid4()
    cursor.execute(
        """INSERT INTO sandbox_executions
           (id, incident_id, tenant_id, actor_id, proposal_hash, action_id,
            simulator_version, idempotency_key, before_metrics, after_metrics,
            execution_digest)
           VALUES (%s,%s,'boundary_a','probe',%s,
                   'checkout.reduce_concurrency_and_recycle.v1','probe-v1','boundary-execution',
                   '{}'::JSONB,'{}'::JSONB,%s)""",
        (execution_id, incident_a, "0" * 64, "1" * 64),
    )
    cursor.execute(
        """INSERT INTO postcheck_observations
           (id, execution_id, incident_id, tenant_id, proposal_hash, execution_digest,
            source, observation_window_seconds, before_metrics, after_metrics,
            observation_digest)
           VALUES (%s,%s,%s,'boundary_a',%s,%s,'probe',60,
                   '{}'::JSONB,'{}'::JSONB,%s)""",
        (observation_id, execution_id, incident_a, "0" * 64, "1" * 64, "2" * 64),
    )
    run_a, run_b = uuid4(), uuid4()
    for incident_id, run_id, tenant in (
        (incident_a, run_a, "boundary_a"),
        (incident_b, run_b, "boundary_b"),
    ):
        cursor.execute(
            """INSERT INTO webmcp_workflows (workflow_id,tenant_id,state,epoch)
            VALUES (%s,%s,'INVESTIGATING',1)""",
            (incident_id, tenant),
        )
        cursor.execute(
            """INSERT INTO judge_runs
            (run_id,tenant_id,generation,scenario_version,source_incident_id,status,
             operator_subject,build_sha,capability_policy_version,expires_at)
            VALUES (%s,%s,1,'boundary-v1',%s,'active','operator','build','policy',
                    now() + interval '5 minutes')""",
            (run_id, tenant, incident_id),
        )
    authority_event_a = uuid4()
    cursor.execute(
        """INSERT INTO authority_events
        (event_id,run_id,tenant_id,sequence,recorded_at,event_type,outcome,actor_subject,
         actor_role,channel,workflow_id,epoch_before,epoch_after,state_before,state_after,
         capabilities_before,capabilities_after,reason_code,display_summary,policy_version,
         build_sha,previous_event_hash,event_hash)
        VALUES (%s,%s,'boundary_a',1,now(),'probe','accepted','probe','system','system',
        %s,1,2,'INVESTIGATING','INVESTIGATING','[]','[]','PROBE','boundary probe',
        'probe','probe',%s,%s)""",
        (authority_event_a, run_a, incident_a, "0" * 64, "9" * 64),
    )
    return (
        incident_a,
        incident_b,
        memory_a,
        memory_b,
        execution_id,
        observation_id,
        run_a,
        run_b,
        authority_event_a,
    )


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
                (
                    incident_a,
                    incident_b,
                    memory_a,
                    memory_b,
                    execution_a,
                    observation_a,
                    run_a,
                    run_b,
                    authority_event_a,
                ) = _seed_boundary_rows(cursor)
            checks = [
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO approvals
                       (incident_id, tenant_id, actor_id, approved, proposal_hash, reason)
                       VALUES (%s, 'boundary_b', 'probe', true, %s, 'boundary probe')""",
                    (incident_a, "0" * 64),
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
                        to_state, memory_digest)
                       VALUES (%s, %s, 'boundary_b', 'probe', 'quarantine',
                               'boundary probe', 'active', 'quarantined', %s)""",
                    (uuid4(), memory_a, "e" * 64),
                    "memory_events_memory_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO memories
                       (id, tenant_id, service, service_version, symptom, action, outcome,
                        outcome_score, confidence, source_incident_id, memory_digest, embedding)
                       VALUES (%s, 'boundary_b', 'boundary-service', '1.0.0', 'probe',
                               'inspect', 'probe', 1, 0.5, %s, %s, %s::VECTOR)""",
                    (uuid4(), incident_a, "f" * 64, _vector()),
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
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO sandbox_executions
                       (id, incident_id, tenant_id, actor_id, proposal_hash, action_id,
                        simulator_version, idempotency_key, before_metrics, after_metrics,
                        execution_digest)
                       VALUES (%s,%s,'boundary_b','probe',%s,
                       'checkout.reduce_concurrency_and_recycle.v1','probe-v1','cross-sandbox',
                       '{}'::JSONB,'{}'::JSONB,%s)""",
                    (uuid4(), incident_a, "0" * 64, "1" * 64),
                    "sandbox_execution_incident_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO postcheck_observations
                       (id, execution_id, incident_id, tenant_id, proposal_hash,
                        execution_digest, source, observation_window_seconds, before_metrics,
                        after_metrics, observation_digest)
                       VALUES (%s,%s,%s,'boundary_b',%s,%s,'probe',60,
                       '{}'::JSONB,'{}'::JSONB,%s)""",
                    (uuid4(), execution_a, incident_b, "0" * 64, "1" * 64, "2" * 64),
                    "postcheck_execution_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO postcheck_policy_verdicts
                       (observation_id, incident_id, tenant_id, classification, policy_version,
                        checks_passed, checks_failed, observation_digest)
                       VALUES (%s,%s,'boundary_b','recovered','probe-v1','[]'::JSONB,
                       '[]'::JSONB,%s)""",
                    (observation_a, incident_b, "2" * 64),
                    "verdict_observation_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO postcheck_assessments
                       (id, observation_id, incident_id, tenant_id, agent_subject,
                        classification, rationale, observation_digest)
                       VALUES (%s,%s,%s,'boundary_b','probe','recovered','probe',%s)""",
                    (uuid4(), observation_a, incident_b, "2" * 64),
                    "assessment_observation_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO authority_ledger_heads
                    (run_id,tenant_id,ledger_version) VALUES (%s,'boundary_b','probe')""",
                    (run_a,),
                    "authority_ledger_head_run_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO authority_events
                    (event_id,run_id,tenant_id,sequence,recorded_at,event_type,outcome,
                     actor_subject,actor_role,channel,workflow_id,epoch_before,epoch_after,
                     state_before,state_after,capabilities_before,capabilities_after,reason_code,
                     display_summary,policy_version,build_sha,previous_event_hash,event_hash)
                    VALUES (%s,%s,'boundary_b',1,now(),'probe','accepted','probe','system',
                    'system',%s,1,2,'INVESTIGATING','INVESTIGATING','[]','[]','PROBE',
                    'boundary probe','probe','probe',%s,%s)""",
                    (uuid4(), run_a, incident_b, "0" * 64, "a" * 64),
                    "authority_events_run_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO activity_observations
                    (activity_id,run_id,tenant_id,workflow_id,source,actor_subject,
                     activity_type,outcome,display_summary,build_sha)
                    VALUES (%s,%s,'boundary_b',%s,'server','probe','probe','observed',
                    'boundary probe','probe')""",
                    (uuid4(), run_a, incident_b),
                    "activity_observations_run_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO activity_observations
                    (activity_id,run_id,tenant_id,workflow_id,source,actor_subject,
                     activity_type,outcome,display_summary,authority_event_id,build_sha)
                    VALUES (%s,%s,'boundary_b',%s,'server','probe','probe','observed',
                    'boundary probe',%s,'probe')""",
                    (uuid4(), run_b, incident_b, authority_event_a),
                    "activity_observations_authority_event_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO webmcp_idempotency
                    (run_id,tenant_id,route,idempotency_key,request_digest)
                    VALUES (%s,'boundary_b','proposal','boundary-probe-key',%s)""",
                    (run_a, "2" * 64),
                    "webmcp_idempotency_run_tenant_fk",
                ),
                _expect_fk_rejection(
                    connection,
                    """INSERT INTO authority_receipts
                    (receipt_id,run_id,tenant_id,ledger_head_hash,ledger_last_sequence,
                     receipt_policy_version,source_sha,image_digest,evaluation_version,status)
                    VALUES (%s,%s,'boundary_b',%s,1,'receipt-v1',%s,%s,'eval-v1','pending')""",
                    (uuid4(), run_a, "3" * 64, "a" * 40, f"sha256:{'b' * 64}"),
                    "authority_receipts_run_tenant_fk",
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
        ("recallops_api", "DELETE FROM webmcp_idempotency WHERE false"),
        ("recallops_api", "DELETE FROM judge_sessions WHERE false"),
        ("recallops_api", "DELETE FROM judge_runs WHERE false"),
        ("recallops_api", "DELETE FROM review_handoffs WHERE false"),
        ("recallops_api", "UPDATE authority_events SET reason_code=reason_code WHERE false"),
        ("recallops_api", "DELETE FROM authority_events WHERE false"),
        ("recallops_api", "DELETE FROM authority_ledger_heads WHERE false"),
        ("recallops_api", "UPDATE activity_observations SET outcome=outcome WHERE false"),
        ("recallops_api", "DELETE FROM activity_observations WHERE false"),
        ("recallops_api", "DELETE FROM authority_receipts WHERE false"),
        ("recallops_api", "SELECT * FROM receipt_requests WHERE false"),
        ("recallops_api", "UPDATE receipt_requests SET status=status WHERE false"),
        ("recallops_api", "UPDATE release_evidence_records SET release_id=release_id WHERE false"),
        ("recallops_api", "DELETE FROM release_evidence_records WHERE false"),
        ("recallops_api", "UPDATE sandbox_executions SET actor_id=actor_id WHERE false"),
        ("recallops_api", "DELETE FROM sandbox_executions WHERE false"),
        ("recallops_api", "UPDATE postcheck_observations SET source=source WHERE false"),
        ("recallops_api", "DELETE FROM postcheck_observations WHERE false"),
        (
            "recallops_api",
            "UPDATE postcheck_policy_verdicts SET policy_version=policy_version WHERE false",
        ),
        ("recallops_api", "DELETE FROM postcheck_policy_verdicts WHERE false"),
        ("recallops_api", "UPDATE postcheck_assessments SET rationale=rationale WHERE false"),
        ("recallops_api", "DELETE FROM postcheck_assessments WHERE false"),
        ("recallops_outbox", "SELECT * FROM incidents LIMIT 0"),
        ("recallops_outbox", "INSERT INTO incidents DEFAULT VALUES"),
        ("recallops_outbox", "INSERT INTO authority_events DEFAULT VALUES"),
        ("recallops_outbox", "UPDATE judge_runs SET status=status WHERE false"),
        ("recallops_outbox", "DELETE FROM authority_receipts WHERE false"),
        ("recallops_outbox", "INSERT INTO receipt_requests DEFAULT VALUES"),
        ("recallops_outbox", "DELETE FROM receipt_requests WHERE false"),
        ("recallops_outbox", "DELETE FROM release_evidence_records WHERE false"),
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
