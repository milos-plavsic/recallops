import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from recallops.api import create_app
from recallops.config import Settings
from recallops.db_verify import verify_database_boundaries
from recallops.domain import (
    ApprovalRequest,
    ExecutionAttestationRequest,
    GovernanceAction,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    MemoryState,
    OutcomeObservation,
    ReviewReasonCode,
)
from recallops.embedding import DeterministicEmbedder
from recallops.ledger import (
    ZERO_EVENT_HASH,
    ActivityObservation,
    PostgresAuthorityLedgerRepository,
    verify_event,
)
from recallops.sandbox import SANDBOX_ACTION_COMMAND
from recallops.service import DeterministicReasoner, IncidentService
from recallops.sessions import PostgresJudgeSessionRepository
from recallops.store import PostgresStore
from recallops.workflow import (
    PostgresWorkflowRepository,
    RequestChannel,
    WorkflowConflict,
    WorkflowCoordinator,
    WorkflowSnapshot,
    WorkflowState,
)


def _seed_authority_fixture(database_url: str, suffix: str) -> tuple[str, UUID, UUID]:
    tenant_id = f"ledger_{suffix}_{uuid4().hex[:12]}"
    incident_id, run_id = uuid4(), uuid4()
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            """INSERT INTO incidents
            (id,tenant_id,service,service_version,symptom,idempotency_key,status,analysis)
            VALUES (%s,%s,'checkout','v2.4.1','latency',%s,'open','{}')""",
            (incident_id, tenant_id, f"ledger-{incident_id}"),
        )
        connection.execute(
            """INSERT INTO webmcp_workflows (workflow_id,tenant_id,state,epoch)
            VALUES (%s,%s,'INVESTIGATING',1)""",
            (incident_id, tenant_id),
        )
        connection.execute(
            """INSERT INTO judge_runs
            (run_id,tenant_id,generation,scenario_version,source_incident_id,status,
             operator_subject,build_sha,capability_policy_version,expires_at)
            VALUES (%s,%s,1,'ledger-v1',%s,'active','operator-ledger','build-ledger',
                    'policy-ledger',now() + interval '10 minutes')""",
            (run_id, tenant_id, incident_id),
        )
    return tenant_id, incident_id, run_id


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
@pytest.mark.parametrize(
    "fault_stage",
    [
        "before_domain",
        "after_domain",
        "before_workflow",
        "after_workflow",
        "before_event",
        "after_event",
        "before_head",
        "after_head",
    ],
)
def test_authority_transaction_faults_roll_back_every_boundary(fault_stage: str) -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    tenant_id, incident_id, run_id = _seed_authority_fixture(database_url, fault_stage)
    store = PostgresStore(database_url)

    def fault(stage: str) -> None:
        if stage == fault_stage:
            raise RuntimeError(f"injected at {stage}")

    def mutate(bound_store: PostgresStore, connection: Any) -> None:
        del bound_store
        fault("before_domain")
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE incidents SET status='mitigated' WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            )
        fault("after_domain")
        ledger = PostgresAuthorityLedgerRepository.from_connection(connection, fault)
        WorkflowCoordinator(
            PostgresWorkflowRepository.from_connection(connection), ledger, fault
        ).transition(
            incident_id,
            tenant_id,
            1,
            WorkflowState.INVESTIGATING,
            WorkflowState.AWAITING_OPERATOR_APPROVAL,
            channel=RequestChannel.WEBMCP,
            actor_subject="agent-ledger",
            role="agent",
        )

    try:
        with pytest.raises(RuntimeError, match=fault_stage):
            store.atomic(mutate)
        with psycopg.connect(database_url) as connection:
            incident = connection.execute(
                "SELECT status FROM incidents WHERE id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            ).fetchone()
            workflow = connection.execute(
                "SELECT state,epoch FROM webmcp_workflows WHERE workflow_id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            ).fetchone()
            event_count = connection.execute(
                "SELECT count(*) FROM authority_events WHERE run_id=%s", (run_id,)
            ).fetchone()
            head_count = connection.execute(
                "SELECT count(*) FROM authority_ledger_heads WHERE run_id=%s", (run_id,)
            ).fetchone()
        assert incident == ("open",)
        assert workflow == ("INVESTIGATING", 1)
        assert event_count == (0,) and head_count == (0,)
    finally:
        store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_concurrent_ledger_appends_retry_and_form_one_verifiable_chain() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    tenant_id, incident_id, run_id = _seed_authority_fixture(database_url, "concurrent")
    before = WorkflowSnapshot(
        workflow_id=incident_id,
        tenant_id=tenant_id,
        state=WorkflowState.INVESTIGATING,
        epoch=1,
    )
    after = before.model_copy(
        update={"state": WorkflowState.AWAITING_OPERATOR_APPROVAL, "epoch": 2}
    )
    store = PostgresStore(database_url)

    def append(index: int) -> str:
        def operation(bound_store: PostgresStore, connection: object) -> str:
            del bound_store
            event = PostgresAuthorityLedgerRepository.from_connection(
                connection
            ).append_transition(
                before,
                after,
                actor_subject=f"operator-{index}",
                actor_role="operator",
                channel=RequestChannel.UI,
            )
            assert event is not None
            return event.event_hash

        return store.atomic(operation)

    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            hashes = list(executor.map(append, range(4)))
        events = PostgresAuthorityLedgerRepository(store.pool).list_events(run_id, tenant_id)
        assert len(set(hashes)) == 4
        assert [event.sequence for event in events] == [1, 2, 3, 4]
        previous = ZERO_EVENT_HASH
        for event in events:
            assert verify_event(event, previous)
            previous = event.event_hash
        with psycopg.connect(database_url) as connection:
            head = connection.execute(
                """SELECT last_sequence,last_event_hash FROM authority_ledger_heads
                WHERE run_id=%s AND tenant_id=%s""",
                (run_id, tenant_id),
            ).fetchone()
        assert head == (4, events[-1].event_hash)
    finally:
        store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_activity_observation_cannot_mutate_or_extend_authority() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    tenant_id, incident_id, run_id = _seed_authority_fixture(database_url, "activity")
    store = PostgresStore(database_url)
    repository = PostgresAuthorityLedgerRepository(store.pool)
    try:
        repository.add_activity(
            ActivityObservation(
                run_id=run_id,
                tenant_id=tenant_id,
                workflow_id=incident_id,
                source="browser",
                actor_subject="browser-pseudonym",
                activity_type="tool_withdrawn",
                tool_name="stage_remediation",
                outcome="observed",
                display_summary="Browser reports tool withdrawal",
                build_sha="build-ledger",
            )
        )
        assert repository.list_events(run_id, tenant_id) == []
        timeline = repository.timeline(run_id, tenant_id)
        assert len(timeline) == 1
        assert timeline[0].evidence_class == "supporting_observation"
        with psycopg.connect(database_url) as connection:
            workflow = connection.execute(
                "SELECT state,epoch FROM webmcp_workflows WHERE workflow_id=%s AND tenant_id=%s",
                (incident_id, tenant_id),
            ).fetchone()
            heads = connection.execute(
                "SELECT count(*) FROM authority_ledger_heads WHERE run_id=%s", (run_id,)
            ).fetchone()
        assert workflow == ("INVESTIGATING", 1)
        assert heads == (0,)
    finally:
        store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_memory_evidence_is_immutable_and_lifecycle_predicates_precede_ranking() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    tenant = f"governance_{uuid4().hex[:16]}"
    now = datetime.now(UTC)
    embedder = DeterministicEmbedder()

    def candidate(
        suffix: str,
        *,
        state: MemoryState = MemoryState.ACTIVE,
        score: float = 1.0,
        expires_at: datetime | None = None,
    ) -> Memory:
        return Memory(
            tenant_id=tenant,
            service="checkout",
            service_version="v2.4.1",
            symptom=f"checkout latency {suffix}",
            action=f"bounded action {suffix}",
            outcome="measured outcome",
            outcome_score=score,
            confidence=0.95,
            valid=state is MemoryState.ACTIVE,
            state=state,
            observed_by="agent-assessor",
            reviewed_by="reviewer-a" if state is MemoryState.ACTIVE else None,
            reviewed_at=now if state is MemoryState.ACTIVE else None,
            expires_at=expires_at,
            embedding=embedder.embed(f"checkout latency {suffix}"),
        )

    store = PostgresStore(database_url)
    active = candidate("active")
    pending = candidate("pending", state=MemoryState.PENDING_REVIEW)
    expired = candidate("expired", expires_at=now - timedelta(seconds=1))
    negative = candidate("negative", score=-1)
    try:
        for item in (active, pending, expired, negative):
            store.add_memory(item)
        assert {item.id for item in store.list_memories(tenant, "checkout")} == {
            active.id,
            pending.id,
            expired.id,
            negative.id,
        }
        incident = IncidentCreate(
            tenant_id=tenant,
            service="checkout",
            service_version="v2.4.1",
            symptom="checkout latency active",
            idempotency_key=f"governance-{uuid4().hex}",
        )
        found = store.find_memories(
            incident,
            embedder.embed("checkout latency active"),
            embedder.space_id,
            10,
        )
        assert {item.memory.id for item in found} == {active.id, negative.id}

        original_digest = pending.memory_digest
        certified = store.govern_memory(
            pending.id,
            MemoryGovernanceRequest(
                tenant_id=tenant,
                actor_id="reviewer-b",
                action=GovernanceAction.CERTIFY,
                reason="evidence accepted",
                reason_code=ReviewReasonCode.EVIDENCE_ACCEPTED,
            ),
        )
        assert certified is not None
        assert certified.state is MemoryState.ACTIVE
        assert certified.memory_digest == original_digest

        with (
            psycopg.connect(database_url) as connection,
            pytest.raises(psycopg.errors.CheckViolation, match="memory evidence is immutable"),
        ):
            connection.execute(
                "UPDATE memories SET action='tampered' WHERE id=%s AND tenant_id=%s",
                (active.id, tenant),
            )

        inconclusive = candidate("inconclusive", score=0)
        with pytest.raises(psycopg.errors.CheckViolation):
            store.add_memory(inconclusive)

        revoked = store.govern_memory(
            certified.id,
            MemoryGovernanceRequest(
                tenant_id=tenant,
                actor_id="reviewer-c",
                action=GovernanceAction.REVOKE,
                reason="new contradictory evidence",
                reason_code=ReviewReasonCode.NEW_CONTRADICTORY_EVIDENCE,
            ),
        )
        assert revoked is not None and revoked.state is MemoryState.REVOKED
        assert store.get_memory(revoked.id, tenant) is not None
        assert revoked.id not in {
            item.memory.id
            for item in store.find_memories(
                incident,
                embedder.embed("checkout latency pending"),
                embedder.space_id,
                10,
            )
        }
    finally:
        store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_runtime_grants_and_cross_tenant_constraints() -> None:
    report = verify_database_boundaries(os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"])

    assert report["passed"] is True
    assert report["exact_runtime_grants"] == 48
    assert len(report["cross_tenant_constraints"]) == 16
    assert len(report["runtime_denials"]) == 25


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_judge_run_session_and_handoff_composite_relationships_fail_closed() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    run_a, run_b, incident_a, incident_b, memory_a, memory_b = (uuid4() for _ in range(6))
    now = datetime.now(UTC)
    vector = "[" + ",".join(["0"] * 1024) + "]"
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "judge_auth_attempts, review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, postcheck_observations, "
            "sandbox_executions, webmcp_workflows, memory_events, execution_attestations, "
            "approvals, evidence_outbox, memories, incidents"
        )
        for incident_id, memory_id, tenant, run_id in (
            (incident_a, memory_a, "judge_boundary_a", run_a),
            (incident_b, memory_b, "judge_boundary_b", run_b),
        ):
            connection.execute(
                """INSERT INTO incidents
                (id, tenant_id, service, service_version, symptom, idempotency_key,
                 status, analysis) VALUES (%s,%s,'checkout','v1','latency',%s,'open','{}')""",
                (incident_id, tenant, f"fixture-{run_id}"),
            )
            connection.execute(
                """INSERT INTO webmcp_workflows
                (workflow_id, tenant_id, state, epoch)
                VALUES (%s,%s,'PENDING_REVIEW',1)""",
                (incident_id, tenant),
            )
            connection.execute(
                """INSERT INTO memories
                (id, tenant_id, service, service_version, symptom, action, outcome,
                 outcome_score, confidence, valid, state, source_incident_id,
                 memory_digest, embedding)
                VALUES (%s,%s,'checkout','v1','latency','inspect','recovered',1,0.9,
                        false,'pending_review',%s,%s,%s::VECTOR)""",
                (
                    memory_id,
                    tenant,
                    incident_id,
                    hashlib.sha256(str(memory_id).encode()).hexdigest(),
                    vector,
                ),
            )
            connection.execute(
                """INSERT INTO judge_runs
                (run_id, tenant_id, generation, scenario_version, source_incident_id,
                 status, operator_subject, build_sha, capability_policy_version, expires_at)
                VALUES (%s,%s,1,'scenario-v1',%s,'active',%s,'abc123','policy-v1',%s)""",
                (run_id, tenant, incident_id, f"operator-{run_id}", now + timedelta(minutes=5)),
            )

        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            connection.execute(
                """INSERT INTO judge_sessions
                (session_hash, csrf_hash, tenant_id, subject, role, expires_at,
                 run_id, session_role, session_generation)
                VALUES (%s,%s,'judge_boundary_b','operator-a','operator',%s,
                        %s,'operator',1)""",
                ("a" * 64, "b" * 64, now + timedelta(minutes=5), run_a),
            )
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            connection.execute(
                """INSERT INTO review_handoffs
                (code_hash, run_id, tenant_id, workflow_id, memory_id, memory_digest,
                 purpose, issued_by_subject, expires_at)
                VALUES (%s,%s,'judge_boundary_a',%s,%s,%s,'initial_review','operator-a',%s)""",
                (
                    "c" * 64,
                    run_a,
                    incident_b,
                    memory_b,
                    "d" * 64,
                    now + timedelta(minutes=5),
                ),
            )


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_postgres_store_complete_governed_memory_lifecycle() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, "
            "postcheck_observations, sandbox_executions, webmcp_workflows, "
            "memory_events, execution_attestations, "
            "approvals, evidence_outbox, memories, incidents"
        )

    embedder = DeterministicEmbedder()
    store = PostgresStore(database_url, retrieval_candidate_multiplier=2)
    service = IncidentService(store, embedder, DeterministicReasoner())
    try:
        assert store.ready()
        assert (
            store.find_memories(
                IncidentCreate(
                    tenant_id="integration",
                    service="checkout",
                    service_version="1.2.3",
                    symptom="latency",
                    idempotency_key="limit-zero",
                ),
                [0.0] * 1024,
                embedder.space_id,
                0,
            )
            == []
        )

        seed = Memory(
            tenant_id="integration",
            service="checkout",
            service_version="1.2.3",
            symptom="latency after connection saturation",
            action="reduce concurrency",
            outcome="latency recovered",
            outcome_score=1.0,
            confidence=0.95,
            reviewed_by="seed-reviewer",
            embedding_space=embedder.space_id,
            embedding=embedder.embed("checkout latency after connection saturation"),
        )
        store.add_memory(seed)
        incident = IncidentCreate(
            tenant_id="integration",
            service="checkout",
            service_version="1.2.3",
            symptom="latency after connection saturation",
            idempotency_key=f"integration-{uuid4()}",
        )
        analysis = service.analyze(incident)
        replay = service.analyze(incident)
        assert replay.incident_id == analysis.incident_id
        assert store.get_analysis(analysis.incident_id, "other") is None
        assert store.get_incident(analysis.incident_id, "other") is None
        assert store.get_approval(analysis.incident_id, "integration") is None
        assert store.get_execution(analysis.incident_id, "integration") is None

        assert service.decide_approval(
            analysis.incident_id,
            ApprovalRequest(
                tenant_id="integration",
                actor_id="operator",
                approved=True,
                proposal_hash=analysis.proposed_action.action_hash,
                reason="reviewed",
            ),
        )
        assert not service.decide_approval(
            analysis.incident_id,
            ApprovalRequest(
                tenant_id="integration",
                actor_id="operator",
                approved=True,
                proposal_hash=analysis.proposed_action.action_hash,
                reason="duplicate",
            ),
        )
        action = analysis.proposed_action
        execution = service.attest_execution(
            analysis.incident_id,
            ExecutionAttestationRequest(
                tenant_id="integration",
                actor_id="operator",
                action_hash=action.action_hash,
                action_taken=action.command,
                evidence_refs=["integration://execution"],
            ),
        )
        assert execution is not None
        assert (
            service.attest_execution(
                analysis.incident_id,
                ExecutionAttestationRequest(
                    tenant_id="integration",
                    actor_id="operator",
                    action_hash=action.action_hash,
                    action_taken=action.command,
                    evidence_refs=["integration://execution"],
                ),
            )
            == execution
        )

        learned = service.learn_outcome(
            analysis.incident_id,
            OutcomeObservation(
                tenant_id="integration",
                actor_id="observer",
                action_taken=action.command,
                outcome="latency remained healthy",
                outcome_score=1.0,
                confidence=0.9,
            ),
        )
        assert learned is not None
        assert (
            service.learn_outcome(
                analysis.incident_id,
                OutcomeObservation(
                    tenant_id="integration",
                    actor_id="observer",
                    action_taken=action.command,
                    outcome="latency remained healthy",
                    outcome_score=1.0,
                    confidence=0.9,
                ),
            ).id
            == learned.id
        )
        assert (
            store.govern_memory(
                uuid4(),
                MemoryGovernanceRequest(
                    tenant_id="integration",
                    actor_id="reviewer",
                    action=GovernanceAction.ACTIVATE,
                    reason="missing",
                ),
            )
            is None
        )
        active = service.govern_memory(
            learned.id,
            MemoryGovernanceRequest(
                tenant_id="integration",
                actor_id="reviewer",
                action=GovernanceAction.ACTIVATE,
                reason="independent review",
            ),
        )
        assert active is not None and active.valid
        assert store.find_memories(
            incident, embedder.embed("checkout latency"), embedder.space_id, 5
        )
        replacement = Memory(
            tenant_id="integration",
            service="checkout",
            service_version="1.2.3",
            symptom="latency",
            action="safer action",
            outcome="verified",
            outcome_score=1,
            confidence=1,
            embedding=embedder.embed("checkout latency"),
        )
        store.add_memory(replacement)
        superseded = store.govern_memory(
            active.id,
            MemoryGovernanceRequest(
                tenant_id="integration",
                actor_id="reviewer-2",
                action=GovernanceAction.SUPERSEDE,
                reason="stronger evidence",
                replacement_memory_id=replacement.id,
            ),
        )
        assert superseded is not None and superseded.superseded_by == replacement.id
    finally:
        store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_postgres_sandbox_evidence_and_assessment_are_distinct_and_bound() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, "
            "postcheck_observations, sandbox_executions, webmcp_workflows, memory_events, "
            "execution_attestations, approvals, evidence_outbox, memories, incidents"
        )
    embedder = DeterministicEmbedder()
    store = PostgresStore(database_url)
    store.add_memory(
        Memory(
            tenant_id="sandbox-db",
            service="checkout",
            service_version="2026.07.31",
            symptom="latency spike after connection pool exhaustion",
            action=SANDBOX_ACTION_COMMAND,
            outcome="recovered",
            outcome_score=1,
            confidence=0.99,
            reviewed_by="seed-reviewer",
            embedding=embedder.embed("checkout latency spike after connection pool exhaustion"),
        )
    )
    client = TestClient(create_app(Settings(store="postgres", database_url=database_url), store))
    incident = client.post(
        "/v1/incidents",
        headers={
            "X-Tenant-ID": "sandbox-db",
            "X-Actor-ID": "sandbox-agent",
            "X-Roles": "agent",
            "X-RecallOps-Channel": "webmcp",
        },
        json={
            "tenant_id": "sandbox-db",
            "service": "checkout",
            "service_version": "2026.07.31",
            "symptom": "latency spike after connection pool exhaustion",
            "idempotency_key": "postgres-sandbox-proof",
        },
    ).json()
    proposal_hash = incident["proposed_action"]["action_hash"]
    operator_headers = {
        "X-Tenant-ID": "sandbox-db",
        "X-Actor-ID": "sandbox-operator",
        "X-Roles": "operator",
        "X-RecallOps-Channel": "ui",
    }
    approval = client.post(
        f"/v1/incidents/{incident['incident_id']}/approval",
        headers={**operator_headers, "X-Workflow-Epoch": "1"},
        json={
            "tenant_id": "sandbox-db",
            "actor_id": "sandbox-operator",
            "approved": True,
            "proposal_hash": proposal_hash,
            "reason": "exact digest approved",
        },
    )
    assert approval.status_code == 200
    execution = client.post(
        f"/v1/incidents/{incident['incident_id']}/sandbox-execution",
        headers={**operator_headers, "X-Workflow-Epoch": "2"},
        json={
            "tenant_id": "sandbox-db",
            "actor_id": "sandbox-operator",
            "proposal_hash": proposal_hash,
            "idempotency_key": "postgres-execution-proof",
        },
    )
    assert execution.status_code == 201
    evidence = execution.json()
    assessment = client.post(
        f"/v1/incidents/{incident['incident_id']}/postcheck-assessment",
        headers={
            "X-Tenant-ID": "sandbox-db",
            "X-Actor-ID": "sandbox-agent",
            "X-Roles": "agent",
            "X-RecallOps-Channel": "webmcp",
            "X-Workflow-Epoch": "4",
        },
        json={
            "observation_id": evidence["observation"]["id"],
            "classification": "not_recovered",
            "rationale": "Deliberate disagreement proves opinions do not rewrite measurements.",
        },
    )
    assert assessment.status_code == 201
    assert assessment.json()["policy_verdict"]["classification"] == "recovered"
    recorded_assessment = store.get_postcheck_assessment(
        UUID(str(incident["incident_id"])), "sandbox-db"
    )
    assert recorded_assessment is not None
    assert recorded_assessment.classification == "not_recovered"
    with psycopg.connect(database_url) as connection:
        row = connection.execute(
            """SELECT a.classification, v.classification, m.state, m.valid,
               o.observation_digest=a.observation_digest,
               o.observation_digest=v.observation_digest,
               e.proposal_hash=o.proposal_hash
               FROM postcheck_assessments AS a
               JOIN postcheck_observations AS o ON o.id=a.observation_id
               JOIN postcheck_policy_verdicts AS v ON v.observation_id=o.id
               JOIN sandbox_executions AS e ON e.id=o.execution_id
               JOIN memories AS m ON m.source_incident_id=o.incident_id
               WHERE o.incident_id=%s AND o.tenant_id='sandbox-db'""",
            (incident["incident_id"],),
        ).fetchone()
    assert row == ("not_recovered", "recovered", "pending_review", False, True, True, True)
    second_incident = uuid4()
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            """INSERT INTO incidents
               (id, tenant_id, service, service_version, symptom, idempotency_key,
                status, analysis)
               VALUES (%s, 'sandbox-db', 'checkout', '2026.07.31', 'binding probe',
                       'same-tenant-binding-probe', 'open', '{}'::JSONB)""",
            (second_incident,),
        )
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            connection.execute(
                """INSERT INTO postcheck_observations
                   (id, execution_id, incident_id, tenant_id, proposal_hash, execution_digest,
                    source, observation_window_seconds, before_metrics, after_metrics,
                    observation_digest)
                   VALUES (%s,%s,%s,'sandbox-db',%s,%s,'malicious-rebind',60,
                           '{}'::JSONB,'{}'::JSONB,%s)""",
                (
                    uuid4(),
                    evidence["execution"]["id"],
                    second_incident,
                    proposal_hash,
                    evidence["execution"]["execution_digest"],
                    "f" * 64,
                ),
            )
    store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_cockroach_concurrency_converges_on_one_incident_execution_and_memory() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, "
            "postcheck_observations, sandbox_executions, webmcp_workflows, "
            "memory_events, execution_attestations, "
            "approvals, evidence_outbox, memories, incidents"
        )
    embedder = DeterministicEmbedder()
    store = PostgresStore(database_url)
    service = IncidentService(store, embedder, DeterministicReasoner())
    incident = IncidentCreate(
        tenant_id="concurrency",
        service="checkout",
        service_version="2026.08",
        symptom="concurrent replay probe",
        idempotency_key="same-concurrent-event",
    )
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            analyses = list(executor.map(lambda _: service.analyze(incident), range(16)))
        assert len({analysis.incident_id for analysis in analyses}) == 1
        analysis = analyses[0]
        action = analysis.proposed_action
        if action.requires_approval:
            service.decide_approval(
                analysis.incident_id,
                ApprovalRequest(
                    tenant_id="concurrency",
                    actor_id="operator",
                    approved=True,
                    proposal_hash=action.action_hash,
                    reason="bounded concurrency proof",
                ),
            )
        request = ExecutionAttestationRequest(
            tenant_id="concurrency",
            actor_id="operator",
            action_hash=action.action_hash,
            action_taken=action.command,
            evidence_refs=["test://concurrency/execution"],
        )

        def attest(_: int):
            return service.attest_execution(analysis.incident_id, request)

        with ThreadPoolExecutor(max_workers=8) as executor:
            executions = list(executor.map(attest, range(16)))
        assert all(execution is not None for execution in executions)
        assert len({execution.action_hash for execution in executions if execution}) == 1

        observation = OutcomeObservation(
            tenant_id="concurrency",
            actor_id="operator",
            action_taken=action.command,
            outcome="concurrent observations converged",
            outcome_score=1,
            confidence=0.9,
        )
        with ThreadPoolExecutor(max_workers=8) as executor:
            memories = list(
                executor.map(
                    lambda _: service.learn_outcome(analysis.incident_id, observation), range(16)
                )
            )
        assert all(memory is not None for memory in memories)
        assert len({memory.id for memory in memories if memory}) == 1
        with psycopg.connect(database_url) as connection:
            counts = connection.execute(
                "SELECT (SELECT count(*) FROM incidents), "
                "(SELECT count(*) FROM execution_attestations), "
                "(SELECT count(*) FROM memories), (SELECT count(*) FROM evidence_outbox)"
            ).fetchone()
        assert counts == (1, 1, 1, 1)
    finally:
        store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_cockroach_workflow_epoch_has_one_authoritative_winner() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    workflow_id = uuid4()
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, "
            "postcheck_observations, sandbox_executions, webmcp_workflows, "
            "memory_events, execution_attestations, "
            "approvals, evidence_outbox, memories, incidents"
        )
        connection.execute(
            """INSERT INTO incidents
               (id, tenant_id, service, service_version, symptom, idempotency_key,
                status, analysis)
               VALUES (%s, 'workflow-race', 'checkout', '2026.08', 'latency',
                       'workflow-race', 'open', '{}'::JSONB)""",
            (workflow_id,),
        )

    repository = PostgresWorkflowRepository(database_url)
    coordinator = WorkflowCoordinator(repository)
    try:
        coordinator.ensure_for_analysis("workflow-race", workflow_id, "0" * 64, mutating=True)

        def approve(_: int) -> str:
            try:
                coordinator.transition(
                    workflow_id,
                    "workflow-race",
                    1,
                    WorkflowState.AWAITING_OPERATOR_APPROVAL,
                    WorkflowState.APPROVED_AWAITING_EXECUTION,
                    channel=RequestChannel.UI,
                    actor_subject="operator",
                    role="operator",
                )
                return "won"
            except WorkflowConflict:
                return "stale"

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(approve, range(16)))

        assert results.count("won") == 1
        assert results.count("stale") == 15
        current = coordinator.get(workflow_id, "workflow-race")
        assert current is not None
        assert current.epoch == 2
        assert current.state is WorkflowState.APPROVED_AWAITING_EXECUTION
    finally:
        repository.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_protected_domain_write_rolls_back_when_epoch_transition_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "judge_auth_attempts, review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, "
            "postcheck_policy_verdicts, postcheck_observations, sandbox_executions, "
            "webmcp_workflows, memory_events, execution_attestations, approvals, "
            "evidence_outbox, memories, incidents"
        )
    store = PostgresStore(database_url)
    embedder = DeterministicEmbedder()
    store.add_memory(
        Memory(
            tenant_id="atomic",
            service="checkout",
            service_version="v1",
            symptom="latency spike",
            action="reduce concurrency",
            outcome="recovered",
            outcome_score=1,
            confidence=0.95,
            reviewed_by="seed-reviewer",
            embedding=embedder.embed("checkout latency spike"),
        )
    )
    app = create_app(Settings(store="postgres", database_url=database_url), store)
    client = TestClient(app, raise_server_exceptions=False)
    headers = {
        "X-Tenant-ID": "atomic",
        "X-Actor-ID": "operator",
        "X-Roles": "operator,agent",
    }
    incident = client.post(
        "/v1/incidents",
        headers={**headers, "X-RecallOps-Channel": "webmcp"},
        json={
            "tenant_id": "atomic",
            "service": "checkout",
            "service_version": "v1",
            "symptom": "latency spike",
            "idempotency_key": "atomic-rollback-proof",
        },
    ).json()

    def fail_transition(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("forced transition failure")

    monkeypatch.setattr(PostgresWorkflowRepository, "transition", fail_transition)
    response = client.post(
        f"/v1/incidents/{incident['incident_id']}/approval",
        headers={
            **headers,
            "X-RecallOps-Channel": "ui",
            "X-Workflow-Epoch": "1",
        },
        json={
            "tenant_id": "atomic",
            "actor_id": "operator",
            "approved": True,
            "proposal_hash": incident["proposed_action"]["action_hash"],
            "reason": "force rollback after the domain insert",
        },
    )
    assert response.status_code == 500
    with psycopg.connect(database_url) as connection:
        approval_count = connection.execute("SELECT count(*) FROM approvals").fetchone()
        workflow = connection.execute(
            "SELECT state, epoch FROM webmcp_workflows WHERE workflow_id=%s",
            (incident["incident_id"],),
        ).fetchone()
    assert approval_count == (0,)
    assert workflow == ("AWAITING_OPERATOR_APPROVAL", 1)
    app.state.workflows._repository.close()
    store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_webmcp_proposal_idempotency_and_authority_commit_are_one_transaction() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, judge_auth_attempts, review_handoffs, judge_sessions, "
            "judge_runs, postcheck_assessments, postcheck_policy_verdicts, "
            "postcheck_observations, sandbox_executions, webmcp_workflows, memory_events, "
            "execution_attestations, approvals, evidence_outbox, memories, incidents"
        )
    store = PostgresStore(database_url)
    app = create_app(
        Settings(
            store="postgres",
            database_url=database_url,
            auth_mode="judge",
            public_origin="http://testserver",
            judge_rate_limit_key=SecretStr("integration-rate-limit-key"),
            judge_cookie_secure=False,
            judge_active_run_limit=4,
        ),
        store,
    )
    client = TestClient(app, raise_server_exceptions=False)
    try:
        started = client.post(
            "/v1/judge/runs",
            headers={"Origin": "http://testserver", "Content-Type": "application/json"},
            json={},
        )
        assert started.status_code == 201
        manifest = client.get("/v1/webmcp/capabilities").json()
        incident = client.get("/v1/webmcp/incident").json()["incident"]
        headers = {
            "Origin": "http://testserver",
            "Content-Type": "application/json",
            "If-Match": f'"{manifest["run_generation"]}:{manifest["epoch"]}"',
            "Idempotency-Key": "postgres-proposal-key-0001",
        }
        payload = {
            "service": incident["service"],
            "service_version": incident["service_version"],
            "symptom": incident["symptom"],
        }
        proposal = client.post("/v1/webmcp/proposal", headers=headers, json=payload)
        assert proposal.status_code == 201
        replay = client.post("/v1/webmcp/proposal", headers=headers, json=payload)
        assert replay.status_code == 201 and replay.json() == proposal.json()
        run_id = UUID(started.json()["run"]["run_id"])
        with psycopg.connect(database_url) as connection:
            row = connection.execute(
                """SELECT i.request_digest,i.response_payload,i.completed_at,w.state,w.epoch,
                   count(e.event_id) FILTER (WHERE e.reason_code='PROPOSAL_STAGED')
                   FROM webmcp_idempotency i
                   JOIN judge_runs r ON r.run_id=i.run_id AND r.tenant_id=i.tenant_id
                   JOIN webmcp_workflows w ON w.workflow_id=r.source_incident_id
                                            AND w.tenant_id=r.tenant_id
                   LEFT JOIN authority_events e ON e.run_id=r.run_id AND e.tenant_id=r.tenant_id
                   WHERE i.run_id=%s AND i.route='proposal'
                   GROUP BY i.request_digest,i.response_payload,i.completed_at,w.state,w.epoch""",
                (run_id,),
            ).fetchone()
        assert row is not None
        assert len(str(row[0])) == 64 and row[1] == proposal.json() and row[2] is not None
        assert row[3:] == ("AWAITING_OPERATOR_APPROVAL", 2, 1)

        failed = client.post(
            "/v1/judge/runs",
            headers={"Origin": "http://testserver", "Content-Type": "application/json"},
            json={},
        )
        assert failed.status_code == 201
        failed_manifest = client.get("/v1/webmcp/capabilities").json()
        failed_incident = client.get("/v1/webmcp/incident").json()["incident"]

        def fail_after_event(stage: str) -> None:
            if stage == "after_event":
                raise RuntimeError("fault after authority event")

        app.state.ledger_fault_hook = fail_after_event
        failed_response = client.post(
            "/v1/webmcp/proposal",
            headers={
                "Origin": "http://testserver",
                "Content-Type": "application/json",
                "If-Match": (
                    f'"{failed_manifest["run_generation"]}:{failed_manifest["epoch"]}"'
                ),
                "Idempotency-Key": "postgres-fault-key-0001",
            },
            json={
                "service": failed_incident["service"],
                "service_version": failed_incident["service_version"],
                "symptom": failed_incident["symptom"],
            },
        )
        assert failed_response.status_code == 500
        failed_run_id = UUID(failed.json()["run"]["run_id"])
        with psycopg.connect(database_url) as connection:
            idempotency_count = connection.execute(
                "SELECT count(*) FROM webmcp_idempotency WHERE run_id=%s", (failed_run_id,)
            ).fetchone()
            workflow_row = connection.execute(
                """SELECT w.state,w.epoch,count(e.event_id)
                   FROM judge_runs r JOIN webmcp_workflows w
                     ON w.workflow_id=r.source_incident_id AND w.tenant_id=r.tenant_id
                   LEFT JOIN authority_events e ON e.run_id=r.run_id AND e.tenant_id=r.tenant_id
                   WHERE r.run_id=%s GROUP BY w.state,w.epoch""",
                (failed_run_id,),
            ).fetchone()
        assert idempotency_count == (0,)
        assert workflow_row == ("INVESTIGATING", 1, 1)
    finally:
        store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_judge_run_persists_only_hashed_credentials_and_bound_authority() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "judge_auth_attempts, review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, postcheck_observations, "
            "sandbox_executions, webmcp_workflows, memory_events, execution_attestations, "
            "approvals, evidence_outbox, memories, incidents"
        )
    store = PostgresStore(database_url)
    app = create_app(
        Settings(
            store="postgres",
            database_url=database_url,
            auth_mode="judge",
            public_origin="http://testserver",
            judge_rate_limit_key=SecretStr("integration-rate-limit-key"),
            judge_cookie_secure=False,
            judge_active_run_limit=1,
        ),
        store,
    )
    client = TestClient(app)
    response = client.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    assert response.status_code == 201
    capacity = client.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    assert capacity.status_code == 503
    cookie = client.cookies.get("recallops_operator")
    assert cookie is not None
    with psycopg.connect(database_url) as connection:
        session = connection.execute(
            """SELECT session_hash, csrf_hash, subject, role, run_id, tenant_id,
            session_generation FROM judge_sessions"""
        ).fetchone()
        run = connection.execute(
            "SELECT run_id, tenant_id, generation, operator_subject, status FROM judge_runs"
        ).fetchone()
        attempts = connection.execute("SELECT attempts FROM judge_auth_attempts").fetchone()
    assert session is not None and run is not None
    assert session[0] == hashlib.sha256(cookie.encode()).hexdigest()
    assert response.json()["csrf_token"] not in session
    assert session[2] == run[3]
    assert session[3] == "operator"
    assert session[4:7] == run[0:3]
    assert run[4] == "active"
    assert attempts == (2,)
    assert client.get("/v1/me").status_code == 200
    logout = client.post(
        "/v1/judge/session/logout",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": response.json()["csrf_token"],
        },
    )
    assert logout.status_code == 200
    assert client.get("/v1/me").status_code == 401
    app.state.workflows._repository.close()
    store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_postgres_reset_route_commits_domain_workflow_event_and_head_together() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "judge_auth_attempts, review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, postcheck_observations, "
            "sandbox_executions, webmcp_workflows, memory_events, execution_attestations, "
            "approvals, evidence_outbox, memories, incidents"
        )
    store = PostgresStore(database_url)
    app = create_app(
        Settings(
            store="postgres",
            database_url=database_url,
            auth_mode="judge",
            public_origin="http://testserver",
            judge_rate_limit_key=SecretStr("integration-rate-limit-key"),
            judge_cookie_secure=False,
        ),
        store,
    )
    client = TestClient(app)
    launch = client.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    assert launch.status_code == 201
    old = launch.json()["run"]
    reset = client.post(
        "/v1/operator/run/reset",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": launch.json()["csrf_token"],
        },
    )
    assert reset.status_code == 201
    with psycopg.connect(database_url) as connection:
        committed = connection.execute(
            """SELECT r.status,w.active,w.epoch,h.last_sequence,h.last_event_hash,
            e.sequence,e.event_hash,e.reason_code
            FROM judge_runs r
            JOIN webmcp_workflows w ON w.workflow_id=r.source_incident_id
                                    AND w.tenant_id=r.tenant_id
            JOIN authority_ledger_heads h ON h.run_id=r.run_id AND h.tenant_id=r.tenant_id
            JOIN authority_events e ON e.run_id=r.run_id AND e.sequence=h.last_sequence
            WHERE r.run_id=%s""",
            (old["run_id"],),
        ).fetchone()
    assert committed is not None
    assert committed[:4] == ("reset", False, 2, 2)
    assert committed[4] == committed[6]
    assert committed[5] == 2 and committed[7] == "WORKFLOW_RESET_ACCEPTED"
    app.state.workflows._repository.close()
    store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_postgres_judge_run_handoff_expiry_and_reset_are_atomic() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "judge_auth_attempts, review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, postcheck_observations, "
            "sandbox_executions, webmcp_workflows, memory_events, execution_attestations, "
            "approvals, evidence_outbox, memories, incidents"
        )
    store = PostgresStore(database_url)
    app = create_app(
        Settings(
            store="postgres",
            database_url=database_url,
            auth_mode="judge",
            public_origin="http://testserver",
            judge_rate_limit_key=SecretStr("integration-rate-limit-key"),
            judge_cookie_secure=False,
        ),
        store,
    )
    first, second = TestClient(app), TestClient(app)
    first_response = first.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    second_response = second.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    first_run_id = UUID(first_response.json()["run"]["run_id"])
    second_run_id = UUID(second_response.json()["run"]["run_id"])
    repository = PostgresJudgeSessionRepository(store.pool)
    first_run = repository.get_run(first_run_id)
    assert first_run is not None
    assert repository.get_run(uuid4()) is None
    assert repository.active_run_count() == 2
    assert repository.run_is_current(first_run.run_id, first_run.tenant_id, first_run.generation)

    memory = Memory(
        tenant_id=first_run.tenant_id,
        service="checkout",
        service_version="v2.4.1",
        symptom="checkout latency",
        action="restore bounded concurrency",
        outcome="recovered",
        outcome_score=1,
        confidence=0.95,
        valid=False,
        state="pending_review",
        source_incident_id=first_run.source_incident_id,
        observed_by="agent_assessor",
        embedding=DeterministicEmbedder().embed("checkout latency"),
    )
    store.save_outcome_memory(memory)
    workflow_repository = app.state.workflows._repository
    workflow = workflow_repository.get(first_run.source_incident_id, first_run.tenant_id)
    assert workflow is not None
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            """UPDATE webmcp_workflows SET state='PENDING_REVIEW', epoch=epoch+1
            WHERE workflow_id=%s AND tenant_id=%s""",
            (first_run.source_incident_id, first_run.tenant_id),
        )
    handoff_response = first.post(
        "/v1/operator/reviewer-handoff",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": first_response.json()["csrf_token"],
        },
        json={"purpose": "initial_review", "memory_digest": memory.memory_digest},
    )
    assert handoff_response.status_code == 201
    code = urlsplit(handoff_response.json()["reviewer_url"]).fragment.removeprefix("review=")
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    assert repository.consume_handoff("0" * 64) is None
    reviewer = TestClient(app)
    reviewer_exchange = reviewer.post(
        "/v1/judge/reviewer-exchange",
        headers={"Origin": "http://testserver"},
        json={"code": code},
    )
    assert reviewer_exchange.status_code == 200
    assert reviewer.cookies.get("recallops_reviewer") is not None
    assert repository.consume_handoff(code_hash) is None
    assert repository.reset_run(first_run.run_id)
    assert not repository.reset_run(first_run.run_id)
    assert not repository.run_is_current(
        first_run.run_id, first_run.tenant_id, first_run.generation
    )
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "UPDATE judge_runs SET expires_at=now() - interval '1 second' WHERE run_id=%s",
            (second_run_id,),
        )
    expired = repository.get_run(second_run_id)
    assert expired is not None and expired.status == "expired"
    assert repository.active_run_count() == 0
    app.state.workflows._repository.close()
    store.close()


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_review_activation_rolls_back_when_workflow_commit_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_idempotency, activity_observations, authority_events, "
            "authority_ledger_heads, "
            "review_handoffs, judge_sessions, judge_runs, "
            "postcheck_assessments, postcheck_policy_verdicts, "
            "postcheck_observations, sandbox_executions, webmcp_workflows, memory_events, "
            "execution_attestations, approvals, evidence_outbox, memories, incidents"
        )
    store = PostgresStore(database_url)
    embedder = DeterministicEmbedder()
    store.add_memory(
        Memory(
            tenant_id="review-atomic",
            service="checkout",
            service_version="v1",
            symptom="latency spike",
            action="reduce concurrency",
            outcome="recovered",
            outcome_score=1,
            confidence=0.95,
            reviewed_by="seed-reviewer",
            embedding=embedder.embed("checkout latency spike"),
        )
    )
    app = create_app(Settings(store="postgres", database_url=database_url), store)
    client = TestClient(app, raise_server_exceptions=False)
    operator = {
        "X-Tenant-ID": "review-atomic",
        "X-Actor-ID": "operator",
        "X-Roles": "operator,agent",
        "X-RecallOps-Channel": "ui",
    }
    incident = client.post(
        "/v1/incidents",
        headers=operator,
        json={
            "tenant_id": "review-atomic",
            "service": "checkout",
            "service_version": "v1",
            "symptom": "latency spike",
            "idempotency_key": "review-atomic-proof",
        },
    ).json()
    action = incident["proposed_action"]
    approval = client.post(
        f"/v1/incidents/{incident['incident_id']}/approval",
        headers={**operator, "X-Workflow-Epoch": "1"},
        json={
            "tenant_id": "review-atomic",
            "actor_id": "operator",
            "approved": True,
            "proposal_hash": action["action_hash"],
            "reason": "approve bounded test action",
        },
    )
    assert approval.status_code == 200
    execution = client.post(
        f"/v1/incidents/{incident['incident_id']}/execution",
        headers={**operator, "X-Workflow-Epoch": "2"},
        json={
            "tenant_id": "review-atomic",
            "actor_id": "operator",
            "action_hash": action["action_hash"],
            "action_taken": action["command"],
            "evidence_refs": ["test://atomic-review/execution"],
        },
    )
    assert execution.status_code == 201
    outcome = client.post(
        f"/v1/incidents/{incident['incident_id']}/outcome",
        headers={**operator, "X-Workflow-Epoch": "3"},
        json={
            "tenant_id": "review-atomic",
            "actor_id": "operator",
            "action_taken": action["command"],
            "outcome": "recovered",
            "outcome_score": 1,
            "confidence": 0.9,
        },
    )
    assert outcome.status_code == 201
    memory = outcome.json()

    def fail_transition(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("forced review transition failure")

    monkeypatch.setattr(PostgresWorkflowRepository, "transition", fail_transition)
    review = client.post(
        f"/v1/memories/{memory['id']}/governance",
        headers={
            "X-Tenant-ID": "review-atomic",
            "X-Actor-ID": "reviewer",
            "X-Roles": "reviewer",
            "X-RecallOps-Channel": "ui",
            "X-Workflow-Epoch": "4",
        },
        json={
            "tenant_id": "review-atomic",
            "actor_id": "reviewer",
            "action": "activate",
            "reason": "force rollback after activation update",
        },
    )
    assert review.status_code == 500
    with psycopg.connect(database_url) as connection:
        memory_row = connection.execute(
            "SELECT state, valid FROM memories WHERE id=%s", (memory["id"],)
        ).fetchone()
        workflow_row = connection.execute(
            "SELECT state, epoch FROM webmcp_workflows WHERE workflow_id=%s",
            (incident["incident_id"],),
        ).fetchone()
        event_count = connection.execute("SELECT count(*) FROM memory_events").fetchone()
    assert memory_row == ("pending_review", False)
    assert workflow_row == ("PENDING_REVIEW", 4)
    assert event_count == (0,)
    app.state.workflows._repository.close()
    store.close()
