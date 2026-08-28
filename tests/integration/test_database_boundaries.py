import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

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
    OutcomeObservation,
)
from recallops.embedding import DeterministicEmbedder
from recallops.sandbox import SANDBOX_ACTION_COMMAND
from recallops.service import DeterministicReasoner, IncidentService
from recallops.store import PostgresStore
from recallops.workflow import (
    PostgresWorkflowRepository,
    RequestChannel,
    WorkflowConflict,
    WorkflowCoordinator,
    WorkflowState,
)


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_runtime_grants_and_cross_tenant_constraints() -> None:
    report = verify_database_boundaries(os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"])

    assert report["passed"] is True
    assert report["exact_runtime_grants"] == 32
    assert len(report["cross_tenant_constraints"]) == 11
    assert len(report["runtime_denials"]) == 17


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_postgres_store_complete_governed_memory_lifecycle() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE postcheck_assessments, postcheck_policy_verdicts, "
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
            service_version="2026.08",
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
            "TRUNCATE postcheck_assessments, postcheck_policy_verdicts, "
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
            "TRUNCATE postcheck_assessments, postcheck_policy_verdicts, "
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
            "TRUNCATE postcheck_assessments, postcheck_policy_verdicts, "
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
            "TRUNCATE judge_auth_attempts, judge_sessions, postcheck_assessments, "
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
def test_judge_exchange_persists_only_hashed_credentials() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    operator_code = "integration-operator-bootstrap-2026"
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute("TRUNCATE judge_auth_attempts, judge_sessions")
    store = PostgresStore(database_url)
    app = create_app(
        Settings(
            store="postgres",
            database_url=database_url,
            auth_mode="judge",
            public_origin="http://testserver",
            judge_tenant_id="judge-integration",
            judge_operator_bootstrap_sha256=hashlib.sha256(operator_code.encode()).hexdigest(),
            judge_reviewer_bootstrap_sha256=hashlib.sha256(
                b"integration-reviewer-bootstrap-2026"
            ).hexdigest(),
            judge_rate_limit_key=SecretStr("integration-rate-limit-key"),
            judge_cookie_secure=False,
        ),
        store,
    )
    client = TestClient(app)
    response = client.post(
        "/v1/judge/session/exchange",
        headers={"Origin": "http://testserver"},
        json={"code": operator_code},
    )
    assert response.status_code == 200
    cookie = client.cookies.get("recallops_session")
    assert cookie is not None
    with psycopg.connect(database_url) as connection:
        session = connection.execute(
            "SELECT session_hash, csrf_hash, subject, role FROM judge_sessions"
        ).fetchone()
        attempts = connection.execute("SELECT count(*) FROM judge_auth_attempts").fetchone()
    assert session is not None
    assert session[0] == hashlib.sha256(cookie.encode()).hexdigest()
    assert operator_code not in session
    assert response.json()["csrf_token"] not in session
    assert session[2:] == ("judge-operator", "operator")
    assert attempts == (1,)
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
def test_review_activation_rolls_back_when_workflow_commit_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE postcheck_assessments, postcheck_policy_verdicts, "
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
