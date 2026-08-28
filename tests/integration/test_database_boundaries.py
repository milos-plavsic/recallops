import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest

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
    assert report["exact_runtime_grants"] == 18
    assert len(report["cross_tenant_constraints"]) == 7
    assert len(report["runtime_denials"]) == 8


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_postgres_store_complete_governed_memory_lifecycle() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_workflows, memory_events, execution_attestations, "
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
                reason="reviewed",
            ),
        )
        assert not service.decide_approval(
            analysis.incident_id,
            ApprovalRequest(
                tenant_id="integration",
                actor_id="operator",
                approved=True,
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
def test_cockroach_concurrency_converges_on_one_incident_execution_and_memory() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE webmcp_workflows, memory_events, execution_attestations, "
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
                    action_hash=action.action_hash,
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
            "TRUNCATE webmcp_workflows, memory_events, execution_attestations, "
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
