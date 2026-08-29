from datetime import UTC, datetime, timedelta

import pytest
from botocore.exceptions import ClientError

from recallops.diagnostics import (
    AlarmInspection,
    DiagnosticScope,
    EcsDeploymentInspection,
    ReadOnlyDiagnosticTools,
)
from recallops.domain import (
    ActionRisk,
    ApprovalRequest,
    CompatibilityPolicy,
    EvidenceVerification,
    ExecutionAttestationRequest,
    GovernanceAction,
    IncidentAnalysis,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    MemoryState,
    OutcomeObservation,
    RetrievedMemory,
)
from recallops.embedding import DeterministicEmbedder
from recallops.resilience import DependencyUnavailable
from recallops.service import (
    BedrockReasoner,
    DeterministicReasoner,
    IncidentService,
    IncidentWorkflowError,
)
from recallops.store import InMemoryStore, rank_memory


class RecordingArchive:
    def __init__(self) -> None:
        self.incident_ids: list[str] = []

    def archive(self, incident: IncidentCreate, analysis: IncidentAnalysis) -> None:
        self.incident_ids.append(str(analysis.incident_id))


class AcceptingEvidenceVerifier:
    def verify(self, verification: EvidenceVerification, references: list[str]) -> bool:
        return bool(references) or verification is EvidenceVerification.MANUAL_ATTESTATION


class FakeAlarms:
    def inspect(self, scope: DiagnosticScope) -> AlarmInspection:
        return AlarmInspection(
            scope.digest, "urn:recallops:diagnostic:alarm:test", "target", (), 5, False
        )


class FakeDeployments:
    def inspect(self, scope: DiagnosticScope) -> EcsDeploymentInspection:
        return EcsDeploymentInspection(
            scope.digest,
            "urn:recallops:diagnostic:ecs:test",
            "target",
            True,
            1,
            1,
            0,
            (),
            5,
            False,
        )


class UnavailableInspector:
    def __init__(self, dependency: str) -> None:
        self.dependency = dependency

    def inspect(self, scope: DiagnosticScope) -> object:
        del scope
        raise DependencyUnavailable(self.dependency)


def incident(version: str = "2026.07.31") -> IncidentCreate:
    return IncidentCreate(
        tenant_id="demo",
        service="checkout",
        service_version=version,
        symptom="latency spike after connection pool exhaustion",
        idempotency_key="event-0001",
    )


class FakeBedrockReasoningClient:
    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self.response = response
        self.error = error
        self.requests: list[dict[str, object]] = []

    def converse(self, **request: object) -> object:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.response


def test_bedrock_reasoner_uses_guarded_zero_temperature_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeBedrockReasoningClient(
        {"output": {"message": {"content": [{"text": " grounded "}, {}, {"text": "diagnosis"}]}}}
    )
    monkeypatch.setattr("recallops.service.boto3.client", lambda *args, **kwargs: client)

    reasoner = BedrockReasoner("us-east-1", "model-v1")
    assert reasoner.diagnosis(incident(), "verified evidence") == "grounded diagnosis"
    request = client.requests[0]
    assert request["modelId"] == "model-v1"
    assert request["inferenceConfig"] == {"maxTokens": 300, "temperature": 0.0}
    assert "untrusted data" in request["system"][0]["text"]  # type: ignore[index]
    assert "verified evidence" in request["messages"][0]["content"][0]["text"]  # type: ignore[index]


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"output": {"message": {"content": None}}},
        {"output": {"message": {"content": [{"text": "  "}]}}},
    ],
)
def test_bedrock_reasoner_fails_closed_on_malformed_output(
    monkeypatch: pytest.MonkeyPatch, response: object
) -> None:
    client = FakeBedrockReasoningClient(response)
    monkeypatch.setattr("recallops.service.boto3.client", lambda *args, **kwargs: client)
    with pytest.raises(DependencyUnavailable, match="bedrock_reasoning"):
        BedrockReasoner("us-east-1", "model-v1").diagnosis(incident(), "evidence")


def test_bedrock_reasoner_translates_provider_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    error = ClientError({"Error": {"Code": "ThrottlingException"}}, "Converse")
    client = FakeBedrockReasoningClient(error=error)
    monkeypatch.setattr("recallops.service.boto3.client", lambda *args, **kwargs: client)
    with pytest.raises(DependencyUnavailable, match="bedrock_reasoning"):
        BedrockReasoner("us-east-1", "model-v1").diagnosis(incident(), "evidence")


def memory(
    embedder: DeterministicEmbedder, version: str, outcome_score: float, action: str
) -> Memory:
    symptom = "checkout latency spike after connection pool exhaustion"
    return Memory(
        tenant_id="demo",
        service="checkout",
        service_version=version,
        symptom=symptom,
        action=action,
        outcome="latency recovered and error rate returned to baseline",
        outcome_score=outcome_score,
        confidence=0.95,
        embedding=embedder.embed(f"checkout {symptom}"),
    )


def test_compatible_successful_memory_drives_guarded_action() -> None:
    embedder = DeterministicEmbedder()
    store = InMemoryStore(
        [
            memory(embedder, "2025.01", 1.0, "obsolete rollback"),
            memory(embedder, "2026.07.31", 1.0, "reduce worker concurrency"),
        ]
    )
    result = IncidentService(store, embedder, DeterministicReasoner()).analyze(incident())
    assert result.proposed_action.command == "reduce worker concurrency"
    assert result.proposed_action.risk is ActionRisk.MUTATING
    assert result.proposed_action.requires_approval is True


def test_versioned_compatibility_policy_can_authorize_reviewed_patch_reuse() -> None:
    embedder = DeterministicEmbedder()
    payload = memory(embedder, "2.4.1", 1.0, "reduce concurrency").model_dump()
    payload.update(
        {
            "compatibility_policy": CompatibilityPolicy.SEMVER_PATCH,
            "compatibility_policy_version": "semver-v1",
            "memory_digest": None,
        }
    )
    compatible = Memory.model_validate(payload)
    result = IncidentService(
        InMemoryStore([compatible]), embedder, DeterministicReasoner()
    ).analyze(incident("2.4.9"))
    assert result.memories[0].compatibility == 1.0
    assert result.proposed_action.command == "reduce concurrency"


def test_no_cross_tenant_retrieval() -> None:
    embedder = DeterministicEmbedder()
    other = memory(embedder, "2026.07.31", 1.0, "secret remediation")
    other.tenant_id = "other"
    result = IncidentService(InMemoryStore([other]), embedder, DeterministicReasoner()).analyze(
        incident()
    )
    assert result.memories == []
    assert result.proposed_action.risk is ActionRisk.READ_ONLY


def test_retrieval_never_crosses_embedding_spaces() -> None:
    embedder = DeterministicEmbedder()
    incompatible = memory(embedder, "2026.07.31", 1.0, "unsafe cross-space action")
    incompatible.embedding_space = "bedrock:amazon.titan-embed-text-v2:0:v1"
    result = IncidentService(
        InMemoryStore([incompatible]), embedder, DeterministicReasoner()
    ).analyze(incident())

    assert result.memories == []
    assert result.proposed_action.risk is ActionRisk.READ_ONLY


def test_retrieval_abstains_when_evidence_confidence_is_insufficient() -> None:
    embedder = DeterministicEmbedder()
    weak = memory(embedder, "2026.07.31", 1.0, "weakly supported action")
    weak.confidence = 0.2
    result = IncidentService(InMemoryStore([weak]), embedder, DeterministicReasoner()).analyze(
        incident()
    )

    assert "evidence_confidence_below_threshold" in result.retrieval_abstention_reasons
    assert result.proposed_action.risk is ActionRisk.READ_ONLY


def attest(service: IncidentService, analysis: IncidentAnalysis, actor: str) -> str:
    action = analysis.proposed_action
    execution = service.attest_execution(
        analysis.incident_id,
        ExecutionAttestationRequest(
            tenant_id="demo",
            actor_id=actor,
            action_hash=action.action_hash,
            action_taken=action.command,
            evidence_refs=["test://execution/verified"],
        ),
    )
    assert execution is not None
    return execution.action_taken


def test_mutating_execution_requires_approval_for_exact_action() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(
        InMemoryStore([memory(embedder, "2026.07.31", 1.0, "reduce concurrency")]),
        embedder,
        DeterministicReasoner(),
    )
    analysis = service.analyze(incident())
    action = analysis.proposed_action
    request = ExecutionAttestationRequest(
        tenant_id="demo",
        actor_id="operator-1",
        action_hash=action.action_hash,
        action_taken=action.command,
        evidence_refs=["test://execution/verified"],
    )

    with pytest.raises(IncidentWorkflowError, match="approved decision required"):
        service.attest_execution(analysis.incident_id, request)

    assert service.decide_approval(
        analysis.incident_id,
        ApprovalRequest(
            tenant_id="demo",
            actor_id="operator-1",
            approved=True,
            proposal_hash=analysis.proposed_action.action_hash,
            reason="exact action reviewed against current evidence",
        ),
    )
    assert service.attest_execution(analysis.incident_id, request) is not None


def test_execution_rejects_action_substitution() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())

    with pytest.raises(IncidentWorkflowError, match="does not match"):
        service.attest_execution(
            analysis.incident_id,
            ExecutionAttestationRequest(
                tenant_id="demo",
                actor_id="operator-1",
                action_hash=analysis.proposed_action.action_hash,
                action_taken="substituted destructive command",
                evidence_refs=["test://execution/verified"],
            ),
        )


def test_retrieval_abstains_when_top_candidates_are_ambiguous() -> None:
    embedder = DeterministicEmbedder()
    first = memory(embedder, "2026.07.31", 1.0, "action one")
    second = memory(embedder, "2026.07.31", 1.0, "action two")
    result = IncidentService(
        InMemoryStore([first, second]), embedder, DeterministicReasoner()
    ).analyze(incident())

    assert "top_candidates_ambiguous" in result.retrieval_abstention_reasons
    assert result.proposed_action.risk is ActionRisk.READ_ONLY


def test_retrieval_accepts_equally_ranked_memories_with_the_same_action() -> None:
    embedder = DeterministicEmbedder()
    first = memory(embedder, "2026.07.31", 1.0, "reduce worker concurrency to 24")
    second = memory(embedder, "2026.07.31", 1.0, "  REDUCE WORKER CONCURRENCY TO 24  ")
    result = IncidentService(
        InMemoryStore([first, second]), embedder, DeterministicReasoner()
    ).analyze(incident())

    assert "top_candidates_ambiguous" not in result.retrieval_abstention_reasons
    assert result.proposed_action.risk is ActionRisk.MUTATING


def test_idempotency_returns_original_analysis() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    first = service.analyze(incident())
    second = service.analyze(incident())
    assert first.incident_id == second.incident_id


def test_analysis_is_archived() -> None:
    embedder = DeterministicEmbedder()
    archive = RecordingArchive()
    result = IncidentService(
        InMemoryStore(), embedder, DeterministicReasoner(), archive=archive
    ).analyze(incident())
    assert archive.incident_ids == [str(result.incident_id)]


def test_observed_outcome_becomes_idempotent_retrievable_memory() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    observation = OutcomeObservation(
        tenant_id="demo",
        action_taken=attest(service, analysis, "operator-observer"),
        outcome="latency recovered without recurrence",
        outcome_score=1.0,
        confidence=0.98,
        actor_id="operator-observer",
    )

    first = service.learn_outcome(analysis.incident_id, observation)
    second = service.learn_outcome(analysis.incident_id, observation)
    assert first is not None
    assert second is not None
    assert first.id == second.id
    assert first.state is MemoryState.PENDING_REVIEW

    before_review = service.analyze(incident().model_copy(update={"idempotency_key": "event-0002"}))
    assert before_review.memories == []

    activated = service.govern_memory(
        first.id,
        MemoryGovernanceRequest(
            tenant_id="demo",
            actor_id="operator-reviewer",
            action=GovernanceAction.ACTIVATE,
            reason="independent telemetry review confirms sustained recovery",
        ),
    )
    assert activated is not None
    assert activated.state is MemoryState.ACTIVE

    future = service.analyze(incident().model_copy(update={"idempotency_key": "event-0003"}))
    assert future.memories[0].memory.id == first.id
    assert future.proposed_action.command == observation.action_taken


def test_outcome_learning_enforces_tenant_boundary() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    result = service.learn_outcome(
        analysis.incident_id,
        OutcomeObservation(
            tenant_id="other",
            action_taken="exfiltrate remediation",
            outcome="should never be learned",
            outcome_score=1.0,
            confidence=1.0,
            actor_id="attacker",
        ),
    )
    assert result is None


def test_memory_activation_requires_independent_reviewer() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    action_taken = attest(service, analysis, "operator-1")
    learned = service.learn_outcome(
        analysis.incident_id,
        OutcomeObservation(
            tenant_id="demo",
            action_taken=action_taken,
            outcome="latency recovered",
            outcome_score=1.0,
            confidence=0.9,
            actor_id="operator-1",
        ),
    )
    assert learned is not None
    request = MemoryGovernanceRequest(
        tenant_id="demo",
        actor_id="operator-1",
        action=GovernanceAction.ACTIVATE,
        reason="self review must not activate memory",
    )
    with pytest.raises(ValueError, match="independent reviewer"):
        service.govern_memory(learned.id, request)


def test_memory_can_be_superseded_only_by_active_same_tenant_memory() -> None:
    embedder = DeterministicEmbedder()
    old = memory(embedder, "2026.07.31", 1.0, "old remediation")
    replacement = memory(embedder, "2026.07.31", 1.0, "safer remediation")
    store = InMemoryStore([old, replacement])
    service = IncidentService(store, embedder, DeterministicReasoner())

    updated = service.govern_memory(
        old.id,
        MemoryGovernanceRequest(
            tenant_id="demo",
            actor_id="reviewer-1",
            action=GovernanceAction.SUPERSEDE,
            reason="new remediation has stronger postcondition evidence",
            replacement_memory_id=replacement.id,
        ),
    )
    assert updated is not None
    assert updated.state is MemoryState.SUPERSEDED
    assert updated.valid is False
    assert updated.superseded_by == replacement.id
    assert store.memory_events[-1].from_state is MemoryState.ACTIVE
    assert store.memory_events[-1].to_state is MemoryState.SUPERSEDED


def test_revoked_memory_is_immediately_excluded_but_history_remains() -> None:
    embedder = DeterministicEmbedder()
    recalled = memory(embedder, "2026.07.31", 1.0, "reduce concurrency")
    store = InMemoryStore([recalled])
    service = IncidentService(store, embedder, DeterministicReasoner())
    before = service.analyze(incident().model_copy(update={"idempotency_key": "before-revoke"}))
    assert before.memories[0].memory.id == recalled.id

    revoked = service.govern_memory(
        recalled.id,
        MemoryGovernanceRequest(
            tenant_id="demo",
            actor_id="reviewer-2",
            action=GovernanceAction.REVOKE,
            reason="new evidence invalidated the remediation",
        ),
    )
    assert revoked is not None and revoked.state is MemoryState.REVOKED

    after = service.analyze(incident().model_copy(update={"idempotency_key": "after-revoke"}))
    assert after.memories == []
    assert after.proposed_action.risk is ActionRisk.READ_ONLY
    assert store.memory_events[-1].from_state is MemoryState.ACTIVE
    assert store.memory_events[-1].to_state is MemoryState.REVOKED


def test_positive_evidence_decays_but_known_failure_penalty_persists() -> None:
    embedder = DeterministicEmbedder()
    as_of = datetime(2026, 8, 1, tzinfo=UTC)
    created_at = as_of - timedelta(days=360)
    success_payload = memory(
        embedder, "2026.07.31", 1.0, "successful remediation"
    ).model_dump()
    success_payload.update({"confidence": 1.0, "created_at": created_at, "memory_digest": None})
    success = Memory.model_validate(success_payload)
    failure_payload = memory(
        embedder, "2026.07.31", -1.0, "failed remediation"
    ).model_dump()
    failure_payload.update({"confidence": 1.0, "created_at": created_at, "memory_digest": None})
    failure = Memory.model_validate(failure_payload)

    ranked_success = rank_memory(success, 1.0, "2026.07.31", as_of=as_of)
    ranked_failure = rank_memory(failure, 1.0, "2026.07.31", as_of=as_of)
    assert ranked_success.freshness == pytest.approx(0.25)
    assert ranked_success.effective_confidence == pytest.approx(0.25)
    assert ranked_failure.rank_score < ranked_success.rank_score


def test_manual_outcome_confidence_is_conservatively_capped() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    learned = service.learn_outcome(
        analysis.incident_id,
        OutcomeObservation(
            tenant_id="demo",
            action_taken=attest(service, analysis, "operator-1"),
            outcome="operator reports recovery",
            outcome_score=1.0,
            confidence=1.0,
            actor_id="operator-1",
        ),
    )
    assert learned is not None
    assert learned.confidence == 0.70


def test_system_observed_outcome_requires_bounded_verifiable_evidence() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(
        InMemoryStore(),
        embedder,
        DeterministicReasoner(),
        evidence_verifier=AcceptingEvidenceVerifier(),
    )
    analysis = service.analyze(incident())
    action_taken = attest(service, analysis, "operator-1")
    observation = OutcomeObservation(
        tenant_id="demo",
        action_taken=action_taken,
        outcome="latency remained below the service objective",
        outcome_score=1.0,
        confidence=0.95,
        actor_id="operator-1",
        evidence_verification=EvidenceVerification.SYSTEM_OBSERVED,
        evidence_refs=["cloudwatch://demo/checkout/latency-query/abc123"],
        observation_window_seconds=900,
        postconditions=["p95 latency below 300ms", "error rate below 1%"],
    )
    learned = service.learn_outcome(analysis.incident_id, observation)
    assert learned is not None
    assert learned.confidence == 0.90


def test_client_cannot_self_assert_system_evidence() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    action_taken = attest(service, analysis, "operator-1")
    with pytest.raises(IncidentWorkflowError, match="could not be verified"):
        service.learn_outcome(
            analysis.incident_id,
            OutcomeObservation(
                tenant_id="demo",
                action_taken=action_taken,
                outcome="unverified recovery claim",
                outcome_score=1.0,
                confidence=1.0,
                actor_id="operator-1",
                evidence_verification=EvidenceVerification.SYSTEM_OBSERVED,
                evidence_refs=["cloudwatch://alarm/fabricated"],
                observation_window_seconds=900,
                postconditions=["latency recovered"],
            ),
        )


def test_analysis_exposes_bounded_plan_and_candidate_dispositions() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(
        InMemoryStore([memory(embedder, "2026.07.31", 1.0, "reduce concurrency")]),
        embedder,
        DeterministicReasoner(),
    )
    analysis = service.analyze(incident())
    assert [step.tool for step in analysis.plan] == [
        "embed_incident",
        "retrieve_governed_memory",
        "reason_from_evidence",
    ]
    assert analysis.candidate_decisions[0].disposition == "selected"
    assert "historical_symptom" in analysis.diagnosis


def test_analysis_records_bounded_read_only_diagnostics() -> None:
    tools = ReadOnlyDiagnosticTools(FakeAlarms(), FakeDeployments())
    analysis = IncidentService(
        InMemoryStore(), DeterministicEmbedder(), DeterministicReasoner(), diagnostic_tools=tools
    ).analyze(incident())
    assert [step.tool for step in analysis.plan] == [
        "embed_incident",
        "retrieve_governed_memory",
        "inspect_cloudwatch_alarms",
        "inspect_ecs_deployments",
        "reason_from_evidence",
    ]
    assert [item.sequence for item in analysis.agent_trace] == [1, 2, 3, 4, 5]
    assert analysis.agent_trace[2].evidence_refs == ["urn:recallops:diagnostic:alarm:test"]
    assert "diagnostics" in analysis.diagnosis


def test_candidate_policy_records_each_rejection_reason() -> None:
    embedder = DeterministicEmbedder()
    item = memory(embedder, "2025.01", 1.0, "old action")
    candidate = RetrievedMemory(
        memory=item,
        semantic_similarity=0.1,
        compatibility=0.0,
        effective_confidence=0.1,
        freshness=1.0,
        rank_score=0.1,
    )
    service = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    reasons = service._abstention_reasons([candidate])
    decisions = service._candidate_decisions([candidate], None)
    assert "similarity_below_threshold" in reasons
    assert "service_version_incompatible" in reasons
    assert "similarity_below_threshold" in decisions[0].reasons


def test_diagnostics_record_invalid_scope_and_provider_degradation() -> None:
    tools = ReadOnlyDiagnosticTools(
        UnavailableInspector("cloudwatch_diagnostics"),  # type: ignore[arg-type]
        UnavailableInspector("ecs_diagnostics"),  # type: ignore[arg-type]
    )
    analysis = IncidentService(
        InMemoryStore(), DeterministicEmbedder(), DeterministicReasoner(), diagnostic_tools=tools
    ).analyze(incident().model_copy(update={"service": "invalid/service"}))
    assert analysis.degraded_dependencies == ["diagnostic_scope_invalid"]
    assert [step.status for step in analysis.agent_trace[2:4]] == ["degraded", "degraded"]

    valid = IncidentService(
        InMemoryStore(), DeterministicEmbedder(), DeterministicReasoner(), diagnostic_tools=tools
    ).analyze(incident())
    assert valid.degraded_dependencies == ["cloudwatch_diagnostics", "ecs_diagnostics"]


def test_workflow_rejects_missing_and_non_executable_analyses() -> None:
    embedder = DeterministicEmbedder()
    store = InMemoryStore()
    service = IncidentService(store, embedder, DeterministicReasoner())
    missing = IncidentService(InMemoryStore(), embedder, DeterministicReasoner())
    analysis = service.analyze(incident())
    request = ApprovalRequest(
        tenant_id="demo",
        actor_id="reviewer",
        approved=True,
        proposal_hash="0" * 64,
        reason="reviewed",
    )
    assert missing.decide_approval(analysis.incident_id, request) is False
    with pytest.raises(IncidentWorkflowError, match="does not require approval"):
        service.decide_approval(analysis.incident_id, request)

    execution_request = ExecutionAttestationRequest(
        tenant_id="demo",
        actor_id="operator",
        action_hash=analysis.proposed_action.action_hash,
        action_taken=analysis.proposed_action.command,
        evidence_refs=["test://execution/verified"],
    )
    assert missing.attest_execution(analysis.incident_id, execution_request) is None
    store.analyses[("demo", analysis.incident_id)] = analysis.model_copy(
        update={
            "proposed_action": analysis.proposed_action.model_copy(update={"action_hash": None})
        }
    )
    with pytest.raises(IncidentWorkflowError, match="lacks an executable"):
        service.attest_execution(analysis.incident_id, execution_request)


def test_outcome_requires_matching_execution_and_bounded_observation() -> None:
    embedder = DeterministicEmbedder()
    service = IncidentService(
        InMemoryStore(),
        embedder,
        DeterministicReasoner(),
        evidence_verifier=AcceptingEvidenceVerifier(),
    )
    analysis = service.analyze(incident())
    base = OutcomeObservation(
        tenant_id="demo",
        action_taken=analysis.proposed_action.command,
        outcome="recovered",
        outcome_score=1,
        confidence=1,
        actor_id="operator",
    )
    with pytest.raises(IncidentWorkflowError, match="execution attestation required"):
        service.learn_outcome(analysis.incident_id, base)
    attest(service, analysis, "operator")
    with pytest.raises(IncidentWorkflowError, match="does not match execution"):
        service.learn_outcome(
            analysis.incident_id, base.model_copy(update={"action_taken": "other"})
        )
    system = base.model_copy(
        update={
            "evidence_verification": EvidenceVerification.SYSTEM_OBSERVED,
            "evidence_refs": ["cloudwatch://verified"],
        }
    )
    with pytest.raises(IncidentWorkflowError, match="observation window"):
        service.learn_outcome(analysis.incident_id, system)
