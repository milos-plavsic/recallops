import json
from datetime import UTC, datetime, timedelta
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr, ValidationError

from recallops.api import create_app
from recallops.canonical import canonical_bytes, content_digest
from recallops.config import Settings
from recallops.domain import (
    GovernanceAction,
    IncidentCreate,
    Memory,
    MemoryGovernanceRequest,
    MemoryState,
    ReviewerDispositionRequest,
    ReviewerRevocationRequest,
    ReviewReasonCode,
)
from recallops.embedding import DeterministicEmbedder
from recallops.service import DeterministicReasoner, IncidentService
from recallops.store import InMemoryStore, MemoryGovernanceError
from recallops.workflow import WorkflowState

EMBEDDER = DeterministicEmbedder()


def memory(
    *,
    state: MemoryState = MemoryState.ACTIVE,
    score: float = 1.0,
    tenant: str = "tenant-a",
    version: str = "v2.4.1",
    suffix: str = "base",
    expires_at: datetime | None = None,
    source_incident_id: UUID | None = None,
    observed_by: str = "agent-assessor",
) -> Memory:
    return Memory(
        tenant_id=tenant,
        service="checkout",
        service_version=version,
        symptom=f"checkout latency {suffix}",
        action=f"bounded action {suffix}",
        outcome="measured outcome",
        outcome_score=score,
        confidence=0.95,
        valid=state is MemoryState.ACTIVE,
        state=state,
        source_incident_id=source_incident_id,
        observed_by=observed_by,
        reviewed_by="reviewer-a" if state is not MemoryState.PENDING_REVIEW else None,
        reviewed_at=datetime.now(UTC) if state is not MemoryState.PENDING_REVIEW else None,
        expires_at=expires_at,
        embedding=EMBEDDER.embed(f"checkout latency {suffix}"),
    )


def incident(tenant: str = "tenant-a") -> IncidentCreate:
    return IncidentCreate(
        tenant_id=tenant,
        service="checkout",
        service_version="v2.4.1",
        symptom="checkout latency base",
        idempotency_key=f"incident-{tenant}",
    )


def judge_settings() -> Settings:
    return Settings(
        store="memory",
        auth_mode="judge",
        public_origin="http://testserver",
        judge_rate_limit_key=SecretStr("test-rate-limit-key-with-enough-entropy"),
        judge_cookie_secure=False,
    )


def start_run(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/v1/judge/runs",
        headers={"Origin": "http://testserver", "Content-Type": "application/json"},
        json={},
    )
    assert response.status_code == 201
    return cast(dict[str, object], response.json())


def test_rfc8785_canonicalization_and_domain_separation() -> None:
    left = {"z": 1, "a": [True, "é"], "nested": {"b": 2, "a": 1}}
    right = {"nested": {"a": 1, "b": 2}, "a": [True, "é"], "z": 1}
    assert canonical_bytes(left) == canonical_bytes(right)
    assert content_digest("memory-v1", left) == content_digest("memory-v1", right)
    assert content_digest("memory-v1", left) != content_digest("review-v1", left)
    assert json.loads(canonical_bytes(left)) == left
    for invalid_domain in ("", "contains\x00nul", "non-ascii-é"):
        with pytest.raises(ValueError, match="digest domain"):
            content_digest(invalid_domain, left)


def test_memory_rejects_claimed_outcome_or_digest_that_does_not_match_evidence() -> None:
    source = memory(suffix="binding")
    payload = source.model_dump()
    payload["outcome_semantics"] = "negative"
    with pytest.raises(ValidationError, match="outcome semantics"):
        Memory.model_validate(payload)
    payload = source.model_dump()
    payload["memory_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="memory digest"):
        Memory.model_validate(payload)


@given(st.text(min_size=1, max_size=40))
def test_every_significant_memory_mutation_changes_digest(action: str) -> None:
    first = memory(suffix="digest-a")
    changed_payload = first.model_dump()
    changed_payload.update({"memory_digest": None, "action": action})
    changed = Memory.model_validate(changed_payload)
    if action == first.action:
        assert changed.memory_digest == first.memory_digest
    else:
        assert changed.memory_digest != first.memory_digest


@pytest.mark.parametrize(
    "state",
    [
        MemoryState.PENDING_REVIEW,
        MemoryState.QUARANTINED,
        MemoryState.REJECTED,
        MemoryState.SUPERSEDED,
        MemoryState.REVOKED,
        MemoryState.EXPIRED,
    ],
)
def test_nonadmissible_lifecycle_states_are_filtered_before_ranking(state: MemoryState) -> None:
    candidate = memory(state=state, suffix=state.value)
    store = InMemoryStore([candidate])
    assert store.find_memories(
        incident(), EMBEDDER.embed("checkout latency base"), EMBEDDER.space_id, 3
    ) == []


def test_expired_cross_tenant_and_inconclusive_memory_never_reaches_ranking() -> None:
    store = InMemoryStore(
        [
            memory(suffix="expired", expires_at=datetime.now(UTC) - timedelta(seconds=1)),
            memory(tenant="tenant-b", suffix="other-tenant"),
            memory(score=0, suffix="inconclusive"),
        ]
    )
    assert store.find_memories(
        incident(), EMBEDDER.embed("checkout latency base"), EMBEDDER.space_id, 3
    ) == []


def test_certified_negative_warns_but_cannot_be_recommended() -> None:
    negative = memory(score=-1, suffix="base")
    positive = memory(score=1, suffix="compatible")
    store = InMemoryStore([negative, positive])
    service = IncidentService(store, EMBEDDER, DeterministicReasoner())
    recurrence = service.recurrence_view(incident())
    assert recurrence.governed_memory_id == positive.id
    assert recurrence.negative_warning_memory_ids == [negative.id]
    assert recurrence.governed_memory_id != negative.id


def test_governance_reason_outcome_and_digest_invariants() -> None:
    pending = memory(state=MemoryState.PENDING_REVIEW, score=0, suffix="pending")
    store = InMemoryStore([pending])
    original_digest = pending.memory_digest
    with pytest.raises(MemoryGovernanceError, match="inconclusive"):
        store.govern_memory(
            pending.id,
            MemoryGovernanceRequest(
                tenant_id=pending.tenant_id,
                actor_id="reviewer-b",
                action=GovernanceAction.CERTIFY,
                reason="accepted",
                reason_code=ReviewReasonCode.EVIDENCE_ACCEPTED,
            ),
        )
    with pytest.raises(ValidationError, match="reason code"):
        ReviewerDispositionRequest(
            decision="certify",
            memory_digest=cast(str, pending.memory_digest),
            reason_code="POLICY_CONFLICT",
        )
    with pytest.raises(ValidationError, match="requires a reviewer note"):
        ReviewerRevocationRequest(
            memory_digest=cast(str, pending.memory_digest),
            reason_code="OTHER_BOUNDED",
        )
    with pytest.raises(ValidationError, match="requires a reviewer note"):
        ReviewerDispositionRequest(
            decision="quarantine",
            memory_digest=cast(str, pending.memory_digest),
            reason_code="OTHER_BOUNDED",
        )
    with pytest.raises(ValidationError, match="valid for revocation"):
        ReviewerRevocationRequest(
            memory_digest=cast(str, pending.memory_digest),
            reason_code="EVIDENCE_ACCEPTED",
        )
    assert pending.memory_digest == original_digest
    assert store.memory_events == []

    positive = memory(state=MemoryState.PENDING_REVIEW, suffix="positive-pending")
    store = InMemoryStore([positive])
    with pytest.raises(MemoryGovernanceError, match="EVIDENCE_ACCEPTED"):
        store.govern_memory(
            positive.id,
            MemoryGovernanceRequest(
                tenant_id=positive.tenant_id,
                actor_id="reviewer-b",
                action=GovernanceAction.CERTIFY,
                reason="policy conflict",
                reason_code=ReviewReasonCode.POLICY_CONFLICT,
            ),
        )
    active = memory(suffix="active-reason")
    store = InMemoryStore([active])
    with pytest.raises(MemoryGovernanceError, match="invalid revocation reason"):
        store.govern_memory(
            active.id,
            MemoryGovernanceRequest(
                tenant_id=active.tenant_id,
                actor_id="reviewer-b",
                action=GovernanceAction.REVOKE,
                reason="not a revocation reason",
                reason_code=ReviewReasonCode.EVIDENCE_ACCEPTED,
            ),
        )
    with pytest.raises(MemoryGovernanceError, match="requires a reviewer note"):
        store.govern_memory(
            active.id,
            MemoryGovernanceRequest(
                tenant_id=active.tenant_id,
                actor_id="reviewer-b",
                action=GovernanceAction.REVOKE,
                reason="   ",
                reason_code=ReviewReasonCode.OTHER_BOUNDED,
            ),
        )


def test_supersession_requires_compatible_admissible_replacement() -> None:
    source = memory(suffix="source")
    incompatible = memory(version="v3.0.0", suffix="replacement")
    store = InMemoryStore([source, incompatible])
    with pytest.raises(MemoryGovernanceError, match="same-service, admissible, and conclusive"):
        store.govern_memory(
            source.id,
            MemoryGovernanceRequest(
                tenant_id=source.tenant_id,
                actor_id="reviewer-b",
                action=GovernanceAction.SUPERSEDE,
                reason="compatibility changed",
                replacement_memory_id=incompatible.id,
            ),
        )


def test_reviewer_handoff_disposition_recurrence_and_revocation_are_exactly_bound() -> None:
    store = InMemoryStore()
    app = create_app(judge_settings(), store)
    operator = TestClient(app)
    started = start_run(operator)
    run_data = cast(dict[str, object], started["run"])
    run = app.state.judge_repository.get_run(UUID(str(run_data["run_id"])))
    assert run is not None
    pending = memory(
        state=MemoryState.PENDING_REVIEW,
        tenant=run.tenant_id,
        suffix="new-reviewed-outcome",
        source_incident_id=run.source_incident_id,
    )
    pending = pending.model_copy(
        update={
            "embedding": EMBEDDER.embed(
                "checkout checkout-latency-42: p95 latency and error rate exceed the sandbox SLO"
            )
        }
    )
    store.save_outcome_memory(pending)
    repository = app.state.workflows._repository
    current = repository.get(run.source_incident_id, run.tenant_id)
    assert current is not None
    pending_workflow = repository.transition(
        run.source_incident_id,
        run.tenant_id,
        current.epoch,
        current.state,
        WorkflowState.PENDING_REVIEW,
        operator_subject=run.operator_subject,
    )
    assert operator.get("/v1/webmcp/recurrence").status_code == 409
    operator_headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": str(started["csrf_token"]),
    }
    mismatch = operator.post(
        "/v1/operator/reviewer-handoff",
        headers=operator_headers,
        json={"purpose": "initial_review", "memory_digest": "0" * 64},
    )
    assert mismatch.status_code == 409
    handoff_response = operator.post(
        "/v1/operator/reviewer-handoff",
        headers=operator_headers,
        json={"purpose": "initial_review", "memory_digest": pending.memory_digest},
    )
    assert handoff_response.status_code == 201
    code = urlsplit(handoff_response.json()["reviewer_url"]).fragment.removeprefix("review=")
    reviewer = TestClient(app)
    exchanged = reviewer.post(
        "/v1/judge/reviewer-exchange",
        headers={"Origin": "http://testserver"},
        json={"code": code},
    )
    assert exchanged.status_code == 200
    evidence = reviewer.get("/v1/reviewer/evidence")
    assert evidence.status_code == 200
    assert evidence.json()["memory"]["memory_digest"] == pending.memory_digest
    assert evidence.json()["immutable_observation"] is None
    reviewer_headers = {
        "Origin": "http://testserver",
        "X-CSRF-Token": exchanged.json()["csrf_token"],
        "If-Match": f'"{run.generation}:{pending_workflow.epoch}"',
    }
    assert (
        reviewer.post(
            "/v1/reviewer/revocation",
            headers=reviewer_headers,
            json={
                "memory_digest": pending.memory_digest,
                "reason_code": "NEW_CONTRADICTORY_EVIDENCE",
            },
        ).status_code
        == 403
    )
    assert (
        reviewer.post(
            "/v1/reviewer/disposition",
            headers=reviewer_headers,
            json={
                "decision": "certify",
                "memory_digest": "0" * 64,
                "reason_code": "EVIDENCE_ACCEPTED",
            },
        ).status_code
        == 409
    )
    stale_headers = {**reviewer_headers, "If-Match": '"1:999"'}
    assert (
        reviewer.post(
            "/v1/reviewer/disposition",
            headers=stale_headers,
            json={
                "decision": "certify",
                "memory_digest": pending.memory_digest,
                "reason_code": "EVIDENCE_ACCEPTED",
            },
        ).status_code
        == 412
    )
    assert (
        reviewer.post(
            "/v1/reviewer/disposition",
            headers={key: value for key, value in reviewer_headers.items() if key != "If-Match"},
            json={
                "decision": "certify",
                "memory_digest": pending.memory_digest,
                "reason_code": "EVIDENCE_ACCEPTED",
            },
        ).status_code
        == 428
    )
    disposition = reviewer.post(
        "/v1/reviewer/disposition",
        headers=reviewer_headers,
        json={
            "decision": "certify",
            "memory_digest": pending.memory_digest,
            "reason_code": "EVIDENCE_ACCEPTED",
        },
    )
    assert disposition.status_code == 200
    governed = store.get_memory(pending.id, run.tenant_id)
    assert governed is not None
    assert governed.state is MemoryState.ACTIVE
    assert governed.memory_digest == pending.memory_digest
    recurrence = operator.get("/v1/webmcp/recurrence")
    assert recurrence.status_code == 200
    assert recurrence.json()["governed_memory_id"] == str(pending.id)

    governed_index = store.memories.index(governed)
    expired_governed = governed.model_copy(
        update={"expires_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    store.memories[governed_index] = expired_governed
    store.outcome_memories[(run.tenant_id, run.source_incident_id)] = expired_governed
    assert (
        operator.post(
            "/v1/operator/reviewer-handoff",
            headers=operator_headers,
            json={"purpose": "revocation", "memory_digest": pending.memory_digest},
        ).status_code
        == 409
    )
    store.memories[governed_index] = governed
    store.outcome_memories[(run.tenant_id, run.source_incident_id)] = governed

    revocation_handoff = operator.post(
        "/v1/operator/reviewer-handoff",
        headers=operator_headers,
        json={"purpose": "revocation", "memory_digest": pending.memory_digest},
    )
    assert revocation_handoff.status_code == 201
    revocation_code = urlsplit(
        revocation_handoff.json()["reviewer_url"]
    ).fragment.removeprefix("review=")
    revoker = TestClient(app)
    revoker_exchange = revoker.post(
        "/v1/judge/reviewer-exchange",
        headers={"Origin": "http://testserver"},
        json={"code": revocation_code},
    )
    assert revoker_exchange.status_code == 200
    reviewed_workflow = repository.get(run.source_incident_id, run.tenant_id)
    assert reviewed_workflow is not None
    assert (
        revoker.post(
            "/v1/reviewer/revocation",
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": revoker_exchange.json()["csrf_token"],
                "If-Match": f'"{run.generation}:{reviewed_workflow.epoch}"',
            },
            json={
                "memory_digest": "0" * 64,
                "reason_code": "NEW_CONTRADICTORY_EVIDENCE",
            },
        ).status_code
        == 409
    )
    revoked = revoker.post(
        "/v1/reviewer/revocation",
        headers={
            "Origin": "http://testserver",
            "X-CSRF-Token": revoker_exchange.json()["csrf_token"],
            "If-Match": f'"{run.generation}:{reviewed_workflow.epoch}"',
        },
        json={
            "memory_digest": pending.memory_digest,
            "reason_code": "NEW_CONTRADICTORY_EVIDENCE",
            "note": "later controlled evidence contradicted the result",
        },
    )
    assert revoked.status_code == 200
    assert store.get_memory(pending.id, run.tenant_id).state is MemoryState.REVOKED  # type: ignore[union-attr]
    after_revocation = operator.get("/v1/webmcp/recurrence")
    assert after_revocation.status_code == 200
    after_payload = after_revocation.json()
    assert after_payload["governed_memory_id"] != str(pending.id)
    assert str(pending.id) not in after_payload["eligible_memory_ids"]
    assert str(pending.id) not in after_payload["negative_warning_memory_ids"]
    legacy = operator.post(
        f"/v1/memories/{pending.id}/governance",
        json={
            "tenant_id": run.tenant_id,
            "actor_id": run.operator_subject,
            "action": "revoke",
            "reason": "legacy route",
        },
    )
    assert legacy.status_code == 410
