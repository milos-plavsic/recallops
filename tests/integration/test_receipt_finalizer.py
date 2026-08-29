import json
import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psycopg
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recallops.authority_archive import ArchivedBundle
from recallops.authority_bundle import read_bundle_zip, sha256_bytes
from recallops.canonical import canonical_bytes, content_digest
from recallops.domain import (
    CompatibilityPolicy,
    EvidenceVerification,
    Memory,
    MemoryOutcome,
    MemoryState,
    PolicyVerdict,
    PostcheckAssessment,
    PostcheckClassification,
    PostcheckObservation,
    SandboxExecution,
    SandboxMetrics,
)
from recallops.ledger import (
    ZERO_EVENT_HASH,
    AuthorityEvent,
    authority_event_hash,
    canonical_event_payload,
)
from recallops.receipt_finalizer import (
    PostgresReceiptMaterialLoader,
    ReceiptDocuments,
    ReceiptFinalizationWorker,
    ReceiptMaterialError,
)
from recallops.receipt_outbox import ReceiptRequest
from recallops.receipts import (
    AWS_KEY_SPEC,
    AWS_KEY_USAGE,
    AWS_SIGNING_ALGORITHM,
    KmsReceiptSigner,
    ReceiptDigestBindings,
    TrustedKey,
    TrustedKeyDocument,
    TrustedKeyRegistry,
    jwk_thumbprint,
    public_jwk_from_der,
    transition_binding_digest,
)
from recallops.sandbox import policy_verdict_digest
from recallops.store import PostgresStore
from recallops.workflow import CAPABILITIES, RequestChannel, WorkflowState

RUN_ID = UUID("20000000-0000-0000-0000-000000000042")
WORKFLOW_ID = UUID("30000000-0000-0000-0000-000000000042")
SOURCE_SHA = "a" * 40
RELEASE_ID = "release-bundle-vector-v1"
IMAGE_DIGEST = f"sha256:{'b' * 64}"


class FakeKms:
    key_id = "arn:aws:kms:us-east-1:111122223333:key/integration-receipt"

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key

    def get_public_key(self, **kwargs: object) -> dict[str, object]:
        return {
            "KeyId": self.key_id,
            "KeySpec": AWS_KEY_SPEC,
            "KeyUsage": AWS_KEY_USAGE,
            "SigningAlgorithms": [AWS_SIGNING_ALGORITHM],
            "PublicKey": self.key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        }

    def sign(self, **kwargs: object) -> dict[str, object]:
        message = kwargs["Message"]
        assert isinstance(message, bytes)
        return {
            "KeyId": self.key_id,
            "SigningAlgorithm": AWS_SIGNING_ALGORITHM,
            "Signature": self.key.sign(message),
        }


class StaticDocuments:
    def __init__(self, documents: ReceiptDocuments) -> None:
        self.documents = documents

    def load(self, evaluation_version: str) -> ReceiptDocuments:
        assert evaluation_version == "governed-benchmark-v1"
        return self.documents


class CapturingArchive:
    def __init__(self) -> None:
        self.files = None

    def persist(self, receipt_id, archive, bundle_digest):
        self.files = read_bundle_zip(archive)
        return ArchivedBundle(
            bucket="private",
            object_key=f"synthetic-authority-bundles/{receipt_id}/authority-bundle.zip",
            version_id="version-integration-1",
            bundle_digest=bundle_digest,
        )


def receipt_events(digests: ReceiptDigestBindings) -> list[AuthorityEvent]:
    steps = (
        ("system", "allocator", "ABSENT", "INVESTIGATING", None, None),
        (
            "agent",
            "agent-42",
            "INVESTIGATING",
            "AWAITING_OPERATOR_APPROVAL",
            "proposal",
            digests.proposal,
        ),
        (
            "operator",
            "operator-42",
            "AWAITING_OPERATOR_APPROVAL",
            "APPROVED_AWAITING_EXECUTION",
            "proposal",
            digests.proposal,
        ),
        (
            "operator",
            "operator-42",
            "APPROVED_AWAITING_EXECUTION",
            "OBSERVING_POSTCHECK",
            "execution_binding",
            transition_binding_digest(
                "execution", {"execution": digests.execution, "proposal": digests.proposal}
            ),
        ),
        (
            "system",
            "observer",
            "OBSERVING_POSTCHECK",
            "POSTCHECK_READY",
            "observation_binding",
            transition_binding_digest(
                "observation",
                {
                    "execution": digests.execution,
                    "observation": digests.observation,
                    "policy_verdict": digests.policy_verdict,
                },
            ),
        ),
        (
            "agent",
            "agent-42",
            "POSTCHECK_READY",
            "PENDING_REVIEW",
            "outcome_binding",
            transition_binding_digest(
                "outcome",
                {
                    "assessment": digests.assessment,
                    "memory": digests.memory,
                    "observation": digests.observation,
                    "policy_verdict": digests.policy_verdict,
                },
            ),
        ),
        (
            "reviewer",
            "reviewer-42",
            "PENDING_REVIEW",
            "REVIEWED",
            "review_binding",
            transition_binding_digest(
                "review",
                {
                    "disposition": sha256_bytes(b"certify"),
                    "memory": digests.memory,
                    "review": digests.review,
                },
            ),
        ),
    )
    previous = ZERO_EVENT_HASH
    result: list[AuthorityEvent] = []
    for sequence, (role, subject, before, after, object_type, object_digest) in enumerate(
        steps, start=1
    ):
        event = AuthorityEvent(
            event_id=UUID(f"40000000-0000-0000-0000-{sequence:012d}"),
            run_id=RUN_ID,
            tenant_id="judge-bundle-vector",
            sequence=sequence,
            recorded_at=datetime(2026, 8, 29, 4, 0, sequence, tzinfo=UTC),
            event_type="RUN_GENESIS" if sequence == 1 else f"{before}_TO_{after}",
            actor_subject=subject,
            actor_role=role,
            channel=(
                RequestChannel.SYSTEM
                if role == "system"
                else RequestChannel.WEBMCP
                if role == "agent"
                else RequestChannel.UI
            ),
            workflow_id=WORKFLOW_ID,
            epoch_before=sequence - 1,
            epoch_after=sequence,
            state_before=before,
            state_after=after,
            capabilities_before=(
                () if before == "ABSENT" else CAPABILITIES[WorkflowState(before)]
            ),
            capabilities_after=CAPABILITIES[WorkflowState(after)],
            object_type=object_type,
            object_id=(
                digests.review
                if after == "REVIEWED"
                else str(WORKFLOW_ID)
                if object_type
                else None
            ),
            object_digest=object_digest,
            reason_code="MEMORY_CERTIFY" if after == "REVIEWED" else "ACCEPTED",
            display_summary=f"Authority committed: {before} to {after}",
            policy_version="webmcp-capability-v1",
            build_sha=SOURCE_SHA,
            previous_event_hash=previous,
            event_hash=ZERO_EVENT_HASH,
        )
        event = event.model_copy(
            update={"event_hash": authority_event_hash(previous, canonical_event_payload(event))}
        )
        result.append(event)
        previous = event.event_hash
    return result


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required",
)
def test_postgres_material_loader_recomputes_domain_digests_and_exact_ledger_prefix() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    tenant = "judge-bundle-vector"
    created = datetime(2026, 8, 29, 4, 0, tzinfo=UTC)
    receipt_created = datetime(2026, 8, 29, 4, 1, tzinfo=UTC)
    metrics_before = SandboxMetrics(
        worker_concurrency=64,
        saturated_connections=40,
        latency_p95_ms=1420,
        error_rate=0.031,
    )
    metrics_after = SandboxMetrics(
        worker_concurrency=24,
        saturated_connections=3,
        latency_p95_ms=210,
        error_rate=0.004,
    )
    proposal_digest = "1" * 64
    execution = SandboxExecution(
        id=uuid4(),
        incident_id=WORKFLOW_ID,
        tenant_id=tenant,
        actor_id="operator-42",
        proposal_hash=proposal_digest,
        action_id="checkout.reduce_concurrency_and_recycle.v1",
        simulator_version="checkout-simulator-v1",
        idempotency_key="receipt-execution-0001",
        before=metrics_before,
        after=metrics_after,
        execution_digest="2" * 64,
        created_at=created,
    )
    observation = PostcheckObservation(
        id=uuid4(),
        execution_id=execution.id,
        incident_id=WORKFLOW_ID,
        tenant_id=tenant,
        proposal_hash=proposal_digest,
        execution_digest=execution.execution_digest,
        source="checkout-simulator-telemetry-v1",
        observation_window_seconds=300,
        before=metrics_before,
        after=metrics_after,
        observation_digest="3" * 64,
        observed_at=created + timedelta(seconds=1),
    )
    assessment = PostcheckAssessment(
        id=uuid4(),
        observation_id=observation.id,
        incident_id=WORKFLOW_ID,
        tenant_id=tenant,
        agent_subject="agent-42",
        classification=PostcheckClassification.RECOVERED,
        rationale="All bounded recovery checks passed.",
        observation_digest=observation.observation_digest,
        created_at=created + timedelta(seconds=2),
    )
    assessment_digest = content_digest(
        "recallops-assessment-v1",
        {
            "observation_digest": assessment.observation_digest,
            "agent_subject": assessment.agent_subject,
            "classification": assessment.classification.value,
            "rationale": assessment.rationale,
            "created_at": assessment.created_at.isoformat().replace("+00:00", "Z"),
        },
    )
    verdict = PolicyVerdict(
        classification=PostcheckClassification.RECOVERED,
        policy_version="checkout-recovery-policy-v1",
        checks_passed=[
            "LATENCY_RECOVERY_THRESHOLD",
            "ERROR_RATE_RECOVERY_THRESHOLD",
            "SATURATION_RECOVERY_THRESHOLD",
        ],
        checks_failed=[],
        observation_digest=observation.observation_digest,
        computed_at=created + timedelta(seconds=1),
    )
    verdict_digest = policy_verdict_digest(verdict)
    memory = Memory(
        id=uuid4(),
        tenant_id=tenant,
        service="checkout",
        service_version="2026.07.31",
        compatibility_policy=CompatibilityPolicy.EXACT,
        compatibility_policy_version="semver-v1",
        symptom="latency spike after connection pool exhaustion",
        action="reduce worker concurrency to 24 and recycle saturated connections",
        outcome="verified recovery after sandbox remediation",
        outcome_score=1.0,
        outcome_semantics=MemoryOutcome.POSITIVE,
        confidence=1.0,
        valid=True,
        state=MemoryState.ACTIVE,
        source_incident_id=WORKFLOW_ID,
        observed_by=assessment.agent_subject,
        reviewed_by="reviewer-42",
        reviewed_at=created + timedelta(seconds=7),
        evidence_verification=EvidenceVerification.SYSTEM_OBSERVED,
        evidence_refs=[f"urn:recallops:observation:{observation.id}"],
        observation_window_seconds=300,
        postconditions=verdict.checks_passed,
        observation_digest=observation.observation_digest,
        assessment_digest=assessment_digest,
        verdict_digest=verdict_digest,
        governance_policy_version="memory-governance-v1",
        governance_version=2,
        expires_at=created + timedelta(days=180),
        embedding=[0.0] * 1024,
        created_at=created + timedelta(seconds=3),
    )
    review_digest = "7" * 64
    digests = ReceiptDigestBindings(
        proposal=proposal_digest,
        execution=execution.execution_digest,
        observation=observation.observation_digest,
        assessment=assessment_digest,
        policy_verdict=verdict_digest,
        memory=str(memory.memory_digest),
        review=review_digest,
    )
    events = receipt_events(digests)
    signing_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    public_der = signing_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_jwk = public_jwk_from_der(public_der)
    key_thumbprint = jwk_thumbprint(public_jwk)
    registry = TrustedKeyRegistry(
        TrustedKeyDocument(
            registry_version="trusted-receipt-keys-v1",
            keys=(
                TrustedKey(
                    kid=key_thumbprint,
                    jwk=public_jwk,
                    trust="repository_root",
                    status="active",
                    release_ids=(RELEASE_ID,),
                ),
            ),
            transitions=(),
        )
    )
    signer = KmsReceiptSigner(
        FakeKms(signing_key), "alias/recallops-integration", RELEASE_ID, registry
    )
    assert signer.preflight() == key_thumbprint
    receipt_id, receipt_request_id = uuid4(), uuid4()
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE receipt_requests,authority_receipts,release_evidence_records,"
            "activity_observations,authority_events,authority_ledger_heads,judge_auth_attempts,"
            "review_handoffs,judge_sessions,judge_runs,postcheck_assessments,"
            "postcheck_policy_verdicts,postcheck_observations,sandbox_executions,"
            "webmcp_workflows,memory_events,execution_attestations,approvals,evidence_outbox,"
            "memories,incidents CASCADE"
        )
        connection.execute(
            """INSERT INTO incidents
            (id,tenant_id,service,service_version,symptom,idempotency_key,status,analysis)
            VALUES (%s,%s,'checkout','2026.07.31','latency spike after connection pool exhaustion',
            'receipt-material-fixture','open','{}'::JSONB)""",
            (WORKFLOW_ID, tenant),
        )
        connection.execute(
            """INSERT INTO webmcp_workflows
            (workflow_id,tenant_id,state,epoch,active,operator_subject,reviewer_subject)
            VALUES (%s,%s,'REVIEWED',7,true,'operator-42','reviewer-42')""",
            (WORKFLOW_ID, tenant),
        )
        connection.execute(
            """INSERT INTO judge_runs
            (run_id,tenant_id,generation,scenario_version,source_incident_id,status,
             operator_subject,build_sha,capability_policy_version,expires_at)
            VALUES (%s,%s,1,'checkout-latency-v1',%s,'completed','operator-42',%s,
            'webmcp-capability-v1',now() + interval '10 minutes')""",
            (RUN_ID, tenant, WORKFLOW_ID, SOURCE_SHA),
        )
        connection.execute(
            """INSERT INTO release_evidence_records
            (release_id,source_sha,image_digest,capability_policy_version,
             receipt_policy_version,evaluation_version,receipt_key_thumbprint,
             live_proof_status,assurance_status)
            VALUES (%s,%s,%s,'webmcp-capability-v1','authority-receipt-policy-v1',
            'governed-benchmark-v1',%s,'pending','pending')""",
            (RELEASE_ID, SOURCE_SHA, IMAGE_DIGEST, key_thumbprint),
        )
        for event in events:
            payload = event.model_dump(mode="python")
            connection.execute(
                """INSERT INTO authority_events
                (event_id,run_id,tenant_id,sequence,recorded_at,event_type,outcome,
                 actor_subject,actor_role,channel,workflow_id,epoch_before,epoch_after,
                 state_before,state_after,capabilities_before,capabilities_after,object_type,
                 object_id,object_digest,reason_code,display_summary,policy_version,build_sha,
                 previous_event_hash,event_hash)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::JSONB,%s::JSONB,
                %s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    event.event_id,
                    event.run_id,
                    event.tenant_id,
                    event.sequence,
                    event.recorded_at,
                    event.event_type,
                    event.outcome,
                    event.actor_subject,
                    event.actor_role,
                    event.channel,
                    event.workflow_id,
                    event.epoch_before,
                    event.epoch_after,
                    event.state_before,
                    event.state_after,
                    json.dumps(payload["capabilities_before"]),
                    json.dumps(payload["capabilities_after"]),
                    event.object_type,
                    event.object_id,
                    event.object_digest,
                    event.reason_code,
                    event.display_summary,
                    event.policy_version,
                    event.build_sha,
                    event.previous_event_hash,
                    event.event_hash,
                ),
            )
        connection.execute(
            """INSERT INTO authority_ledger_heads
            (run_id,tenant_id,last_sequence,last_event_hash,ledger_version)
            VALUES (%s,%s,%s,%s,'authority-ledger-v1')""",
            (RUN_ID, tenant, len(events), events[-1].event_hash),
        )
        connection.execute(
            """INSERT INTO authority_receipts
            (receipt_id,run_id,tenant_id,ledger_head_hash,ledger_last_sequence,
             receipt_policy_version,source_sha,image_digest,evaluation_version,status,synthetic,
             created_at)
            VALUES (%s,%s,%s,%s,%s,'authority-receipt-policy-v1',%s,%s,
            'governed-benchmark-v1','pending',true,%s)""",
            (
                receipt_id,
                RUN_ID,
                tenant,
                events[-1].event_hash,
                len(events),
                SOURCE_SHA,
                IMAGE_DIGEST,
                receipt_created,
            ),
        )
        connection.execute(
            """INSERT INTO receipt_requests
            (request_id,receipt_id,run_id,tenant_id,target_sequence,target_ledger_hash,
             publish_public,created_at)
            VALUES (%s,%s,%s,%s,%s,%s,true,%s)""",
            (
                receipt_request_id,
                receipt_id,
                RUN_ID,
                tenant,
                len(events),
                events[-1].event_hash,
                receipt_created,
            ),
        )
    store = PostgresStore(database_url)
    try:
        assert store.record_approval(
            WORKFLOW_ID, tenant, "operator-42", True, proposal_digest, "approved exact digest"
        )
        store.record_sandbox_execution(execution)
        store.record_postcheck(observation, verdict)
        store.record_postcheck_assessment(assessment)
        store.save_outcome_memory(memory)
    finally:
        store.close()
    request = ReceiptRequest(
        request_id=receipt_request_id,
        receipt_id=receipt_id,
        run_id=RUN_ID,
        tenant_id=tenant,
        target_sequence=len(events),
        target_ledger_hash=events[-1].event_hash,
        publish_public=True,
        attempts=1,
        created_at=receipt_created,
        receipt_policy_version="authority-receipt-policy-v1",
        source_sha=SOURCE_SHA,
        image_digest=IMAGE_DIGEST,
        evaluation_version="governed-benchmark-v1",
        synthetic=True,
    )
    documents = ReceiptDocuments(
        evaluation_case={"evaluation_version": request.evaluation_version},
        evaluation_result={"evaluation_version": request.evaluation_version},
        claims={"claims": [], "schema_version": "claim-registry-v1"},
    )
    loader = PostgresReceiptMaterialLoader(database_url)
    material = loader.load(
        request,
        release_id=RELEASE_ID,
        key_thumbprint=key_thumbprint,
        documents=documents,
    )
    assert material.digests == digests
    assert material.final_disposition == "certify"
    assert material.events[-1].event_hash == request.target_ledger_hash
    assert canonical_bytes(material.documents.claims) == canonical_bytes(documents.claims)

    archive = CapturingArchive()
    finalized = ReceiptFinalizationWorker(
        database_url=database_url,
        worker_id="integration-worker-1",
        release_id=RELEASE_ID,
        subject_pseudonym_key=b"integration-pseudonym-key-32bytes!",
        documents=StaticDocuments(documents),
        loader=loader,
        signer=signer,
        archive=archive,
    ).run_once()
    assert finalized.status == "signed" and archive.files is not None
    with psycopg.connect(database_url) as connection:
        finalized_row = connection.execute(
            """SELECT r.status,r.public_at,r.s3_version_id,q.status,q.delivered_at
            FROM authority_receipts r JOIN receipt_requests q ON q.receipt_id=r.receipt_id
            WHERE r.receipt_id=%s""",
            (receipt_id,),
        ).fetchone()
    assert finalized_row is not None
    assert finalized_row[0] == "signed" and finalized_row[1] is not None
    assert finalized_row[2:4] == ("version-integration-1", "delivered")
    assert finalized_row[4] is not None

    with psycopg.connect(database_url) as connection:
        connection.execute(
            "UPDATE postcheck_assessments SET rationale='tampered after review' WHERE id=%s",
            (assessment.id,),
        )
    with pytest.raises(ReceiptMaterialError, match="stored evidence digests"):
        loader.load(
            request,
            release_id=RELEASE_ID,
            key_thumbprint=key_thumbprint,
            documents=documents,
        )
