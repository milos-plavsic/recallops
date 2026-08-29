import os
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from recallops.authority_archive import ArchivedBundle
from recallops.ledger import AuthorityLedgerConflict, PostgresAuthorityLedgerRepository
from recallops.receipt_outbox import (
    SignedReceiptResult,
    claim_receipt_request,
    finalize_receipt_request,
    release_receipt_failure,
)
from recallops.receipts import (
    ReceiptDigestBindings,
    ReceiptManifest,
    ReceiptSubjects,
    ReleaseBinding,
)
from recallops.workflow import RequestChannel, WorkflowSnapshot, WorkflowState


def manifest(run_id: UUID, workflow_id: UUID, head: str) -> ReceiptManifest:
    return ReceiptManifest(
        receipt_policy_version="receipt-v1",
        capability_policy_version="capability-v1",
        run_id=run_id,
        tenant_id_hash="8" * 64,
        scenario_version="scenario-v1",
        workflow_id=workflow_id,
        final_state="REVIEWED",
        final_disposition="certify",
        first_epoch="0",
        last_epoch="1",
        event_count="1",
        ledger_first_hash=head,
        ledger_head_hash=head,
        digests=ReceiptDigestBindings(
            proposal="1" * 64,
            execution="2" * 64,
            observation="3" * 64,
            assessment="4" * 64,
            policy_verdict="5" * 64,
            memory="6" * 64,
            review="7" * 64,
        ),
        subjects=ReceiptSubjects(operator="9" * 64, reviewer="a" * 64, separated=True),
        release=ReleaseBinding(
            release_id="release-v1",
            source_sha="b" * 40,
            image_digest=f"sha256:{'c' * 64}",
            evaluation_version="evaluation-v1",
            claim_registry_digest="d" * 64,
        ),
        evidence_index_digest="e" * 64,
        asserted_signing_time="2026-08-29T05:00:00Z",
        expires_at="2026-09-05T05:00:00Z",
        key_thumbprint="k" * 43,
    )


def seed(database_url: str, *, head: str, synthetic: bool = True) -> tuple[UUID, UUID, UUID]:
    incident_id, run_id, receipt_id = uuid4(), uuid4(), uuid4()
    tenant = f"receipt_{run_id.hex[:12]}"
    with psycopg.connect(database_url) as connection:
        connection.execute(
            """INSERT INTO incidents
            (id,tenant_id,service,service_version,symptom,idempotency_key,status,analysis)
            VALUES (%s,%s,'checkout','1.0.0','latency',%s,'open','{}'::JSONB)""",
            (incident_id, tenant, f"receipt-{incident_id}"),
        )
        connection.execute(
            """INSERT INTO judge_runs
            (run_id,tenant_id,generation,scenario_version,source_incident_id,status,
             operator_subject,build_sha,capability_policy_version,expires_at)
            VALUES (%s,%s,1,'scenario-v1',%s,'completed','operator',%s,
            'capability-v1',now() + interval '10 minutes')""",
            (run_id, tenant, incident_id, "b" * 40),
        )
        connection.execute(
            """INSERT INTO authority_receipts
            (receipt_id,run_id,tenant_id,ledger_head_hash,ledger_last_sequence,
             receipt_policy_version,source_sha,image_digest,evaluation_version,status,synthetic)
            VALUES (%s,%s,%s,%s,1,'receipt-v1',%s,%s,'evaluation-v1',
            'pending',%s)""",
            (
                receipt_id,
                run_id,
                tenant,
                head,
                "b" * 40,
                f"sha256:{'c' * 64}",
                synthetic,
            ),
        )
        connection.execute(
            """INSERT INTO receipt_requests
            (request_id,receipt_id,run_id,tenant_id,target_sequence,target_ledger_hash,
             publish_public) VALUES (%s,%s,%s,%s,1,%s,true)""",
            (uuid4(), receipt_id, run_id, tenant, head),
        )
    return incident_id, run_id, receipt_id


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required",
)
def test_receipt_claim_finalize_and_retry_are_atomic_and_idempotent() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    with psycopg.connect(database_url, autocommit=True) as connection:
        connection.execute(
            "TRUNCATE receipt_requests,authority_receipts,authority_events,"
            "authority_ledger_heads,judge_auth_attempts,review_handoffs,judge_sessions,"
            "judge_runs,webmcp_workflows,memory_events,memories,evidence_outbox,"
            "execution_attestations,approvals,incidents CASCADE"
        )
    _, run_id, receipt_id = seed(database_url, head="1" * 64)
    request = claim_receipt_request(database_url, "worker-1")
    assert request is not None and request.receipt_id == receipt_id and request.attempts == 1
    receipt_manifest = manifest(run_id, UUID(int=42), "1" * 64)
    signed = SignedReceiptResult(
        manifest_digest="2" * 64,
        jws_compact="j" * 64,
        key_thumbprint="k" * 43,
        archived=ArchivedBundle(
            bucket="private",
            object_key=f"synthetic-authority-bundles/{receipt_id}/authority-bundle.zip",
            version_id="version-1",
            bundle_digest="3" * 64,
        ),
    )
    assert finalize_receipt_request(
        database_url, request, "worker-1", receipt_manifest, signed
    )
    assert finalize_receipt_request(
        database_url, request, "worker-1", receipt_manifest, signed
    )
    with psycopg.connect(database_url) as connection:
        row = connection.execute(
            """SELECT status,synthetic,public_at,bundle_digest,s3_version_id
            FROM authority_receipts WHERE receipt_id=%s""",
            (receipt_id,),
        ).fetchone()
        request_row = connection.execute(
            "SELECT status,delivered_at FROM receipt_requests WHERE receipt_id=%s",
            (receipt_id,),
        ).fetchone()
    assert row is not None and row[0] == "signed" and row[1] and row[2] is not None
    assert row[3:] == ("3" * 64, "version-1")
    assert request_row is not None and request_row[0] == "delivered"

    _, _, failed_receipt = seed(database_url, head="4" * 64)
    failed = claim_receipt_request(database_url, "worker-2")
    assert failed is not None and failed.receipt_id == failed_receipt
    assert not release_receipt_failure(
        database_url, failed, "worker-2", "KMS_UNAVAILABLE", max_attempts=2
    )
    with psycopg.connect(database_url) as connection:
        connection.execute(
            "UPDATE receipt_requests SET available_at=now() WHERE receipt_id=%s",
            (failed_receipt,),
        )
    retried = claim_receipt_request(database_url, "worker-2")
    assert retried is not None and retried.attempts == 2
    assert release_receipt_failure(
        database_url, retried, "worker-2", "KMS_UNAVAILABLE", max_attempts=2
    )
    with psycopg.connect(database_url) as connection:
        terminal = connection.execute(
            """SELECT r.status,q.status,q.dead_lettered_at FROM authority_receipts r
            JOIN receipt_requests q ON q.receipt_id=r.receipt_id WHERE r.receipt_id=%s""",
            (failed_receipt,),
        ).fetchone()
    assert terminal is not None and terminal[0:2] == ("failed", "dead_lettered")
    assert terminal[2] is not None


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required",
)
def test_receipt_enqueue_requires_the_exact_committed_review_event() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    incident_id, run_id = uuid4(), uuid4()
    tenant = f"enqueue_{run_id.hex[:12]}"
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        connection.execute(
            """INSERT INTO incidents
            (id,tenant_id,service,service_version,symptom,idempotency_key,status,analysis)
            VALUES (%s,%s,'checkout','1.0.0','latency',%s,'open','{}'::JSONB)""",
            (incident_id, tenant, f"enqueue-{incident_id}"),
        )
        connection.execute(
            """INSERT INTO webmcp_workflows (workflow_id,tenant_id,state,epoch)
            VALUES (%s,%s,'PENDING_REVIEW',7)""",
            (incident_id, tenant),
        )
        connection.execute(
            """INSERT INTO judge_runs
            (run_id,tenant_id,generation,scenario_version,source_incident_id,status,
             operator_subject,build_sha,capability_policy_version,expires_at)
            VALUES (%s,%s,1,'scenario-v1',%s,'completed','operator',%s,
            'capability-v1',now() + interval '10 minutes')""",
            (run_id, tenant, incident_id, "b" * 40),
        )
        before = WorkflowSnapshot(
            workflow_id=incident_id,
            tenant_id=tenant,
            state=WorkflowState.PENDING_REVIEW,
            epoch=7,
        )
        after = before.model_copy(update={"state": WorkflowState.REVIEWED, "epoch": 8})
        repository = PostgresAuthorityLedgerRepository.from_connection(connection)
        event = repository.append_transition(
            before,
            after,
            actor_subject="reviewer-distinct",
            actor_role="reviewer",
            channel=RequestChannel.UI,
            reason_code="MEMORY_CERTIFIED",
            object_type="memory_review",
            object_id=str(uuid4()),
            object_digest="a" * 64,
        )
        assert event is not None
        fabricated = event.model_copy(update={"object_id": str(uuid4())})
        with pytest.raises(
            AuthorityLedgerConflict,
            match="differs from committed authority event",
        ):
            repository.request_receipt(
                fabricated,
                receipt_policy_version="receipt-v1",
                image_digest=f"sha256:{'c' * 64}",
                evaluation_version="evaluation-v1",
                synthetic=True,
                publish_public=True,
            )
        receipt_id = repository.request_receipt(
            event,
            receipt_policy_version="receipt-v1",
            image_digest=f"sha256:{'c' * 64}",
            evaluation_version="evaluation-v1",
            synthetic=True,
            publish_public=True,
        )
        receipt = connection.execute(
            """SELECT ledger_head_hash,ledger_last_sequence,status FROM authority_receipts
            WHERE receipt_id=%s""",
            (receipt_id,),
        ).fetchone()
        request = connection.execute(
            """SELECT target_ledger_hash,target_sequence,status,publish_public
            FROM receipt_requests WHERE receipt_id=%s""",
            (receipt_id,),
        ).fetchone()
    assert receipt == {
        "ledger_head_hash": event.event_hash,
        "ledger_last_sequence": event.sequence,
        "status": "pending",
    }
    assert request == {
        "target_ledger_hash": event.event_hash,
        "target_sequence": event.sequence,
        "status": "pending",
        "publish_public": True,
    }
