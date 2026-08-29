"""Append-only authority evidence and non-authoritative activity projections."""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, cast
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from pydantic import BaseModel, Field

from recallops.canonical import canonical_bytes
from recallops.workflow import RequestChannel, WorkflowSnapshot

LEDGER_VERSION = "authority-ledger-v1"
EVENT_HASH_DOMAIN = b"recallops-authority-event-v1"
ZERO_EVENT_HASH = "0" * 64


class AuthorityLedgerConflict(ValueError):
    """The append did not extend the exact current ledger head."""


class AuthorityEvent(BaseModel):
    event_id: UUID
    run_id: UUID
    tenant_id: str
    sequence: int = Field(gt=0)
    recorded_at: datetime
    event_type: str
    outcome: Literal["accepted", "denied", "observed"] = "accepted"
    actor_subject: str
    actor_role: Literal["agent", "operator", "reviewer", "system"]
    channel: RequestChannel
    workflow_id: UUID
    epoch_before: int = Field(ge=0)
    epoch_after: int = Field(gt=0)
    state_before: str
    state_after: str
    capabilities_before: tuple[str, ...]
    capabilities_after: tuple[str, ...]
    object_type: str | None = None
    object_id: str | None = None
    object_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    reason_code: str
    display_summary: str = Field(min_length=1, max_length=240)
    policy_version: str
    build_sha: str
    previous_event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    event_hash: str = Field(pattern=r"^[a-f0-9]{64}$")


class ActivityObservation(BaseModel):
    activity_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    tenant_id: str
    workflow_id: UUID
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: Literal["webmcp", "browser", "server"]
    actor_subject: str
    activity_type: str
    tool_name: str | None = None
    outcome: str
    display_summary: str = Field(min_length=1, max_length=240)
    authority_event_id: UUID | None = None
    object_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    build_sha: str
    client_instance_id_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class TimelineEntry(BaseModel):
    entry_id: UUID
    recorded_at: datetime
    evidence_class: Literal["authority_commit", "supporting_observation"]
    event_type: str
    outcome: str
    actor_subject: str
    display_summary: str
    sequence: int | None = None
    event_hash: str | None = None


class ReceiptStatus(BaseModel):
    receipt_id: UUID
    status: str
    target_sequence: int
    ledger_head_hash: str
    bundle_digest: str | None = None
    key_thumbprint: str | None = None
    signing_algorithm: str | None = None
    public: bool = False
    failure_code: str | None = None


def canonical_event_payload(event: AuthorityEvent) -> dict[str, object]:
    payload = event.model_dump(mode="json", exclude={"event_hash"})
    # Integers which could eventually exceed the I-JSON exact range are encoded
    # as decimal strings. UUIDs, timestamps, and digests are already strings.
    payload["sequence"] = str(event.sequence)
    payload["epoch_before"] = str(event.epoch_before)
    payload["epoch_after"] = str(event.epoch_after)
    return cast(dict[str, object], payload)


def authority_event_hash(previous_event_hash: str, payload: Mapping[str, object]) -> str:
    if len(previous_event_hash) != 64:
        raise ValueError("previous event hash must be 32 bytes of lowercase hex")
    try:
        predecessor = bytes.fromhex(previous_event_hash)
    except ValueError as error:
        raise ValueError("previous event hash must be 32 bytes of lowercase hex") from error
    if previous_event_hash != previous_event_hash.lower() or len(predecessor) != 32:
        raise ValueError("previous event hash must be 32 bytes of lowercase hex")
    return hashlib.sha256(
        EVENT_HASH_DOMAIN + b"\x00" + predecessor + b"\x00" + canonical_bytes(dict(payload))
    ).hexdigest()


def verify_event(event: AuthorityEvent, expected_previous_hash: str) -> bool:
    return (
        event.previous_event_hash == expected_previous_hash
        and event.event_hash
        == authority_event_hash(expected_previous_hash, canonical_event_payload(event))
    )


FaultHook = Callable[[str], None]


class AuthorityLedgerRepository(Protocol):
    def append_genesis(self, snapshot: WorkflowSnapshot) -> AuthorityEvent | None: ...

    def append_transition(
        self,
        before: WorkflowSnapshot,
        after: WorkflowSnapshot,
        *,
        actor_subject: str,
        actor_role: str,
        channel: RequestChannel,
        reason_code: str = "STATE_TRANSITION_ACCEPTED",
        object_type: str | None = None,
        object_id: str | None = None,
        object_digest: str | None = None,
        event_type: str | None = None,
        state_before: str | None = None,
        display_summary: str | None = None,
    ) -> AuthorityEvent | None: ...

    def list_events(self, run_id: UUID, tenant_id: str) -> list[AuthorityEvent]: ...
    def add_activity(self, observation: ActivityObservation) -> None: ...
    def timeline(self, run_id: UUID, tenant_id: str) -> list[TimelineEntry]: ...

    def request_receipt(
        self,
        event: AuthorityEvent,
        *,
        receipt_policy_version: str,
        image_digest: str,
        evaluation_version: str,
        synthetic: bool,
        publish_public: bool,
    ) -> UUID: ...

    def receipt_status(self, run_id: UUID, tenant_id: str) -> ReceiptStatus | None: ...


def _event(
    *,
    run_id: UUID,
    build_sha: str,
    policy_version: str,
    sequence: int,
    previous_hash: str,
    before: WorkflowSnapshot,
    after: WorkflowSnapshot,
    actor_subject: str,
    actor_role: str,
    channel: RequestChannel,
    reason_code: str,
    object_type: str | None,
    object_id: str | None,
    object_digest: str | None,
    event_type: str | None = None,
    state_before: str | None = None,
    display_summary: str | None = None,
) -> AuthorityEvent:
    event = AuthorityEvent(
        event_id=uuid4(),
        run_id=run_id,
        tenant_id=before.tenant_id,
        sequence=sequence,
        recorded_at=datetime.now(UTC),
        event_type=event_type or f"{before.state.value}_TO_{after.state.value}",
        actor_subject=actor_subject,
        actor_role=cast(Any, actor_role),
        channel=channel,
        workflow_id=before.workflow_id,
        epoch_before=before.epoch,
        epoch_after=after.epoch,
        state_before=state_before or before.state.value,
        state_after=after.state.value,
        capabilities_before=before.available_tools,
        capabilities_after=after.available_tools,
        object_type=object_type,
        object_id=object_id,
        object_digest=object_digest,
        reason_code=reason_code,
        display_summary=display_summary
        or f"Authority committed: {before.state.value} → {after.state.value}",
        policy_version=policy_version,
        build_sha=build_sha,
        previous_event_hash=previous_hash,
        event_hash=ZERO_EVENT_HASH,
    )
    return event.model_copy(
        update={
            "event_hash": authority_event_hash(previous_hash, canonical_event_payload(event))
        }
    )


class InMemoryAuthorityLedgerRepository:
    def __init__(self, fault_hook: FaultHook | None = None) -> None:
        self._runs: dict[tuple[str, UUID], tuple[UUID, str, str]] = {}
        self._events: dict[tuple[str, UUID], list[AuthorityEvent]] = {}
        self._activities: dict[tuple[str, UUID], list[ActivityObservation]] = {}
        self.receipt_requests: dict[UUID, dict[str, object]] = {}
        self._lock = threading.RLock()
        self._fault_hook = fault_hook

    def bind_run(
        self, tenant_id: str, workflow_id: UUID, run_id: UUID, build_sha: str, policy_version: str
    ) -> None:
        with self._lock:
            self._runs[(tenant_id, workflow_id)] = (run_id, build_sha, policy_version)

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def append_transition(
        self,
        before: WorkflowSnapshot,
        after: WorkflowSnapshot,
        *,
        actor_subject: str,
        actor_role: str,
        channel: RequestChannel,
        reason_code: str = "STATE_TRANSITION_ACCEPTED",
        object_type: str | None = None,
        object_id: str | None = None,
        object_digest: str | None = None,
        event_type: str | None = None,
        state_before: str | None = None,
        display_summary: str | None = None,
    ) -> AuthorityEvent | None:
        with self._lock:
            run = self._runs.get((before.tenant_id, before.workflow_id))
            if run is None:
                return None
            run_id, build_sha, policy_version = run
            key = (before.tenant_id, run_id)
            events = self._events.setdefault(key, [])
            previous = events[-1].event_hash if events else ZERO_EVENT_HASH
            event = _event(
                run_id=run_id,
                build_sha=build_sha,
                policy_version=policy_version,
                sequence=len(events) + 1,
                previous_hash=previous,
                before=before,
                after=after,
                actor_subject=actor_subject,
                actor_role=actor_role,
                channel=channel,
                reason_code=reason_code,
                object_type=object_type,
                object_id=object_id,
                object_digest=object_digest,
                event_type=event_type,
                state_before=state_before,
                display_summary=display_summary,
            )
            self._fault("before_event")
            events.append(event)
            try:
                self._fault("after_event")
                self._fault("before_head")
                self._fault("after_head")
            except Exception:
                events.pop()
                raise
            return event

    def append_genesis(self, snapshot: WorkflowSnapshot) -> AuthorityEvent | None:
        before = WorkflowSnapshot.model_construct(
            workflow_id=snapshot.workflow_id,
            tenant_id=snapshot.tenant_id,
            state=snapshot.state,
            epoch=0,
            active=False,
            created_at=snapshot.created_at,
            updated_at=snapshot.created_at,
        )
        return self.append_transition(
            before,
            snapshot,
            actor_subject="recallops-run-allocator",
            actor_role="system",
            channel=RequestChannel.SYSTEM,
            reason_code="RUN_GENESIS_ACCEPTED",
            event_type="RUN_GENESIS",
            state_before="ABSENT",
            display_summary="Authority committed: isolated judge run created",
        )

    def list_events(self, run_id: UUID, tenant_id: str) -> list[AuthorityEvent]:
        with self._lock:
            return list(self._events.get((tenant_id, run_id), ()))

    def add_activity(self, observation: ActivityObservation) -> None:
        with self._lock:
            self._activities.setdefault(
                (observation.tenant_id, observation.run_id), []
            ).append(observation)

    def timeline(self, run_id: UUID, tenant_id: str) -> list[TimelineEntry]:
        events = [
            TimelineEntry(
                entry_id=item.event_id,
                recorded_at=item.recorded_at,
                evidence_class="authority_commit",
                event_type=item.event_type,
                outcome=item.outcome,
                actor_subject=item.actor_subject,
                display_summary=item.display_summary,
                sequence=item.sequence,
                event_hash=item.event_hash,
            )
            for item in self.list_events(run_id, tenant_id)
        ]
        with self._lock:
            observations = list(self._activities.get((tenant_id, run_id), ()))
        entries = events + [
            TimelineEntry(
                entry_id=item.activity_id,
                recorded_at=item.recorded_at,
                evidence_class="supporting_observation",
                event_type=item.activity_type,
                outcome=item.outcome,
                actor_subject=item.actor_subject,
                display_summary=item.display_summary,
            )
            for item in observations
        ]
        return sorted(entries, key=lambda item: (item.recorded_at, str(item.entry_id)))

    def request_receipt(
        self,
        event: AuthorityEvent,
        *,
        receipt_policy_version: str,
        image_digest: str,
        evaluation_version: str,
        synthetic: bool,
        publish_public: bool,
    ) -> UUID:
        with self._lock:
            events = self._events.get((event.tenant_id, event.run_id), [])
            if not events or events[-1] != event or event.state_after != "REVIEWED":
                raise AuthorityLedgerConflict("receipt target is not the finalized ledger head")
            receipt_id = uuid5(
                NAMESPACE_URL,
                f"urn:recallops:receipt:{event.run_id}:{event.event_hash}:{receipt_policy_version}",
            )
            self.receipt_requests.setdefault(
                receipt_id,
                {
                    "receipt_id": receipt_id,
                    "run_id": event.run_id,
                    "tenant_id": event.tenant_id,
                    "target_sequence": event.sequence,
                    "target_ledger_hash": event.event_hash,
                    "receipt_policy_version": receipt_policy_version,
                    "source_sha": event.build_sha,
                    "image_digest": image_digest,
                    "evaluation_version": evaluation_version,
                    "synthetic": synthetic,
                    "publish_public": publish_public,
                    "status": "pending",
                },
            )
            return receipt_id

    def receipt_status(self, run_id: UUID, tenant_id: str) -> ReceiptStatus | None:
        with self._lock:
            requests = [
                item
                for item in self.receipt_requests.values()
                if item["run_id"] == run_id and item["tenant_id"] == tenant_id
            ]
            if not requests:
                return None
            item = requests[-1]
            return ReceiptStatus(
                receipt_id=cast(UUID, item["receipt_id"]),
                status=str(item["status"]),
                target_sequence=cast(int, item["target_sequence"]),
                ledger_head_hash=str(item["target_ledger_hash"]),
            )


class _BoundLedgerPool:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def connection(self) -> Any:
        return nullcontext(self._connection)


class PostgresAuthorityLedgerRepository:
    def __init__(self, pool: Any, fault_hook: FaultHook | None = None) -> None:
        self._pool = pool
        self._fault_hook = fault_hook
        self._transaction_bound = False

    @classmethod
    def from_connection(
        cls, connection: Any, fault_hook: FaultHook | None = None
    ) -> PostgresAuthorityLedgerRepository:
        repository = cls(_BoundLedgerPool(connection), fault_hook)
        repository._transaction_bound = True
        return repository

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def append_transition(
        self,
        before: WorkflowSnapshot,
        after: WorkflowSnapshot,
        *,
        actor_subject: str,
        actor_role: str,
        channel: RequestChannel,
        reason_code: str = "STATE_TRANSITION_ACCEPTED",
        object_type: str | None = None,
        object_id: str | None = None,
        object_digest: str | None = None,
        event_type: str | None = None,
        state_before: str | None = None,
        display_summary: str | None = None,
    ) -> AuthorityEvent | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT run_id, build_sha, capability_policy_version FROM judge_runs
                WHERE tenant_id=%s AND source_incident_id=%s""",
                (before.tenant_id, before.workflow_id),
            )
            run_row = cursor.fetchone()
            if run_row is None:
                return None
            if not self._transaction_bound:
                raise RuntimeError(
                    "authority appends require an enclosing serializable domain transaction"
                )
            run = dict(cast(Mapping[str, Any], run_row))
            cursor.execute(
                """INSERT INTO authority_ledger_heads
                (run_id, tenant_id, ledger_version) VALUES (%s,%s,%s)
                ON CONFLICT (run_id, tenant_id) DO NOTHING""",
                (run["run_id"], before.tenant_id, LEDGER_VERSION),
            )
            cursor.execute(
                """SELECT last_sequence, last_event_hash, closed
                FROM authority_ledger_heads WHERE run_id=%s AND tenant_id=%s FOR UPDATE""",
                (run["run_id"], before.tenant_id),
            )
            head_row = cursor.fetchone()
            if head_row is None:
                raise AuthorityLedgerConflict("ledger head unavailable")
            head = dict(cast(Mapping[str, Any], head_row))
            if bool(head["closed"]):
                raise AuthorityLedgerConflict("ledger is closed")
            sequence = int(head["last_sequence"]) + 1
            previous = str(head["last_event_hash"])
            event = _event(
                run_id=cast(UUID, run["run_id"]),
                build_sha=str(run["build_sha"]),
                policy_version=str(run["capability_policy_version"]),
                sequence=sequence,
                previous_hash=previous,
                before=before,
                after=after,
                actor_subject=actor_subject,
                actor_role=actor_role,
                channel=channel,
                reason_code=reason_code,
                object_type=object_type,
                object_id=object_id,
                object_digest=object_digest,
                event_type=event_type,
                state_before=state_before,
                display_summary=display_summary,
            )
            self._fault("before_event")
            cursor.execute(
                """INSERT INTO authority_events
                (event_id,run_id,tenant_id,sequence,recorded_at,event_type,outcome,
                 actor_subject,actor_role,channel,workflow_id,epoch_before,epoch_after,
                 state_before,state_after,capabilities_before,capabilities_after,
                 object_type,object_id,object_digest,reason_code,display_summary,
                 policy_version,build_sha,previous_event_hash,event_hash)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::JSONB,%s::JSONB,
                        %s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    event.event_id, event.run_id, event.tenant_id, event.sequence,
                    event.recorded_at, event.event_type, event.outcome, event.actor_subject,
                    event.actor_role, event.channel, event.workflow_id, event.epoch_before,
                    event.epoch_after, event.state_before, event.state_after,
                    json.dumps(event.capabilities_before), json.dumps(event.capabilities_after),
                    event.object_type, event.object_id, event.object_digest, event.reason_code,
                    event.display_summary, event.policy_version, event.build_sha,
                    event.previous_event_hash, event.event_hash,
                ),
            )
            self._fault("after_event")
            self._fault("before_head")
            cursor.execute(
                """UPDATE authority_ledger_heads SET last_sequence=%s, last_event_hash=%s,
                updated_at=%s WHERE run_id=%s AND tenant_id=%s AND last_sequence=%s
                AND last_event_hash=%s AND closed=false RETURNING run_id""",
                (
                    event.sequence, event.event_hash, event.recorded_at, event.run_id,
                    event.tenant_id, sequence - 1, previous,
                ),
            )
            if cursor.fetchone() is None:
                raise AuthorityLedgerConflict("ledger predecessor changed")
            self._fault("after_head")
            return event

    def append_genesis(self, snapshot: WorkflowSnapshot) -> AuthorityEvent | None:
        before = WorkflowSnapshot.model_construct(
            workflow_id=snapshot.workflow_id,
            tenant_id=snapshot.tenant_id,
            state=snapshot.state,
            epoch=0,
            active=False,
            created_at=snapshot.created_at,
            updated_at=snapshot.created_at,
        )
        return self.append_transition(
            before,
            snapshot,
            actor_subject="recallops-run-allocator",
            actor_role="system",
            channel=RequestChannel.SYSTEM,
            reason_code="RUN_GENESIS_ACCEPTED",
            event_type="RUN_GENESIS",
            state_before="ABSENT",
            display_summary="Authority committed: isolated judge run created",
        )

    @staticmethod
    def _authority_event(row: object) -> AuthorityEvent:
        return AuthorityEvent.model_validate(dict(cast(Mapping[str, Any], row)))

    def list_events(self, run_id: UUID, tenant_id: str) -> list[AuthorityEvent]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT * FROM authority_events WHERE run_id=%s AND tenant_id=%s
                ORDER BY sequence""",
                (run_id, tenant_id),
            )
            return [self._authority_event(row) for row in cursor.fetchall()]

    def request_receipt(
        self,
        event: AuthorityEvent,
        *,
        receipt_policy_version: str,
        image_digest: str,
        evaluation_version: str,
        synthetic: bool,
        publish_public: bool,
    ) -> UUID:
        if not self._transaction_bound:
            raise RuntimeError("receipt requests require an enclosing authority transaction")
        if event.state_after != "REVIEWED":
            raise AuthorityLedgerConflict("receipt target is not a reviewed workflow")
        receipt_id = uuid5(
            NAMESPACE_URL,
            f"urn:recallops:receipt:{event.run_id}:{event.event_hash}:{receipt_policy_version}",
        )
        request_id = uuid5(NAMESPACE_URL, f"urn:recallops:receipt-request:{receipt_id}")
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT last_sequence,last_event_hash FROM authority_ledger_heads
                WHERE run_id=%s AND tenant_id=%s FOR UPDATE""",
                (event.run_id, event.tenant_id),
            )
            head_row = cursor.fetchone()
            if head_row is None:
                raise AuthorityLedgerConflict("receipt target differs from locked ledger head")
            head = dict(cast(Mapping[str, Any], head_row))
            if (
                int(head["last_sequence"]) != event.sequence
                or str(head["last_event_hash"]) != event.event_hash
            ):
                raise AuthorityLedgerConflict("receipt target differs from locked ledger head")
            cursor.execute(
                # Authority events are append-only and the mutable head above is
                # already locked. A second locking read would require forbidden
                # UPDATE authority without strengthening this serializable check.
                """SELECT * FROM authority_events
                WHERE event_id=%s AND run_id=%s AND tenant_id=%s AND sequence=%s""",
                (event.event_id, event.run_id, event.tenant_id, event.sequence),
            )
            stored_row = cursor.fetchone()
            if stored_row is None or self._authority_event(stored_row) != event:
                raise AuthorityLedgerConflict(
                    "receipt target differs from committed authority event"
                )
            cursor.execute(
                """INSERT INTO authority_receipts
                (receipt_id,run_id,tenant_id,ledger_head_hash,ledger_last_sequence,
                 receipt_policy_version,source_sha,image_digest,evaluation_version,status,synthetic)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'pending',%s)
                ON CONFLICT (receipt_id) DO NOTHING""",
                (
                    receipt_id,
                    event.run_id,
                    event.tenant_id,
                    event.event_hash,
                    event.sequence,
                    receipt_policy_version,
                    event.build_sha,
                    image_digest,
                    evaluation_version,
                    synthetic,
                ),
            )
            cursor.execute(
                """INSERT INTO receipt_requests
                (request_id,receipt_id,run_id,tenant_id,target_sequence,target_ledger_hash,
                 publish_public) VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (receipt_id) DO NOTHING""",
                (
                    request_id,
                    receipt_id,
                    event.run_id,
                    event.tenant_id,
                    event.sequence,
                    event.event_hash,
                    publish_public,
                ),
            )
        return receipt_id

    def receipt_status(self, run_id: UUID, tenant_id: str) -> ReceiptStatus | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT receipt_id,status,ledger_last_sequence,ledger_head_hash,
                bundle_digest,key_thumbprint,signing_algorithm,public_at,failure_code
                FROM authority_receipts WHERE run_id=%s AND tenant_id=%s
                ORDER BY created_at DESC,receipt_id DESC LIMIT 1""",
                (run_id, tenant_id),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        item = dict(cast(Mapping[str, Any], row))
        return ReceiptStatus(
            receipt_id=item["receipt_id"],
            status=item["status"],
            target_sequence=int(item["ledger_last_sequence"]),
            ledger_head_hash=item["ledger_head_hash"],
            bundle_digest=item["bundle_digest"],
            key_thumbprint=item["key_thumbprint"],
            signing_algorithm=item["signing_algorithm"],
            public=item["public_at"] is not None,
            failure_code=item["failure_code"],
        )

    def add_activity(self, observation: ActivityObservation) -> None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """INSERT INTO activity_observations
                (activity_id,run_id,tenant_id,workflow_id,recorded_at,source,actor_subject,
                 activity_type,tool_name,outcome,display_summary,authority_event_id,
                 object_digest,build_sha,client_instance_id_hash)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    observation.activity_id,
                    observation.run_id,
                    observation.tenant_id,
                    observation.workflow_id,
                    observation.recorded_at,
                    observation.source,
                    observation.actor_subject,
                    observation.activity_type,
                    observation.tool_name,
                    observation.outcome,
                    observation.display_summary,
                    observation.authority_event_id,
                    observation.object_digest,
                    observation.build_sha,
                    observation.client_instance_id_hash,
                ),
            )

    def timeline(self, run_id: UUID, tenant_id: str) -> list[TimelineEntry]:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT entry_id,recorded_at,evidence_class,event_type,outcome,
                actor_subject,display_summary,sequence,event_hash FROM (
                  SELECT event_id AS entry_id,recorded_at,'authority_commit' AS evidence_class,
                    event_type,outcome,actor_subject,display_summary,sequence,event_hash
                  FROM authority_events WHERE run_id=%s AND tenant_id=%s
                  UNION ALL
                  SELECT activity_id AS entry_id,recorded_at,
                    'supporting_observation' AS evidence_class,activity_type AS event_type,
                    outcome,actor_subject,display_summary,NULL AS sequence,NULL AS event_hash
                  FROM activity_observations WHERE run_id=%s AND tenant_id=%s
                ) ORDER BY recorded_at, entry_id""",
                (run_id, tenant_id, run_id, tenant_id),
            )
            return [TimelineEntry.model_validate(dict(row)) for row in cursor.fetchall()]
