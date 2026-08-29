from __future__ import annotations

import threading
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, cast
from uuid import UUID

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field

from recallops.db_retry import run_serializable

if TYPE_CHECKING:
    from recallops.ledger import AuthorityLedgerRepository, ReceiptStatus


class WorkflowState(StrEnum):
    INVESTIGATING = "INVESTIGATING"
    AWAITING_OPERATOR_APPROVAL = "AWAITING_OPERATOR_APPROVAL"
    APPROVED_AWAITING_EXECUTION = "APPROVED_AWAITING_EXECUTION"
    OBSERVING_POSTCHECK = "OBSERVING_POSTCHECK"
    POSTCHECK_READY = "POSTCHECK_READY"
    POSTCHECK_UNAVAILABLE = "POSTCHECK_UNAVAILABLE"
    PENDING_REVIEW = "PENDING_REVIEW"
    REVIEWED = "REVIEWED"


class RequestChannel(StrEnum):
    WEBMCP = "webmcp"
    UI = "ui"
    SYSTEM = "system"


CAPABILITIES: dict[WorkflowState, tuple[str, ...]] = {
    WorkflowState.INVESTIGATING: ("inspect_incident", "propose_mitigation"),
    WorkflowState.AWAITING_OPERATOR_APPROVAL: ("inspect_incident",),
    WorkflowState.APPROVED_AWAITING_EXECUTION: ("inspect_incident",),
    WorkflowState.OBSERVING_POSTCHECK: ("inspect_incident",),
    WorkflowState.POSTCHECK_READY: ("inspect_incident", "record_postcheck_assessment"),
    WorkflowState.POSTCHECK_UNAVAILABLE: ("inspect_incident",),
    WorkflowState.PENDING_REVIEW: ("inspect_incident",),
    WorkflowState.REVIEWED: ("inspect_incident", "recall_reviewed_memory"),
}


class WorkflowSnapshot(BaseModel):
    workflow_id: UUID
    tenant_id: str = Field(min_length=1, max_length=80)
    state: WorkflowState
    epoch: int = Field(ge=1)
    active: bool = True
    proposal_hash: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    operator_subject: str | None = Field(default=None, max_length=200)
    reviewer_subject: str | None = Field(default=None, max_length=200)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def available_tools(self) -> tuple[str, ...]:
        return CAPABILITIES[self.state] if self.active else ()


class CapabilityManifest(BaseModel):
    workflow_id: UUID
    state: WorkflowState
    epoch: int
    active: bool
    authority_owner: str
    available_tools: tuple[str, ...]
    protected_tools: tuple[str, ...] = (
        "approve_proposal",
        "apply_sandbox_mitigation",
        "retry_observation",
        "activate_memory",
        "reject_memory",
        "reset_demo",
    )


class WorkflowConflict(ValueError):
    pass


class _BoundWorkflowPool:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def connection(self) -> Any:
        return nullcontext(self._connection)


def authority_owner(state: WorkflowState) -> str:
    if state is WorkflowState.INVESTIGATING:
        return "AGENT"
    if state in {
        WorkflowState.AWAITING_OPERATOR_APPROVAL,
        WorkflowState.APPROVED_AWAITING_EXECUTION,
        WorkflowState.POSTCHECK_UNAVAILABLE,
    }:
        return "HUMAN_OPERATOR"
    if state is WorkflowState.OBSERVING_POSTCHECK:
        return "SYSTEM"
    if state is WorkflowState.POSTCHECK_READY:
        return "AGENT"
    if state is WorkflowState.PENDING_REVIEW:
        return "HUMAN_REVIEWER"
    return "GOVERNED_MEMORY"


def manifest(snapshot: WorkflowSnapshot) -> CapabilityManifest:
    return CapabilityManifest(
        workflow_id=snapshot.workflow_id,
        state=snapshot.state,
        epoch=snapshot.epoch,
        active=snapshot.active,
        authority_owner=authority_owner(snapshot.state) if snapshot.active else "NONE",
        available_tools=snapshot.available_tools,
    )


class WorkflowRepository(Protocol):
    def ensure(self, snapshot: WorkflowSnapshot) -> WorkflowSnapshot: ...
    def get(self, workflow_id: UUID, tenant_id: str) -> WorkflowSnapshot | None: ...
    def transition(
        self,
        workflow_id: UUID,
        tenant_id: str,
        expected_epoch: int,
        expected_state: WorkflowState,
        target_state: WorkflowState,
        *,
        operator_subject: str | None = None,
        reviewer_subject: str | None = None,
    ) -> WorkflowSnapshot: ...
    def invalidate(
        self, workflow_id: UUID, tenant_id: str, expected_epoch: int
    ) -> WorkflowSnapshot: ...


class InMemoryWorkflowRepository:
    def __init__(self) -> None:
        self._workflows: dict[tuple[str, UUID], WorkflowSnapshot] = {}
        self._lock = threading.RLock()

    def ensure(self, snapshot: WorkflowSnapshot) -> WorkflowSnapshot:
        with self._lock:
            return self._workflows.setdefault((snapshot.tenant_id, snapshot.workflow_id), snapshot)

    def get(self, workflow_id: UUID, tenant_id: str) -> WorkflowSnapshot | None:
        with self._lock:
            return self._workflows.get((tenant_id, workflow_id))

    def transition(
        self,
        workflow_id: UUID,
        tenant_id: str,
        expected_epoch: int,
        expected_state: WorkflowState,
        target_state: WorkflowState,
        *,
        operator_subject: str | None = None,
        reviewer_subject: str | None = None,
    ) -> WorkflowSnapshot:
        with self._lock:
            current = self._workflows.get((tenant_id, workflow_id))
            if current is None:
                raise WorkflowConflict("workflow not found")
            if not current.active:
                raise WorkflowConflict("workflow is inactive")
            if current.epoch != expected_epoch or current.state is not expected_state:
                raise WorkflowConflict("stale workflow state or epoch")
            updated = current.model_copy(
                update={
                    "state": target_state,
                    "epoch": current.epoch + 1,
                    "operator_subject": operator_subject or current.operator_subject,
                    "reviewer_subject": reviewer_subject or current.reviewer_subject,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._workflows[(tenant_id, workflow_id)] = updated
            return updated

    def invalidate(
        self, workflow_id: UUID, tenant_id: str, expected_epoch: int
    ) -> WorkflowSnapshot:
        with self._lock:
            current = self._workflows.get((tenant_id, workflow_id))
            if current is None:
                raise WorkflowConflict("workflow not found")
            if not current.active or current.epoch != expected_epoch:
                raise WorkflowConflict("stale workflow state or epoch")
            updated = current.model_copy(
                update={
                    "active": False,
                    "epoch": current.epoch + 1,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._workflows[(tenant_id, workflow_id)] = updated
            return updated


class PostgresWorkflowRepository:
    def __init__(
        self,
        database_url: str,
        connect_timeout_seconds: int = 5,
        statement_timeout_seconds: int = 15,
    ) -> None:
        self._pool: Any = ConnectionPool(
            database_url,
            open=True,
            min_size=1,
            max_size=10,
            timeout=connect_timeout_seconds,
            kwargs={
                "row_factory": dict_row,
                "connect_timeout": connect_timeout_seconds,
                "options": f"-c statement_timeout={statement_timeout_seconds * 1000}",
            },
        )
        self._transaction_bound = False

    @classmethod
    def from_connection(cls, connection: Any) -> PostgresWorkflowRepository:
        repository = object.__new__(cls)
        repository._pool = _BoundWorkflowPool(connection)
        repository._transaction_bound = True
        return repository

    def _run_write[T](self, operation: Callable[[], T]) -> T:
        if getattr(self, "_transaction_bound", False):
            return operation()
        return run_serializable(operation)

    def close(self) -> None:
        self._pool.close()

    @staticmethod
    def _snapshot(row: object) -> WorkflowSnapshot:
        return WorkflowSnapshot.model_validate(dict(cast(Mapping[str, Any], row)))

    def ensure(self, snapshot: WorkflowSnapshot) -> WorkflowSnapshot:
        def ensure_once() -> WorkflowSnapshot:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO webmcp_workflows
                (workflow_id, tenant_id, state, epoch, active, proposal_hash,
                 operator_subject, reviewer_subject, created_at, updated_at)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (workflow_id, tenant_id)
                DO UPDATE SET workflow_id=excluded.workflow_id
                RETURNING workflow_id, tenant_id, state, epoch, active, proposal_hash,
                 operator_subject, reviewer_subject, created_at, updated_at""",
                    (
                        snapshot.workflow_id,
                        snapshot.tenant_id,
                        snapshot.state,
                        snapshot.epoch,
                        snapshot.active,
                        snapshot.proposal_hash,
                        snapshot.operator_subject,
                        snapshot.reviewer_subject,
                        snapshot.created_at,
                        snapshot.updated_at,
                    ),
                )
                row = cursor.fetchone()
            if row is None:
                raise RuntimeError("workflow upsert returned no row")
            return self._snapshot(row)

        return self._run_write(ensure_once)

    def get(self, workflow_id: UUID, tenant_id: str) -> WorkflowSnapshot | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT workflow_id, tenant_id, state, epoch, active, proposal_hash,
                 operator_subject, reviewer_subject, created_at, updated_at
                 FROM webmcp_workflows WHERE workflow_id=%s AND tenant_id=%s""",
                (workflow_id, tenant_id),
            )
            row = cursor.fetchone()
        return self._snapshot(row) if row is not None else None

    def transition(
        self,
        workflow_id: UUID,
        tenant_id: str,
        expected_epoch: int,
        expected_state: WorkflowState,
        target_state: WorkflowState,
        *,
        operator_subject: str | None = None,
        reviewer_subject: str | None = None,
    ) -> WorkflowSnapshot:
        def transition_once() -> WorkflowSnapshot:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE webmcp_workflows SET state=%s, epoch=epoch+1,
                 operator_subject=COALESCE(%s, operator_subject),
                 reviewer_subject=COALESCE(%s, reviewer_subject), updated_at=now()
                 WHERE workflow_id=%s AND tenant_id=%s AND active=true
                   AND epoch=%s AND state=%s
                 RETURNING workflow_id, tenant_id, state, epoch, active, proposal_hash,
                  operator_subject, reviewer_subject, created_at, updated_at""",
                    (
                        target_state,
                        operator_subject,
                        reviewer_subject,
                        workflow_id,
                        tenant_id,
                        expected_epoch,
                        expected_state,
                    ),
                )
                row = cursor.fetchone()
            if row is None:
                raise WorkflowConflict("stale workflow state or epoch")
            return self._snapshot(row)

        return self._run_write(transition_once)

    def invalidate(
        self, workflow_id: UUID, tenant_id: str, expected_epoch: int
    ) -> WorkflowSnapshot:
        def invalidate_once() -> WorkflowSnapshot:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE webmcp_workflows SET active=false, epoch=epoch+1, updated_at=now()
                 WHERE workflow_id=%s AND tenant_id=%s AND active=true AND epoch=%s
                 RETURNING workflow_id, tenant_id, state, epoch, active, proposal_hash,
                  operator_subject, reviewer_subject, created_at, updated_at""",
                    (workflow_id, tenant_id, expected_epoch),
                )
                row = cursor.fetchone()
            if row is None:
                raise WorkflowConflict("stale workflow state or epoch")
            return self._snapshot(row)

        return self._run_write(invalidate_once)


class WorkflowCoordinator:
    def __init__(
        self,
        repository: WorkflowRepository,
        ledger: AuthorityLedgerRepository | None = None,
        fault_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._repository = repository
        self._ledger = ledger
        self._fault_hook = fault_hook

    def _fault(self, stage: str) -> None:
        if self._fault_hook is not None:
            self._fault_hook(stage)

    def ensure_for_analysis(
        self,
        tenant_id: str,
        workflow_id: UUID,
        action_hash: str | None,
        mutating: bool,
    ) -> WorkflowSnapshot:
        state = (
            WorkflowState.AWAITING_OPERATOR_APPROVAL if mutating else WorkflowState.INVESTIGATING
        )
        return self._repository.ensure(
            WorkflowSnapshot(
                workflow_id=workflow_id,
                tenant_id=tenant_id,
                state=state,
                epoch=1,
                proposal_hash=action_hash,
            )
        )

    def get(self, workflow_id: UUID, tenant_id: str) -> WorkflowSnapshot | None:
        return self._repository.get(workflow_id, tenant_id)

    def capability_manifest(self, workflow_id: UUID, tenant_id: str) -> CapabilityManifest | None:
        snapshot = self.get(workflow_id, tenant_id)
        return manifest(snapshot) if snapshot is not None else None

    def transition(
        self,
        workflow_id: UUID,
        tenant_id: str,
        expected_epoch: int,
        expected_state: WorkflowState,
        target_state: WorkflowState,
        *,
        channel: RequestChannel,
        actor_subject: str,
        role: str,
        reason_code: str = "STATE_TRANSITION_ACCEPTED",
        object_type: str | None = None,
        object_id: str | None = None,
        object_digest: str | None = None,
        allow_legacy_ui: bool = False,
    ) -> WorkflowSnapshot:
        self.validate_transition(
            workflow_id,
            tenant_id,
            expected_epoch,
            expected_state,
            channel=channel,
            actor_subject=actor_subject,
            role=role,
            allow_legacy_ui=allow_legacy_ui,
        )
        before = self.get(workflow_id, tenant_id)
        if before is None:  # pragma: no cover - validate_transition already enforces this
            raise WorkflowConflict("workflow not found")
        self._fault("before_workflow")
        after = self._repository.transition(
            workflow_id,
            tenant_id,
            expected_epoch,
            expected_state,
            target_state,
            operator_subject=actor_subject if role == "operator" else None,
            reviewer_subject=actor_subject if role == "reviewer" else None,
        )
        self._fault("after_workflow")
        if self._ledger is not None:
            self._ledger.append_transition(
                before,
                after,
                actor_subject=actor_subject,
                actor_role=role,
                channel=channel,
                reason_code=reason_code,
                object_type=object_type,
                object_id=object_id,
                object_digest=object_digest,
            )
        return after

    def request_receipt(
        self,
        run_id: UUID,
        tenant_id: str,
        *,
        receipt_policy_version: str,
        image_digest: str,
        evaluation_version: str,
        synthetic: bool,
        publish_public: bool,
    ) -> UUID:
        if self._ledger is None:
            raise WorkflowConflict("authority ledger is unavailable")
        events = self._ledger.list_events(run_id, tenant_id)
        if not events:
            raise WorkflowConflict("receipt target event is unavailable")
        return self._ledger.request_receipt(
            events[-1],
            receipt_policy_version=receipt_policy_version,
            image_digest=image_digest,
            evaluation_version=evaluation_version,
            synthetic=synthetic,
            publish_public=publish_public,
        )

    def receipt_status(self, run_id: UUID, tenant_id: str) -> ReceiptStatus | None:
        return self._ledger.receipt_status(run_id, tenant_id) if self._ledger is not None else None

    def validate_transition(
        self,
        workflow_id: UUID,
        tenant_id: str,
        expected_epoch: int,
        expected_state: WorkflowState,
        *,
        channel: RequestChannel,
        actor_subject: str,
        role: str,
        allow_legacy_ui: bool = False,
    ) -> WorkflowSnapshot:
        if expected_state is WorkflowState.INVESTIGATING:
            if allow_legacy_ui and channel is RequestChannel.UI and role == "operator":
                required_role = "operator"
            elif channel is RequestChannel.WEBMCP and role == "agent":
                required_role = "agent"
            else:
                raise WorkflowConflict("proposal transition requires WebMCP agent authority")
        elif expected_state is WorkflowState.OBSERVING_POSTCHECK:
            if channel is not RequestChannel.SYSTEM or role != "system":
                raise WorkflowConflict("postcheck state transition requires system authority")
            required_role = "system"
        elif expected_state is WorkflowState.POSTCHECK_READY:
            if channel is not RequestChannel.WEBMCP or role != "agent":
                raise WorkflowConflict("postcheck assessment requires WebMCP agent authority")
            required_role = "agent"
        else:
            if channel is not RequestChannel.UI:
                raise WorkflowConflict("protected transition is not authorized through WebMCP")
            required_role = (
                "reviewer" if expected_state is WorkflowState.PENDING_REVIEW else "operator"
            )
        if role != required_role:
            raise WorkflowConflict(f"{required_role} role required for workflow transition")
        current = self.get(workflow_id, tenant_id)
        if current is None:
            raise WorkflowConflict("workflow not found")
        if (
            not current.active
            or current.epoch != expected_epoch
            or current.state is not expected_state
        ):
            raise WorkflowConflict("stale workflow state or epoch")
        if required_role == "reviewer" and current.operator_subject == actor_subject:
            raise WorkflowConflict("independent reviewer subject required")
        return current

    def invalidate(
        self,
        workflow_id: UUID,
        tenant_id: str,
        expected_epoch: int,
        *,
        channel: RequestChannel,
        role: str,
        actor_subject: str = "operator",
    ) -> WorkflowSnapshot:
        if channel is not RequestChannel.UI or role != "operator":
            raise WorkflowConflict("reset requires the operator UI channel")
        before = self.get(workflow_id, tenant_id)
        if before is None:
            raise WorkflowConflict("workflow not found")
        self._fault("before_workflow")
        after = self._repository.invalidate(workflow_id, tenant_id, expected_epoch)
        self._fault("after_workflow")
        if self._ledger is not None:
            self._ledger.append_transition(
                before,
                after,
                actor_subject=actor_subject,
                actor_role=role,
                channel=channel,
                reason_code="WORKFLOW_RESET_ACCEPTED",
            )
        return after
