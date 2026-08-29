from __future__ import annotations

import threading
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, Protocol, cast
from uuid import UUID

from psycopg_pool import ConnectionPool
from pydantic import BaseModel

from recallops.db_retry import run_serializable


class JudgeSession(BaseModel):
    session_hash: str
    csrf_hash: str
    tenant_id: str
    subject: str
    role: Literal["operator", "reviewer"]
    run_id: UUID
    session_generation: int
    review_handoff_hash: str | None = None
    expires_at: datetime
    revoked_at: datetime | None = None


class JudgeRun(BaseModel):
    run_id: UUID
    tenant_id: str
    generation: int
    scenario_version: str
    source_incident_id: UUID
    status: Literal["active", "completed", "reset", "expired"] = "active"
    operator_subject: str
    build_sha: str
    capability_policy_version: str
    created_at: datetime
    expires_at: datetime
    finalized_at: datetime | None = None
    reset_at: datetime | None = None


class ReviewHandoff(BaseModel):
    code_hash: str
    run_id: UUID
    tenant_id: str
    workflow_id: UUID
    memory_id: UUID
    memory_digest: str
    purpose: Literal["initial_review", "revocation"]
    issued_by_subject: str
    expires_at: datetime
    consumed_at: datetime | None = None
    revoked_at: datetime | None = None


class JudgeRunCapacityError(ValueError):
    pass


class JudgeSessionRepository(Protocol):
    def consume_attempt(self, client_hash: str, limit: int, window_seconds: int) -> bool: ...
    def save(self, session: JudgeSession) -> None: ...
    def get(self, session_hash: str) -> JudgeSession | None: ...
    def revoke(self, session_hash: str) -> None: ...
    def save_run(self, run: JudgeRun, active_limit: int) -> None: ...
    def get_run(self, run_id: UUID) -> JudgeRun | None: ...
    def reset_run(self, run_id: UUID) -> bool: ...
    def run_is_current(self, run_id: UUID, tenant_id: str, generation: int) -> bool: ...
    def save_handoff(self, handoff: ReviewHandoff) -> None: ...
    def get_handoff(self, code_hash: str) -> ReviewHandoff | None: ...
    def consume_handoff(self, code_hash: str) -> ReviewHandoff | None: ...
    def active_run_count(self) -> int: ...


class _BoundJudgePool:
    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def connection(self) -> Any:
        return nullcontext(self._connection)


class InMemoryJudgeSessionRepository:
    def __init__(self) -> None:
        self._sessions: dict[str, JudgeSession] = {}
        self._attempts: dict[str, tuple[datetime, int]] = {}
        self._lock = threading.RLock()
        self._runs: dict[UUID, JudgeRun] = {}
        self._handoffs: dict[str, ReviewHandoff] = {}

    def consume_attempt(self, client_hash: str, limit: int, window_seconds: int) -> bool:
        now = datetime.now(UTC)
        with self._lock:
            started, count = self._attempts.get(client_hash, (now, 0))
            if now - started >= timedelta(seconds=window_seconds):
                started, count = now, 0
            count += 1
            self._attempts[client_hash] = (started, count)
            return count <= limit

    def save(self, session: JudgeSession) -> None:
        with self._lock:
            self._sessions[session.session_hash] = session

    def get(self, session_hash: str) -> JudgeSession | None:
        with self._lock:
            return self._sessions.get(session_hash)

    def revoke(self, session_hash: str) -> None:
        with self._lock:
            session = self._sessions.get(session_hash)
            if session is not None:
                self._sessions[session_hash] = session.model_copy(
                    update={"revoked_at": datetime.now(UTC)}
                )

    def save_run(self, run: JudgeRun, active_limit: int) -> None:
        with self._lock:
            if self.active_run_count() >= active_limit:
                raise JudgeRunCapacityError("judge scenario capacity reached")
            if any(item.tenant_id == run.tenant_id for item in self._runs.values()):
                raise ValueError("judge run tenant already exists")
            self._runs[run.run_id] = run

    def get_run(self, run_id: UUID) -> JudgeRun | None:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                return None
            if run.status == "active" and run.expires_at <= datetime.now(UTC):
                run = run.model_copy(
                    update={"status": "expired", "finalized_at": datetime.now(UTC)}
                )
                self._runs[run_id] = run
            return run

    def reset_run(self, run_id: UUID) -> bool:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None or run.status != "active":
                return False
            now = datetime.now(UTC)
            self._runs[run_id] = run.model_copy(
                update={"status": "reset", "reset_at": now, "finalized_at": now}
            )
            for session_hash, session in tuple(self._sessions.items()):
                if session.run_id == run_id and session.revoked_at is None:
                    self._sessions[session_hash] = session.model_copy(update={"revoked_at": now})
            return True

    def run_is_current(self, run_id: UUID, tenant_id: str, generation: int) -> bool:
        run = self.get_run(run_id)
        return bool(
            run
            and run.tenant_id == tenant_id
            and run.generation == generation
            and run.status == "active"
            and run.expires_at > datetime.now(UTC)
        )

    def save_handoff(self, handoff: ReviewHandoff) -> None:
        with self._lock:
            if handoff.code_hash in self._handoffs:
                raise ValueError("review handoff already exists")
            self._handoffs[handoff.code_hash] = handoff

    def get_handoff(self, code_hash: str) -> ReviewHandoff | None:
        with self._lock:
            return self._handoffs.get(code_hash)

    def consume_handoff(self, code_hash: str) -> ReviewHandoff | None:
        with self._lock:
            handoff = self._handoffs.get(code_hash)
            now = datetime.now(UTC)
            if (
                handoff is None
                or handoff.consumed_at is not None
                or handoff.revoked_at is not None
                or handoff.expires_at <= now
                or (run := self.get_run(handoff.run_id)) is None
                or run.tenant_id != handoff.tenant_id
                or run.status != "active"
            ):
                return None
            consumed = handoff.model_copy(update={"consumed_at": now})
            self._handoffs[code_hash] = consumed
            return consumed

    def active_run_count(self) -> int:
        with self._lock:
            return sum(
                1
                for run_id in tuple(self._runs)
                if (run := self.get_run(run_id)) is not None and run.status == "active"
            )


class PostgresJudgeSessionRepository:
    def __init__(self, pool: ConnectionPool[Any]) -> None:
        self._pool: Any = pool

    @classmethod
    def from_connection(cls, connection: Any) -> PostgresJudgeSessionRepository:
        repository = object.__new__(cls)
        repository._pool = _BoundJudgePool(connection)
        return repository

    def consume_attempt(self, client_hash: str, limit: int, window_seconds: int) -> bool:
        def consume_once() -> bool:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO judge_auth_attempts (client_hash, window_started, attempts)
                    VALUES (%s, now(), 1)
                    ON CONFLICT (client_hash) DO UPDATE SET
                      attempts=CASE
                        WHEN judge_auth_attempts.window_started < now() - (%s * interval '1 second')
                        THEN 1 ELSE judge_auth_attempts.attempts + 1 END,
                      window_started=CASE
                        WHEN judge_auth_attempts.window_started < now() - (%s * interval '1 second')
                        THEN now() ELSE judge_auth_attempts.window_started END
                    RETURNING attempts""",
                    (client_hash, window_seconds, window_seconds),
                )
                row = cursor.fetchone()
            return row is not None and int(dict(cast(Any, row))["attempts"]) <= limit

        return run_serializable(consume_once)

    def save(self, session: JudgeSession) -> None:
        def save_once() -> None:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO judge_sessions
                    (session_hash, csrf_hash, tenant_id, subject, role, expires_at,
                     run_id, session_role, session_generation, review_handoff_hash)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        session.session_hash,
                        session.csrf_hash,
                        session.tenant_id,
                        session.subject,
                        session.role,
                        session.expires_at,
                        session.run_id,
                        session.role,
                        session.session_generation,
                        session.review_handoff_hash,
                    ),
                )

        run_serializable(save_once)

    def get(self, session_hash: str) -> JudgeSession | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT session_hash, csrf_hash, tenant_id, subject, role, expires_at,
                revoked_at, run_id, session_generation, review_handoff_hash
                FROM judge_sessions WHERE session_hash=%s""",
                (session_hash,),
            )
            row = cursor.fetchone()
        return JudgeSession.model_validate(dict(cast(Any, row))) if row is not None else None

    def revoke(self, session_hash: str) -> None:
        def revoke_once() -> None:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE judge_sessions SET revoked_at=COALESCE(revoked_at, now())
                    WHERE session_hash=%s""",
                    (session_hash,),
                )

        run_serializable(revoke_once)

    @staticmethod
    def _run(row: object) -> JudgeRun:
        return JudgeRun.model_validate(dict(cast(Any, row)))

    def save_run(self, run: JudgeRun, active_limit: int) -> None:
        def save_once() -> None:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """SELECT count(*) AS count FROM judge_runs
                    WHERE status='active' AND expires_at > now()"""
                )
                row = cursor.fetchone()
                count = int(dict(cast(Any, row))["count"]) if row is not None else 0
                if count >= active_limit:
                    raise JudgeRunCapacityError("judge scenario capacity reached")
                cursor.execute(
                    """INSERT INTO judge_runs
                    (run_id, tenant_id, generation, scenario_version, source_incident_id,
                     status, operator_subject, build_sha, capability_policy_version,
                     created_at, expires_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        run.run_id,
                        run.tenant_id,
                        run.generation,
                        run.scenario_version,
                        run.source_incident_id,
                        run.status,
                        run.operator_subject,
                        run.build_sha,
                        run.capability_policy_version,
                        run.created_at,
                        run.expires_at,
                    ),
                )

        run_serializable(save_once)

    def get_run(self, run_id: UUID) -> JudgeRun | None:
        def get_once() -> JudgeRun | None:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE judge_runs SET status='expired', finalized_at=now()
                    WHERE run_id=%s AND status='active' AND expires_at <= now()""",
                    (run_id,),
                )
                cursor.execute("SELECT * FROM judge_runs WHERE run_id=%s", (run_id,))
                row = cursor.fetchone()
            return self._run(row) if row is not None else None

        return run_serializable(get_once)

    def reset_run(self, run_id: UUID) -> bool:
        def reset_once() -> bool:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE judge_runs SET status='reset', reset_at=now(), finalized_at=now()
                    WHERE run_id=%s AND status='active' AND expires_at > now()
                    RETURNING run_id""",
                    (run_id,),
                )
                changed = cursor.fetchone() is not None
                if changed:
                    cursor.execute(
                        """UPDATE judge_sessions SET revoked_at=COALESCE(revoked_at, now())
                        WHERE run_id=%s""",
                        (run_id,),
                    )
                    cursor.execute(
                        """UPDATE review_handoffs SET revoked_at=COALESCE(revoked_at, now())
                        WHERE run_id=%s AND consumed_at IS NULL""",
                        (run_id,),
                    )
            return changed

        return run_serializable(reset_once)

    def run_is_current(self, run_id: UUID, tenant_id: str, generation: int) -> bool:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT 1 FROM judge_runs WHERE run_id=%s AND tenant_id=%s
                AND generation=%s AND status='active' AND expires_at > now()""",
                (run_id, tenant_id, generation),
            )
            return cursor.fetchone() is not None

    def save_handoff(self, handoff: ReviewHandoff) -> None:
        def save_once() -> None:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO review_handoffs
                    (code_hash, run_id, tenant_id, workflow_id, memory_id, memory_digest,
                     purpose, issued_by_subject, expires_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        handoff.code_hash,
                        handoff.run_id,
                        handoff.tenant_id,
                        handoff.workflow_id,
                        handoff.memory_id,
                        handoff.memory_digest,
                        handoff.purpose,
                        handoff.issued_by_subject,
                        handoff.expires_at,
                    ),
                )

        run_serializable(save_once)

    def get_handoff(self, code_hash: str) -> ReviewHandoff | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute("SELECT * FROM review_handoffs WHERE code_hash=%s", (code_hash,))
            row = cursor.fetchone()
        return ReviewHandoff.model_validate(dict(cast(Any, row))) if row is not None else None

    def consume_handoff(self, code_hash: str) -> ReviewHandoff | None:
        def consume_once() -> ReviewHandoff | None:
            with self._pool.connection() as connection, connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE review_handoffs AS h SET consumed_at=now()
                    FROM judge_runs AS r
                    WHERE h.code_hash=%s AND h.run_id=r.run_id AND h.tenant_id=r.tenant_id
                      AND h.consumed_at IS NULL AND h.revoked_at IS NULL
                      AND h.expires_at > now() AND r.status='active' AND r.expires_at > now()
                    RETURNING h.*""",
                    (code_hash,),
                )
                row = cursor.fetchone()
            return ReviewHandoff.model_validate(dict(cast(Any, row))) if row is not None else None

        return run_serializable(consume_once)

    def active_run_count(self) -> int:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT count(*) AS count FROM judge_runs
                WHERE status='active' AND expires_at > now()"""
            )
            row = cursor.fetchone()
        return int(dict(cast(Any, row))["count"]) if row is not None else 0
