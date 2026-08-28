from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, cast

from psycopg_pool import ConnectionPool
from pydantic import BaseModel

from recallops.db_retry import run_serializable


class JudgeSession(BaseModel):
    session_hash: str
    csrf_hash: str
    tenant_id: str
    subject: str
    role: str
    expires_at: datetime
    revoked_at: datetime | None = None


class JudgeSessionRepository(Protocol):
    def consume_attempt(self, client_hash: str, limit: int, window_seconds: int) -> bool: ...
    def save(self, session: JudgeSession) -> None: ...
    def get(self, session_hash: str) -> JudgeSession | None: ...
    def revoke(self, session_hash: str) -> None: ...


class InMemoryJudgeSessionRepository:
    def __init__(self) -> None:
        self._sessions: dict[str, JudgeSession] = {}
        self._attempts: dict[str, tuple[datetime, int]] = {}
        self._lock = threading.RLock()

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


class PostgresJudgeSessionRepository:
    def __init__(self, pool: ConnectionPool[Any]) -> None:
        self._pool = pool

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
                    (session_hash, csrf_hash, tenant_id, subject, role, expires_at)
                    VALUES (%s,%s,%s,%s,%s,%s)""",
                    (
                        session.session_hash,
                        session.csrf_hash,
                        session.tenant_id,
                        session.subject,
                        session.role,
                        session.expires_at,
                    ),
                )

        run_serializable(save_once)

    def get(self, session_hash: str) -> JudgeSession | None:
        with self._pool.connection() as connection, connection.cursor() as cursor:
            cursor.execute(
                """SELECT session_hash, csrf_hash, tenant_id, subject, role, expires_at,
                revoked_at FROM judge_sessions WHERE session_hash=%s""",
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
