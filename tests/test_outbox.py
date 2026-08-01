from typing import Any
from uuid import uuid4

import pytest

from recallops import outbox
from recallops.resilience import DependencyUnavailable


class FakeCursor:
    def __init__(self, row: dict[str, Any] | None = None, rowcount: int = 1) -> None:
        self.row = row
        self.rowcount = rowcount
        self.executions: list[tuple[str, object]] = []

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, parameters: object = None) -> None:
        self.executions.append((query, parameters))

    def fetchone(self) -> dict[str, Any] | None:
        return self.row


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def cursor(self) -> FakeCursor:
        return self._cursor


def test_outbox_claim_acknowledgement_and_failure_release(monkeypatch: pytest.MonkeyPatch) -> None:
    message_id = uuid4()
    cursor = FakeCursor({"id": message_id, "attempts": 1})
    monkeypatch.setattr(outbox.psycopg, "connect", lambda *args, **kwargs: FakeConnection(cursor))

    assert outbox.claim("postgresql://test", "worker-1") == {
        "id": message_id,
        "attempts": 1,
    }
    assert outbox.mark_delivered("postgresql://test", message_id, "worker-1")
    outbox.release_failed(
        "postgresql://test", message_id, "worker-1", 20, "x" * 1200
    )

    assert len(cursor.executions) == 3
    assert "INTERVAL '2 minutes'" in cursor.executions[0][0]
    assert "delivered_at=now()" in cursor.executions[1][0]
    assert len(cursor.executions[2][1][1]) == 1000


class RecordingArchive:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.incidents: list[object] = []

    def archive_payload(self, *args: object) -> None:
        if self.fail:
            raise DependencyUnavailable("s3_evidence")
        self.incidents.append(args[1])


def message() -> dict[str, Any]:
    return {
        "id": uuid4(),
        "incident_id": uuid4(),
        "tenant_id": "tenant-a",
        "service": "checkout",
        "service_version": "v1",
        "payload": {"schema_version": 1},
        "attempts": 1,
    }


def test_delivery_acknowledges_success(monkeypatch: pytest.MonkeyPatch) -> None:
    pending = [message(), None]
    acknowledged: list[object] = []
    monkeypatch.setattr(outbox, "claim", lambda *args: pending.pop(0))
    monkeypatch.setattr(
        outbox,
        "mark_delivered",
        lambda database_url, message_id, worker_id: acknowledged.append(message_id) or True,
    )
    archive = RecordingArchive()

    assert outbox.deliver_available("postgresql://test", archive, "worker-1", 5) == (1, 0)
    assert len(acknowledged) == len(archive.incidents) == 1


def test_delivery_releases_failed_message(monkeypatch: pytest.MonkeyPatch) -> None:
    pending = [message()]
    released: list[object] = []
    monkeypatch.setattr(outbox, "claim", lambda *args: pending.pop(0))
    monkeypatch.setattr(
        outbox,
        "release_failed",
        lambda database_url, message_id, worker_id, attempts, error: released.append(message_id),
    )

    assert outbox.deliver_available(
        "postgresql://test", RecordingArchive(fail=True), "worker-1", 1
    ) == (0, 1)
    assert len(released) == 1
