from typing import Any
from uuid import uuid4

from recallops.embedding import DeterministicEmbedder
from recallops.reembed import reembed_batch, vector_literal


def test_vector_literal_is_stable_and_database_compatible() -> None:
    assert vector_literal([0.0, 1.25, -0.5]) == "[0,1.25,-0.5]"


class FakeCursor:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.rowcount = 1
        self.executions: list[tuple[str, object]] = []

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def execute(self, query: str, parameters: object = None) -> None:
        self.executions.append((query, parameters))

    def fetchall(self) -> list[dict[str, Any]]:
        return self.rows


class FakeConnection:
    def __init__(self, cursor: FakeCursor) -> None:
        self._cursor = cursor

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def cursor(self) -> FakeCursor:
        return self._cursor


def test_reembed_batch_uses_compare_and_set_update() -> None:
    read_cursor = FakeCursor(
        [{"id": uuid4(), "service": "checkout", "symptom": "elevated latency"}]
    )
    update_cursor = FakeCursor([])
    connections = [FakeConnection(read_cursor), FakeConnection(update_cursor)]

    repaired = reembed_batch(
        "postgresql://test",
        DeterministicEmbedder(),
        10,
        connect=lambda *args, **kwargs: connections.pop(0),
    )

    assert repaired == 1
    assert "embedding_space='legacy:unknown:v0'" in update_cursor.executions[0][0]
    assert update_cursor.executions[0][1][1].endswith(":v1")
