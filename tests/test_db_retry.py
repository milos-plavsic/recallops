from collections.abc import Callable

import pytest
from psycopg.errors import SerializationFailure

from recallops.db_retry import run_serializable


def operation_failing(times: int) -> tuple[Callable[[], str], list[int]]:
    attempts: list[int] = []

    def operation() -> str:
        attempts.append(len(attempts) + 1)
        if len(attempts) <= times:
            raise SerializationFailure()
        return "committed"

    return operation, attempts


def test_serializable_retry_restarts_whole_operation_with_bounded_backoff() -> None:
    operation, attempts = operation_failing(2)
    delays: list[float] = []

    assert run_serializable(operation, sleep=delays.append) == "committed"
    assert attempts == [1, 2, 3]
    assert delays == [0.01, 0.02]


def test_serializable_retry_propagates_last_failure() -> None:
    operation, attempts = operation_failing(3)

    with pytest.raises(SerializationFailure):
        run_serializable(operation, max_attempts=3, sleep=lambda _: None)

    assert attempts == [1, 2, 3]


def test_serializable_retry_rejects_invalid_attempt_count() -> None:
    with pytest.raises(ValueError, match="at least one"):
        run_serializable(lambda: "unused", max_attempts=0)
