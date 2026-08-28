from __future__ import annotations

import time
from collections.abc import Callable

from psycopg.errors import SerializationFailure

MAX_SERIALIZATION_ATTEMPTS = 6
BASE_RETRY_DELAY_SECONDS = 0.01


def run_serializable[T](
    operation: Callable[[], T],
    *,
    max_attempts: int = MAX_SERIALIZATION_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Retry a complete database transaction after a serialization failure.

    CockroachDB can reject a transaction at commit time under contention. The
    caller must therefore put connection acquisition and the entire transaction
    inside ``operation`` so every attempt starts from a fresh snapshot.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least one")
    for attempt in range(max_attempts):
        try:
            return operation()
        except SerializationFailure:
            if attempt == max_attempts - 1:
                raise
            sleep(BASE_RETRY_DELAY_SECONDS * (2**attempt))
    raise AssertionError(  # pragma: no cover - loop exits only by return or propagated error
        "retry loop exhausted without returning or raising"
    )
