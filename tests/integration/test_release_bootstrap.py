import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest

from recallops.migrate import register_release_evidence
from recallops.release_evidence import ReleaseIdentity

pytestmark = pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)


def identity(release_id: str) -> ReleaseIdentity:
    return ReleaseIdentity(
        release_id=release_id,
        source_sha="a" * 40,
        image_digest=f"sha256:{'b' * 64}",
        capability_policy_version="webmcp-capability-v1",
        receipt_policy_version="authority-receipt-policy-v1",
        evaluation_version="governed-benchmark-v1",
        receipt_key_thumbprint="c" * 43,
    )


def test_concurrent_bootstrap_is_idempotent_and_identity_is_not_rebindable() -> None:
    database_url = os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"]
    release = identity(f"integration-{uuid4().hex}")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _: register_release_evidence(database_url, release),
                range(2),
            )
        )

    assert sorted(results) == [False, True]
    with psycopg.connect(database_url, autocommit=True) as connection:
        row = connection.execute(
            """SELECT release_id,source_sha,image_digest,capability_policy_version,
            receipt_policy_version,evaluation_version,receipt_key_thumbprint,
            live_proof_status,assurance_status
            FROM release_evidence_records WHERE release_id=%s""",
            (release.release_id,),
        ).fetchone()
    assert row == (*tuple(release.model_dump().values()), "pending", "pending")

    conflicting = release.model_copy(update={"source_sha": "d" * 40})
    with pytest.raises(RuntimeError, match="immutable existing record"):
        register_release_evidence(database_url, conflicting)
