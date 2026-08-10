import os

import pytest

from recallops.db_verify import verify_database_boundaries


@pytest.mark.skipif(
    not os.getenv("RECALLOPS_INTEGRATION_DATABASE_URL"),
    reason="RECALLOPS_INTEGRATION_DATABASE_URL is required for direct database tests",
)
def test_runtime_grants_and_cross_tenant_constraints() -> None:
    report = verify_database_boundaries(os.environ["RECALLOPS_INTEGRATION_DATABASE_URL"])

    assert report["passed"] is True
    assert report["exact_runtime_grants"] == 15
    assert len(report["cross_tenant_constraints"]) == 6
    assert len(report["runtime_denials"]) == 7
