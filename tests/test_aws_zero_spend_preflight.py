from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from botocore.exceptions import ClientError


def module() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / "aws-zero-spend-preflight.py"
    spec = importlib.util.spec_from_file_location("aws_zero_spend_preflight", path)
    assert spec is not None and spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


NOW = datetime(2026, 8, 29, tzinfo=UTC)


class FreeTier:
    def __init__(self, **updates: object) -> None:
        self.response: dict[str, Any] = {
            "accountPlanType": "FREE",
            "accountPlanStatus": "ACTIVE",
            "accountPlanRemainingCredits": {"amount": 100.0, "unit": "USD"},
            "accountPlanExpirationDate": NOW + timedelta(days=180),
        }
        self.response.update(updates)

    def get_account_plan_state(self) -> dict[str, Any]:
        return self.response


class Standalone:
    def describe_organization(self) -> dict[str, Any]:
        raise ClientError(
            {"Error": {"Code": "AWSOrganizationsNotInUseException", "Message": "none"}},
            "DescribeOrganization",
        )


def test_active_standalone_free_plan_passes_without_account_identifier() -> None:
    report = module().verify_zero_spend_gate(
        FreeTier(), Standalone(), minimum_credits=50, minimum_days=14, now=NOW
    )
    assert report["passed"] is True
    assert report["payment_card_spend_allowed"] is False
    assert "account" not in " ".join(report).replace("standalone_account", "")


@pytest.mark.parametrize(
    "updates",
    [
        {"accountPlanType": "PAID"},
        {"accountPlanStatus": "EXPIRED"},
        {"accountPlanRemainingCredits": {"amount": 49.99, "unit": "USD"}},
        {"accountPlanRemainingCredits": {"amount": 100, "unit": "EUR"}},
        {"accountPlanExpirationDate": NOW + timedelta(days=13)},
        {"accountPlanExpirationDate": datetime(2026, 9, 30)},
    ],
)
def test_nonqualifying_plan_fails_closed(updates: dict[str, object]) -> None:
    with pytest.raises(RuntimeError):
        module().verify_zero_spend_gate(
            FreeTier(**updates), Standalone(), minimum_credits=50, minimum_days=14, now=NOW
        )


def test_organization_membership_or_unverifiable_status_fails_closed() -> None:
    class Member:
        def describe_organization(self) -> dict[str, Any]:
            return {"Organization": {"Id": "o-example"}}

    class Denied:
        def describe_organization(self) -> dict[str, Any]:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "DescribeOrganization",
            )

    for organizations in (Member(), Denied()):
        with pytest.raises(RuntimeError):
            module().verify_zero_spend_gate(
                FreeTier(), organizations, minimum_credits=50, minimum_days=14, now=NOW
            )


def test_invalid_thresholds_are_rejected() -> None:
    with pytest.raises(ValueError):
        module().verify_zero_spend_gate(
            FreeTier(), Standalone(), minimum_credits=0, minimum_days=14, now=NOW
        )
