#!/usr/bin/env python3
"""Fail closed unless AWS proves a standalone active Free Plan with ample credits."""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class FreeTierClient(Protocol):
    def get_account_plan_state(self) -> dict[str, Any]: ...


class OrganizationsClient(Protocol):
    def describe_organization(self) -> dict[str, Any]: ...


def verify_zero_spend_gate(
    free_tier: FreeTierClient,
    organizations: OrganizationsClient,
    *,
    minimum_credits: float,
    minimum_days: int,
    now: datetime,
) -> dict[str, object]:
    if minimum_credits <= 0 or minimum_days < 1:
        raise ValueError("zero-spend thresholds must be positive")
    try:
        plan = free_tier.get_account_plan_state()
    except (BotoCoreError, ClientError) as error:
        raise RuntimeError("AWS Free Plan state could not be verified") from error
    try:
        organizations.describe_organization()
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") != "AWSOrganizationsNotInUseException":
            raise RuntimeError("standalone-account status could not be verified") from error
    except BotoCoreError as error:
        raise RuntimeError("standalone-account status could not be verified") from error
    else:
        raise RuntimeError("AWS Organizations membership violates the zero-spend gate")

    credits = plan.get("accountPlanRemainingCredits")
    expiration = plan.get("accountPlanExpirationDate")
    if (
        plan.get("accountPlanType") != "FREE"
        or plan.get("accountPlanStatus") != "ACTIVE"
        or not isinstance(credits, dict)
        or credits.get("unit") != "USD"
        or not isinstance(credits.get("amount"), int | float)
        or not isinstance(expiration, datetime)
    ):
        raise RuntimeError("AWS account is not an active USD-denominated Free Plan")
    if expiration.tzinfo is None:
        raise RuntimeError("AWS Free Plan expiration is not timezone-aware")
    expiration = expiration.astimezone(UTC)
    required_expiration = now.astimezone(UTC) + timedelta(days=minimum_days)
    remaining = float(credits["amount"])
    if remaining < minimum_credits:
        raise RuntimeError("AWS Free Plan credits are below the release safety floor")
    if expiration < required_expiration:
        raise RuntimeError("AWS Free Plan expires before the teardown safety horizon")
    return {
        "checked_at": now.astimezone(UTC).isoformat(),
        "plan_type": "FREE",
        "plan_status": "ACTIVE",
        "remaining_credits": {"amount": remaining, "unit": "USD"},
        "expiration": expiration.isoformat(),
        "minimum_credits": minimum_credits,
        "minimum_days": minimum_days,
        "standalone_account": True,
        "payment_card_spend_allowed": False,
        "passed": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--minimum-credits", type=float, default=50.0)
    parser.add_argument("--minimum-days", type=int, default=14)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = verify_zero_spend_gate(
        boto3.client("freetier", region_name=args.region),
        boto3.client("organizations", region_name=args.region),
        minimum_credits=args.minimum_credits,
        minimum_days=args.minimum_days,
        now=datetime.now(UTC),
    )
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")


if __name__ == "__main__":
    main()
