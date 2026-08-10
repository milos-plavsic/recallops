#!/usr/bin/env python3
"""Capture deployed dimensions, observed usage, current AWS prices, and a bounded forecast."""

import argparse
import json
import statistics
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3


def price(service: str, filters: dict[str, str], *, operation: str | None = None) -> float:
    client = boto3.client("pricing", region_name="us-east-1")
    query = [{"Type": "TERM_MATCH", "Field": key, "Value": value} for key, value in filters.items()]
    if operation:
        query.append({"Type": "TERM_MATCH", "Field": "operation", "Value": operation})
    products = client.get_products(ServiceCode=service, Filters=query, MaxResults=20)["PriceList"]
    rates = []
    for encoded in products:
        product = json.loads(encoded)
        for term in product["terms"]["OnDemand"].values():
            for dimension in term["priceDimensions"].values():
                if dimension["beginRange"] == "0":
                    rates.append(float(dimension["pricePerUnit"]["USD"]))
    if not rates:
        raise RuntimeError(f"no AWS price matched {service} {filters}")
    return max(rates) if len(rates) > 1 else rates[0]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--stack-name", default="recallops-production")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    cf = boto3.client("cloudformation", region_name=args.region)
    resources = cf.describe_stack_resources(StackName=args.stack_name)["StackResources"]
    by_type: dict[str, list[str]] = {}
    for item in resources:
        by_type.setdefault(item["ResourceType"], []).append(item["PhysicalResourceId"])
    ecs = boto3.client("ecs", region_name=args.region)
    task = ecs.describe_task_definition(
        taskDefinition=by_type["AWS::ECS::TaskDefinition"][0]
    )["taskDefinition"]
    cpu = int(task["cpu"]) / 1024
    memory_gb = int(task["memory"]) / 1024

    cloudwatch = boto3.client("cloudwatch", region_name=args.region)
    end = datetime.now(UTC)
    start = end - timedelta(hours=24)
    api_id = by_type["AWS::ApiGatewayV2::Api"][0]
    request_points = cloudwatch.get_metric_statistics(
        Namespace="AWS/ApiGateway",
        MetricName="Count",
        Dimensions=[{"Name": "ApiId", "Value": api_id}],
        StartTime=start,
        EndTime=end,
        Period=3600,
        Statistics=["Sum"],
    )["Datapoints"]
    requests_24h = sum(point["Sum"] for point in request_points)
    load_balancer_arn = by_type["AWS::ElasticLoadBalancingV2::LoadBalancer"][0]
    elb = boto3.client("elbv2", region_name=args.region)
    full_name = elb.describe_load_balancers(LoadBalancerArns=[load_balancer_arn])[
        "LoadBalancers"
    ][0]["LoadBalancerArn"].split(":loadbalancer/", 1)[1]
    lcu_points = cloudwatch.get_metric_statistics(
        Namespace="AWS/ApplicationELB",
        MetricName="ConsumedLCUs",
        Dimensions=[{"Name": "LoadBalancer", "Value": full_name}],
        StartTime=start,
        EndTime=end,
        Period=3600,
        Statistics=["Average"],
    )["Datapoints"]
    mean_lcu = statistics.fmean(point["Average"] for point in lcu_points) if lcu_points else 0

    prices = {
        "fargate_vcpu_hour": price(
            "AmazonECS",
            {"regionCode": args.region, "usagetype": "USE1-Fargate-vCPU-Hours:perCPU"},
        ),
        "fargate_gb_hour": price(
            "AmazonECS",
            {"regionCode": args.region, "usagetype": "USE1-Fargate-GB-Hours"},
        ),
        "application_load_balancer_hour": price(
            "AWSELB",
            {"regionCode": args.region, "usagetype": "LoadBalancerUsage"},
            operation="LoadBalancing:Application",
        ),
        "application_lcu_hour": price(
            "AWSELB",
            {"regionCode": args.region, "usagetype": "LCUUsage"},
            operation="LoadBalancing:Application",
        ),
        "http_api_request": price(
            "AmazonApiGateway",
            {"regionCode": args.region, "usagetype": "USE1-ApiGatewayHttpRequest"},
        ),
    }
    hours = 730
    projected_requests = requests_24h * 30.4167
    forecast = {
        "fargate": hours
        * (cpu * prices["fargate_vcpu_hour"] + memory_gb * prices["fargate_gb_hour"]),
        "application_load_balancer": hours * prices["application_load_balancer_hour"],
        "observed_lcu_projection": hours * mean_lcu * prices["application_lcu_hour"],
        "http_api_request_projection": projected_requests * prices["http_api_request"],
    }
    payload: dict[str, Any] = {
        "evidence_version": 1,
        "generated_at": end.isoformat(),
        "build_sha": args.release_sha,
        "environment_class": f"aws-public-judge-demo-{args.region}",
        "command": "scripts/capture-cost-evidence.py",
        "deployed_dimensions": {"fargate_vcpu": cpu, "fargate_memory_gb": memory_gb},
        "observed_24h": {
            "http_api_requests": requests_24h,
            "application_lcu_hourly_mean": mean_lcu,
            "metric_hours_present": len(request_points),
        },
        "current_public_prices_usd": prices,
        "monthly_projection_usd": {
            **forecast,
            "measured_subset_total": sum(forecast.values()),
        },
        "passed": all(value >= 0 for value in prices.values()),
        "redaction": "Account, API, load balancer, task, tenant, and request identifiers omitted",
        "limitations": (
            "Measured subset only. Excludes CockroachDB Cloud, S3, CloudWatch Logs/alarms, "
            "data transfer, tax, support, and optional Bedrock. The 24-hour request/LCU sample "
            "is extrapolated and is not a bill."
        ),
    }
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not payload["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
