#!/usr/bin/env python3
"""Run a bounded concurrency profile against a disposable managed CockroachDB database."""

import argparse
import json
import os
import platform
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from recallops.domain import IncidentCreate, Memory
from recallops.embedding import DeterministicEmbedder
from recallops.service import DeterministicReasoner, IncidentService
from recallops.store import PostgresStore


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * quantile)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--database-url", default=os.getenv("RECALLOPS_DATABASE_URL"))
    parser.add_argument("--requests-per-level", type=int, default=12)
    parser.add_argument("--concurrency", default="1,4,8")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.database_url:
        parser.error("--database-url or RECALLOPS_DATABASE_URL is required")
    levels = [int(value) for value in args.concurrency.split(",")]
    if not levels or min(levels) < 1 or max(levels) > 10:
        parser.error("concurrency must contain values between 1 and the pool limit of 10")

    embedder = DeterministicEmbedder()
    store = PostgresStore(
        args.database_url,
        connect_timeout_seconds=30,
        statement_timeout_seconds=60,
    )
    tenant = f"load-{uuid4().hex[:12]}"
    service = "checkout-load-evidence"
    try:
        for index in range(200):
            successful = index % 4 != 0
            symptom = f"connection pool saturation shard {index % 20}"
            store.add_memory(
                Memory(
                    tenant_id=tenant,
                    service=service,
                    service_version="2026.8.0",
                    symptom=symptom,
                    action=f"bounded remediation class {index % 8}",
                    outcome="recovered" if successful else "regressed",
                    outcome_score=1.0 if successful else -1.0,
                    confidence=0.9,
                    embedding_space=embedder.space_id,
                    embedding=embedder.embed(f"{service} {symptom}"),
                )
            )
        service_layer = IncidentService(store, embedder, DeterministicReasoner())
        results = []
        for concurrency in levels:
            latencies: list[float] = []
            errors: list[str] = []

            def request(
                index: int,
                *,
                level: int = concurrency,
                samples: list[float] = latencies,
            ) -> None:
                started = time.perf_counter()
                service_layer.analyze(
                    IncidentCreate(
                        tenant_id=tenant,
                        service=service,
                        service_version="2026.8.0",
                        symptom=f"connection pool saturation shard {index % 20}",
                        idempotency_key=f"load-{level}-{index}-{uuid4().hex}",
                    )
                )
                samples.append((time.perf_counter() - started) * 1000)

            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = [
                    executor.submit(request, index) for index in range(args.requests_per_level)
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as error:  # evidence records only the exception class
                        errors.append(type(error).__name__)
            elapsed = time.perf_counter() - started
            results.append(
                {
                    "concurrency": concurrency,
                    "requests": args.requests_per_level,
                    "successes": len(latencies),
                    "errors": len(errors),
                    "error_classes": sorted(set(errors)),
                    "elapsed_seconds": round(elapsed, 6),
                    "throughput_requests_per_second": round(len(latencies) / elapsed, 6),
                    "latency_ms": {
                        "mean": statistics.fmean(latencies) if latencies else None,
                        "p50": percentile(latencies, 0.50) if latencies else None,
                        "p95": percentile(latencies, 0.95) if latencies else None,
                        "p99": percentile(latencies, 0.99) if latencies else None,
                    },
                }
            )
    finally:
        store.close()

    assertions = {
        "zero_request_errors": all(item["errors"] == 0 for item in results),
        "all_requests_completed": all(
            item["successes"] == item["requests"] for item in results
        ),
        "bounded_p95_under_10_seconds": all(
            item["latency_ms"]["p95"] is not None
            and item["latency_ms"]["p95"] < 10_000
            for item in results
        ),
    }
    payload = {
        "evidence_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "build_sha": args.release_sha,
        "environment_class": "disposable-managed-cockroach-aws-us-east-1",
        "command": "scripts/capture-managed-load.py",
        "runtime": {"python": platform.python_version(), "client_pool_max": 10},
        "corpus": {"synthetic_memories": 200, "tenant_count": 1, "service_count": 1},
        "profiles": results,
        "assertions": assertions,
        "passed": all(assertions.values()),
        "redaction": (
            "Database URL, credentials, tenant ID, rows, incident IDs, and vectors omitted"
        ),
        "limitations": (
            "Short bounded synthetic workload on a disposable database; not a saturation, "
            "soak, multi-region, or production-capacity claim."
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
