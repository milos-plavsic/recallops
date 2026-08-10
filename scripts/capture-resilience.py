#!/usr/bin/env python3
"""Run bounded failure, concurrency, and retry-policy drills and emit evidence."""

import argparse
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

DRILLS = {
    "dependency_degradation": (
        "tests/test_resilience.py::test_provider_failures_degrade_without_inventing_action"
    ),
    "embedding_fail_closed": (
        "tests/test_resilience.py::test_embedding_failure_never_persists_fallback_vector"
    ),
    "idempotency_concurrency_64": (
        "tests/test_resilience.py::test_concurrent_idempotent_requests_return_one_incident"
    ),
    "bounded_aws_retries": (
        "tests/test_resilience.py::test_aws_policy_has_finite_timeouts_and_bounded_standard_retries"
    ),
    "outbox_retry_release": "tests/test_outbox.py::test_delivery_releases_failed_message",
    "outbox_dead_letter_budget": (
        "tests/test_outbox.py::test_outbox_dead_letters_after_retry_budget"
    ),
    "payload_free_failure_status": "tests/test_outbox.py::test_outbox_status_is_payload_free",
    "encrypted_archive_write": (
        "tests/test_archive.py::test_s3_archive_uses_deterministic_encrypted_object"
    ),
}

EXPECTED_BEHAVIOR = {
    "dependency_degradation": "abstain and emit read-only degraded trace",
    "embedding_fail_closed": "never persist a fallback vector",
    "idempotency_concurrency_64": "return one incident identity",
    "bounded_aws_retries": "finite timeouts and bounded SDK attempts",
    "outbox_retry_release": "release lease and schedule bounded retry",
    "outbox_dead_letter_budget": "terminally dead-letter after retry budget",
    "payload_free_failure_status": "expose status without evidence payload",
    "encrypted_archive_write": "write deterministic server-side-encrypted object",
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    results = []
    for name, test in DRILLS.items():
        started = time.perf_counter()
        run = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", test],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        results.append(
            {
                "name": name,
                "test": test,
                "expected_behavior": EXPECTED_BEHAVIOR[name],
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "passed": run.returncode == 0,
            }
        )
    report = {
        "evidence_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "build_sha": args.release_sha,
        "environment_class": "local-isolated-deterministic-failure-injection",
        "command": "scripts/capture-resilience.py",
        "drills": results,
        "passed": all(result["passed"] for result in results),
        "redaction": "pytest output omitted; test identifiers and timings retained",
        "limitations": (
            "Isolated component drills validate safety behavior, not regional AWS or managed "
            "CockroachDB disaster recovery. No production failure was injected."
        ),
    }
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print(encoded, end="")
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
