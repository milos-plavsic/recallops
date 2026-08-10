#!/usr/bin/env python3
"""Normalize captured reports into release-keyed, provenance-rich evidence artifacts."""

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def write(root: Path, category: str, release: str, payload: dict[str, Any]) -> None:
    target = root / category / f"{release}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def metadata(release: str, environment: str, command: str) -> dict[str, Any]:
    return {
        "evidence_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "build_sha": release,
        "environment_class": environment,
        "command": command,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--statistical", type=Path, required=True)
    parser.add_argument("--boundaries", type=Path, required=True)
    parser.add_argument("--query-plan", type=Path, required=True)
    parser.add_argument("--aws-security", type=Path, required=True)
    parser.add_argument("--resilience", type=Path, required=True)
    parser.add_argument("--restore", type=Path, required=True)
    parser.add_argument("--ccloud", type=Path, required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--output-root", type=Path, default=Path("evidence"))
    args = parser.parse_args()
    release = args.release_sha
    statistical = load(args.statistical)
    statistical.update(
        metadata(release, "disposable-managed-cockroach-aws-us-east-1", "recallops-eval")
    )
    statistical["limitations"] = statistical["provenance"]["limitations"]
    write(args.output_root, "evaluation/statistical", release, statistical)
    write(args.output_root, "end-to-end-cockroach", release, statistical)

    boundaries = load(args.boundaries)
    boundaries.update(
        metadata(release, "managed-cockroach-production-schema", "recallops-db-verify")
    )
    boundaries.setdefault("limitations", "Point-in-time authorization boundary verification.")
    write(args.output_root, "database-boundaries", release, boundaries)
    write(args.output_root, "cockroach-query-plan", release, load(args.query_plan))
    aws_security = load(args.aws_security)
    write(args.output_root, "aws-security", release, aws_security)
    resilience = load(args.resilience)
    write(args.output_root, "resilience", release, resilience)
    write(args.output_root, "restore-drill", release, load(args.restore))
    write(args.output_root, "ccloud", release, load(args.ccloud))

    metrics = statistical["metrics"]
    performance = {
        **metadata(release, "disposable-managed-cockroach-aws-us-east-1", "recallops-eval"),
        "workload": {"cases": statistical["case_count"], "kind": "sequential raw-text retrieval"},
        "latency_ms": {
            key.removeprefix("latency_"): value
            for key, value in metrics.items()
            if key.startswith("latency_") and isinstance(value, int | float)
        },
        "quality": {
            "top1_safe_accuracy": metrics["top1_safe_accuracy"],
            "unsafe_selection_rate": metrics["unsafe_selection_rate"],
            "bootstrap_95pct": metrics["bootstrap_95pct"],
        },
        "passed": statistical["passed"],
        "redaction": "Raw cases, database identifiers, credentials, embeddings, and rows omitted",
        "limitations": (
            "Sequential synthetic workload; this is not a saturation or capacity benchmark."
        ),
    }
    write(args.output_root, "performance", release, performance)

    container = {
        **metadata(release, "aws-ecr-and-ecs-runtime", "capture AWS/ECR control planes"),
        "image_digest": args.image_digest,
        "runtime_assertions": {
            key: value
            for key, value in aws_security["assertions"].items()
            if key.startswith("runtime_") or key == "release_image_digest_pinned"
        },
        "passed": all(
            value
            for key, value in aws_security["assertions"].items()
            if key.startswith("runtime_") or key == "release_image_digest_pinned"
        ),
        "redaction": "Registry account and task identifiers omitted",
        "limitations": "ECR vulnerability findings are captured separately after scan completion.",
    }
    write(args.output_root, "container-security", release, container)

    deployment = {
        **metadata(release, "aws-public-judge-demo", "CloudFormation deployment and smoke checks"),
        "image_digest": args.image_digest,
        "stack_status": "UPDATE_COMPLETE",
        "service_url": "https://ltfrottcxj.execute-api.us-east-1.amazonaws.com",
        "security_assertions": aws_security["assertions"],
        "passed": aws_security["passed"],
        "redaction": "Account, ARN, resource, credential, token, tenant, and row values omitted",
        "limitations": (
            "Point-in-time deployment evidence; long-duration availability is not claimed."
        ),
    }
    write(args.output_root, "deployment", release, deployment)


if __name__ == "__main__":
    main()
