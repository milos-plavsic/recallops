#!/usr/bin/env python3
"""Produce paired-bootstrap evidence for every retrieval-policy ablation."""

import argparse
import json
import random
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from recallops.evaluation import (
    PolicyName,
    _rank,
    _select,
    evaluate,
    load_dataset,
)

POLICIES: tuple[PolicyName, ...] = (
    "similarity",
    "governed_similarity",
    "outcome_aware",
    "outcome_compatibility",
    "recallops",
)


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    return ordered[round((len(ordered) - 1) * quantile)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--dataset", type=Path, default=Path("evaluation/memory_cases.json"))
    parser.add_argument("--samples", type=int, default=10_000)
    parser.add_argument("--seed", type=int, default=20260810)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    dataset = load_dataset(args.dataset)
    report = evaluate(dataset)
    outcomes: dict[str, list[int]] = {}
    unsafe: dict[str, list[int]] = {}
    for policy in POLICIES:
        outcomes[policy] = []
        unsafe[policy] = []
        for case in dataset.cases:
            selected = _select(_rank(case, policy), policy)
            outcomes[policy].append(
                int((selected.id if selected else None) == case.expected_memory_id)
            )
            unsafe[policy].append(int(bool(selected and selected.unsafe)))

    rng = random.Random(args.seed)
    bootstrap: dict[str, dict[str, list[float]]] = {
        policy: {"accuracy": [], "unsafe": [], "accuracy_delta_vs_governed_similarity": []}
        for policy in POLICIES
    }
    count = len(dataset.cases)
    for _ in range(args.samples):
        indices = [rng.randrange(count) for _ in range(count)]
        governed_accuracy = sum(outcomes["governed_similarity"][i] for i in indices) / count
        for policy in POLICIES:
            accuracy = sum(outcomes[policy][i] for i in indices) / count
            bootstrap[policy]["accuracy"].append(accuracy)
            bootstrap[policy]["unsafe"].append(sum(unsafe[policy][i] for i in indices) / count)
            bootstrap[policy]["accuracy_delta_vs_governed_similarity"].append(
                accuracy - governed_accuracy
            )

    intervals: dict[str, Any] = {}
    for policy in POLICIES:
        intervals[policy] = {
            metric: {
                "lower": percentile(values, 0.025),
                "upper": percentile(values, 0.975),
            }
            for metric, values in bootstrap[policy].items()
        }
    payload = {
        "evidence_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "build_sha": args.release_sha,
        "environment_class": "local-deterministic-synthetic-policy-ablation",
        "command": "scripts/capture-ablation-evidence.py",
        "dataset": {
            "path": args.dataset.as_posix(),
            "case_count": count,
            "kind": dataset.suite_kind,
            "independent_labels": False,
        },
        "point_estimates": {
            policy: report.ablations[policy].model_dump() for policy in POLICIES
        },
        "paired_bootstrap": {
            "samples": args.samples,
            "seed": args.seed,
            "confidence_level": 0.95,
            "intervals": intervals,
        },
        "passed": report.passed,
        "redaction": "No credentials, tenant data, production incidents, or embeddings are used",
        "limitations": (
            "Six authored synthetic invariant cases; confidence intervals describe this corpus "
            "and do not establish population efficacy."
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
