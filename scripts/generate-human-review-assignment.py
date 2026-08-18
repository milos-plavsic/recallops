#!/usr/bin/env python3
"""Create a deterministic blinded A/B reviewer packet from synthetic evaluation evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from pathlib import Path
from typing import Any

LABEL_FIELDS = [
    "variant_a_safe",
    "variant_b_safe",
    "variant_a_relevance_1_5",
    "variant_b_relevance_1_5",
    "preference",
    "abstention_required",
    "confidence_1_5",
    "rationale_optional",
]


def eligible(memory: dict[str, Any]) -> bool:
    return (
        memory.get("tenant_scope") != "other"
        and memory.get("state") != "pending_review"
        and memory.get("valid", True) is not False
    )


def decision(memory: dict[str, Any] | None) -> str:
    if memory is None:
        return "ABSTAIN — insufficient eligible evidence; request human review."
    return f"Action: {memory['action']}\nObserved outcome: {memory['outcome']}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", type=Path, default=Path("evaluation/statistical_cases.json"))
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--assignment-id", required=True)
    parser.add_argument("--reviewer-pseudonym", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--count", type=int, default=24)
    args = parser.parse_args()

    dataset = json.loads(args.dataset.read_text(encoding="utf-8"))
    evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
    selected = {case["name"]: case.get("selected_memory_name") for case in evidence["cases"]}
    cases = dataset["cases"]
    if not 20 <= args.count <= 30 or args.count > len(cases):
        raise SystemExit("--count must be between 20 and 30 and no larger than the dataset")

    rng = random.Random(args.seed)
    chosen = rng.sample(cases, args.count)
    packet_rows: list[dict[str, str]] = []
    key_rows: list[dict[str, Any]] = []
    for index, case in enumerate(chosen, start=1):
        memories = case["memories"]
        by_name = {memory["name"]: memory for memory in memories}
        baseline = next((memory for memory in memories if eligible(memory)), None)
        recallops_name = selected.get(case["name"])
        recallops = by_name.get(recallops_name) if recallops_name else None
        variants = [("baseline", decision(baseline)), ("recallops", decision(recallops))]
        rng.shuffle(variants)
        case_id = f"HR-{index:02d}"
        packet_rows.append(
            {
                "assignment_id": args.assignment_id,
                "reviewer_pseudonym": args.reviewer_pseudonym,
                "case_id": case_id,
                "incident_context": (
                    f"Service: {case['service']}\nVersion: {case['service_version']}\n"
                    f"Symptom: {case['symptom']}"
                ),
                "variant_a": variants[0][1],
                "variant_b": variants[1][1],
                **{field: "" for field in LABEL_FIELDS},
            }
        )
        key_rows.append(
            {
                "case_id": case_id,
                "source_case": case["name"],
                "variant_a_system": variants[0][0],
                "variant_b_system": variants[1][0],
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    packet_path = args.output_dir / f"{args.assignment_id}.csv"
    with packet_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(packet_rows[0]))
        writer.writeheader()
        writer.writerows(packet_rows)

    key = {
        "assignment_id": args.assignment_id,
        "reviewer_pseudonym": args.reviewer_pseudonym,
        "seed": args.seed,
        "dataset": args.dataset.as_posix(),
        "dataset_sha256": hashlib.sha256(args.dataset.read_bytes()).hexdigest(),
        "evidence": args.evidence.as_posix(),
        "evidence_sha256": hashlib.sha256(args.evidence.read_bytes()).hexdigest(),
        "cases": key_rows,
    }
    (args.output_dir / f"{args.assignment_id}.key.json").write_text(
        json.dumps(key, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(packet_path)


if __name__ == "__main__":
    main()
