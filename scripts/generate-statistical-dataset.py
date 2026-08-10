#!/usr/bin/env python3
"""Generate a deterministic, explicitly synthetic adversarial retrieval corpus."""

import copy
import json
from pathlib import Path

SOURCE = Path("evaluation/end_to_end_cases.json")
TARGET = Path("evaluation/statistical_cases.json")
VARIANTS = (
    "during a regional traffic increase",
    "after the latest rollout",
    "while the on-call dashboard shows elevated saturation",
    "with customer impact confirmed",
    "during the scheduled observation window",
    "after an upstream dependency recovered",
    "while error budgets are being consumed",
    "with no unrelated deployment in progress",
    "after normal capacity was restored",
    "during a repeat incident simulation",
    "with telemetry from two availability zones",
    "after the alert persisted for five minutes",
    "while request volume remains within forecast",
    "with traces confirming the same bottleneck",
    "after a canary reproduced the symptom",
    "during a controlled incident exercise",
    "with the service owner observing the response",
    "after cache and queue health were checked",
    "while downstream health checks remain green",
    "with the symptom independently reproduced",
)


def main() -> None:
    source = json.loads(SOURCE.read_text(encoding="utf-8"))
    cases: list[dict[str, object]] = []
    for variant_index, suffix in enumerate(VARIANTS, start=1):
        for base in source["cases"]:
            case = copy.deepcopy(base)
            case["name"] = f"{base['name']}__v{variant_index:02d}"
            case["category"] = base["name"]
            case["service"] = f"{base['service']}-eval-{variant_index:02d}"
            case["symptom"] = f"{base['symptom']} {suffix}"
            for memory in case["memories"]:
                memory["service"] = case["service"]
                memory["symptom"] = f"{memory['symptom']} {suffix}"
                memory["name"] = f"{memory['name']}__v{variant_index:02d}"
            expected = case.get("expected_memory_name")
            if expected is not None:
                case["expected_memory_name"] = f"{expected}__v{variant_index:02d}"
            cases.append(case)
    payload = {
        "schema_version": 1,
        "suite_kind": "end_to_end_retrieval",
        "provenance": {
            "kind": "synthetic_adversarial",
            "label_source": "deterministic policy oracle derived from six reviewed invariants",
            "independent_labels": "false",
            "generator": "scripts/generate-statistical-dataset.py",
            "generator_version": "1",
            "seed": "not-random",
            "limitations": (
                "Lexical variants are generated and are not production incident records."
            ),
        },
        "cases": cases,
    }
    TARGET.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} explicitly synthetic cases to {TARGET}")


if __name__ == "__main__":
    main()
