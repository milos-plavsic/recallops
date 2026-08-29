#!/usr/bin/env python3
"""Generate the deterministic RecallOps PRD requirement trace skeleton."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRD_PATH = ROOT / "docs" / "hackathon-build" / "prd.md"
OUTPUT_PATH = ROOT / "evidence" / "requirements-trace.json"


@dataclass(frozen=True)
class Requirement:
    requirement_id: str
    text: str
    owner: str
    boundary: str
    live_proof: str
    assurance: str


EPIC_BOUNDARIES: dict[int, tuple[str, str, str, str]] = {
    1: (
        "Judge Run Service / Control Room",
        "run allocation and first viewport",
        "/",
        "tests/browser/recallops.spec.ts",
    ),
    2: (
        "Retrieval Service / WebMCP Registry",
        "bounded inspection and eligibility-before-ranking",
        "/#incident-evidence",
        "tests/test_retrieval.py",
    ),
    3: (
        "Proposal Service / Workflow Policy",
        "proposal schema, CAS transition, and withdrawal",
        "/#capability-inspector",
        "tests/webmcp-native/native.spec.ts",
    ),
    4: (
        "Authentication / Sandbox Service",
        "role-bound approval and exact allowlisted action",
        "/#protected-action",
        "tests/test_sandbox.py",
    ),
    5: (
        "Observation / Assessment Service",
        "immutable observation, verdict, and attributable assessment",
        "/#postcheck-evidence",
        "tests/test_sandbox.py",
    ),
    6: (
        "Memory Governance Service",
        "distinct reviewer and immutable disposition lifecycle",
        "/reviewer",
        "tests/test_service.py",
    ),
    7: (
        "Retrieval Service",
        "review-gated recurrence predicates",
        "/#recurrence",
        "tests/test_retrieval.py",
    ),
    8: (
        "Control Room / Authority Ledger",
        "visible capabilities, chronology, and receipt",
        "/#authority-proof",
        "tests/browser/recallops.spec.ts",
    ),
    9: (
        "Transaction Coordinator / Browser Client",
        "reconciliation, replay, and degraded operation",
        "/#synchronization-status",
        "tests/test_api.py",
    ),
    10: (
        "Accessible Browser Client",
        "assistive and cross-client completion",
        "/",
        "tests/browser/recallops.spec.ts",
    ),
    11: (
        "Evaluation / Release Evidence",
        "fair benchmark, claims, and independent gates",
        "/#readiness",
        "tests/test_evaluation.py",
    ),
    12: (
        "Judge Run / Release Pipeline",
        "public isolation and frozen release coherence",
        "/",
        "scripts/smoke-live.mjs",
    ),
}

EDGE_BOUNDARY = (
    "Cross-cutting boundary owner",
    "edge-case response and forbidden-behavior guard",
    "/#activity-rail",
    "tests/test_api.py",
)

XCUT_BOUNDARIES: dict[str, tuple[str, str, str, str]] = {
    "XSEC": (
        "Security boundary owners",
        "server-side authority and isolation",
        "/#capability-inspector",
        "tests/integration/test_database_boundaries.py",
    ),
    "XFUNC": (
        "Workflow / Control Room",
        "authoritative cross-surface coherence",
        "/",
        "tests/browser/recallops.spec.ts",
    ),
    "XA11Y": (
        "Accessible Browser Client",
        "semantic and assistive completion",
        "/",
        "tests/browser/recallops.spec.ts",
    ),
    "XEVID": (
        "Release Evidence",
        "generated build-bound proof and limitations",
        "/#authority-proof",
        "tests/test_release_evidence.py",
    ),
}


def normalized(text: str) -> str:
    return " ".join(text.split())


def bullet_items(block: str) -> list[str]:
    items: list[str] = []
    current: list[str] = []
    for line in block.splitlines():
        if line.startswith("- "):
            if current:
                items.append(normalized(" ".join(current)))
            current = [line[2:]]
        elif current and (line.startswith("  ") or not line.strip()):
            if line.strip():
                current.append(line.strip())
        elif current:
            items.append(normalized(" ".join(current)))
            current = []
    if current:
        items.append(normalized(" ".join(current)))
    return items


def parse_story_requirements(prd: str) -> list[Requirement]:
    story_area = prd.split("\n## Edge Cases And Required Responses", 1)[0]
    parts = re.split(r"^#### Story (\d+\.\d+) — ", story_area, flags=re.MULTILINE)
    requirements: list[Requirement] = []
    for index in range(1, len(parts), 2):
        story_id = parts[index]
        body = parts[index + 1].split("\n#### Story ", 1)[0].split("\n### Epic ", 1)[0]
        acceptance = body.split("Acceptance criteria:", 1)[1]
        epic = int(story_id.split(".", 1)[0])
        owner, boundary, live, assurance = EPIC_BOUNDARIES[epic]
        for ordinal, text in enumerate(bullet_items(acceptance), start=1):
            requirements.append(
                Requirement(f"PRD-{story_id}-AC{ordinal}", text, owner, boundary, live, assurance)
            )
    return requirements


def parse_edge_requirements(prd: str) -> list[Requirement]:
    block = prd.split("## Edge Cases And Required Responses", 1)[1].split(
        "## Cross-Cutting Acceptance Standards", 1
    )[0]
    rows = [line for line in block.splitlines() if line.startswith("| ")][2:]
    owner, boundary, live, assurance = EDGE_BOUNDARY
    requirements: list[Requirement] = []
    for ordinal, row in enumerate(rows, start=1):
        cells = [normalized(cell) for cell in row.strip("|").split("|")]
        text = f"Situation: {cells[0]}. Required: {cells[1]}. Forbidden: {cells[2]}."
        requirements.append(
            Requirement(f"EDGE-{ordinal:02d}", text, owner, boundary, live, assurance)
        )
    return requirements


def parse_cross_cutting_requirements(prd: str) -> list[Requirement]:
    block = prd.split("## Cross-Cutting Acceptance Standards", 1)[1].split(
        "## What We Are Building", 1
    )[0]
    groups = [
        ("Security and authority", "XSEC"),
        ("Functional coherence", "XFUNC"),
        ("Accessibility and comprehension", "XA11Y"),
        ("Evidence quality", "XEVID"),
    ]
    requirements: list[Requirement] = []
    for index, (heading, prefix) in enumerate(groups):
        start = block.split(f"### {heading}", 1)[1]
        if index + 1 < len(groups):
            start = start.split(f"### {groups[index + 1][0]}", 1)[0]
        owner, boundary, live, assurance = XCUT_BOUNDARIES[prefix]
        for ordinal, text in enumerate(bullet_items(start), start=1):
            requirements.append(
                Requirement(f"{prefix}-{ordinal:02d}", text, owner, boundary, live, assurance)
            )
    return requirements


def git_sha() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def build_document() -> dict[str, object]:
    prd = PRD_PATH.read_text(encoding="utf-8")
    requirements = (
        parse_story_requirements(prd)
        + parse_edge_requirements(prd)
        + parse_cross_cutting_requirements(prd)
    )
    identifiers = [requirement.requirement_id for requirement in requirements]
    if len(identifiers) != 180 or len(set(identifiers)) != 180:
        raise ValueError(f"expected 180 unique requirements, got {len(identifiers)}")

    records: list[dict[str, object]] = []
    for requirement in requirements:
        slug = requirement.requirement_id.lower().replace(".", "-")
        records.append(
            {
                "id": requirement.requirement_id,
                "requirement": requirement.text,
                "requirement_sha256": hashlib.sha256(requirement.text.encode("utf-8")).hexdigest(),
                "owner": requirement.owner,
                "enforcing_boundary": requirement.boundary,
                "positive_test": f"REQ-{slug}-positive",
                "negative_test": f"REQ-{slug}-negative",
                "live_proof": requirement.live_proof,
                "assurance_artifact": requirement.assurance,
                "source_revision": git_sha(),
                "status": "planned",
            }
        )
    return {
        "schema_version": "recallops-requirements-trace-v1",
        "source_prd": "docs/hackathon-build/prd.md",
        "source_prd_sha256": hashlib.sha256(PRD_PATH.read_bytes()).hexdigest(),
        "source_revision": git_sha(),
        "counts": {
            "story_acceptance": 149,
            "edge_cases": 16,
            "cross_cutting": 15,
            "total": 180,
        },
        "status_policy": {
            "allowed": ["planned", "implemented", "verified", "failed", "stale"],
            "release_complete_only_when": "all records are verified for the exact release",
            "waivers_allowed": False,
        },
        "requirements": records,
    }


def encoded_document() -> bytes:
    return (json.dumps(build_document(), indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def validate_document(actual: dict[str, object]) -> bool:
    expected = build_document()
    if any(
        actual.get(field) != expected[field]
        for field in (
            "schema_version",
            "source_prd",
            "source_prd_sha256",
            "counts",
            "status_policy",
        )
    ):
        return False
    source_revision = actual.get("source_revision")
    if not isinstance(source_revision, str) or not re.fullmatch(r"[a-f0-9]{40}", source_revision):
        return False
    actual_records = actual.get("requirements")
    expected_records = expected["requirements"]
    if not isinstance(actual_records, list) or not isinstance(expected_records, list):
        return False
    if len(actual_records) != 180:
        return False
    exact_fields = (
        "id",
        "requirement",
        "requirement_sha256",
        "owner",
        "enforcing_boundary",
        "positive_test",
        "negative_test",
        "live_proof",
        "assurance_artifact",
    )
    allowed_statuses = set(expected["status_policy"]["allowed"])
    seen: set[str] = set()
    for record, expected_record in zip(actual_records, expected_records, strict=True):
        if not isinstance(record, dict) or not isinstance(expected_record, dict):
            return False
        if any(record.get(field) != expected_record[field] for field in exact_fields):
            return False
        identifier = record.get("id")
        if not isinstance(identifier, str) or identifier in seen:
            return False
        seen.add(identifier)
        if record.get("source_revision") != source_revision:
            return False
        if record.get("status") not in allowed_statuses:
            return False
        for field in ("claim_ids", "raw_evidence", "receipt_fields"):
            value = record.get(field)
            if not isinstance(value, list) or not value:
                return False
        if not isinstance(record.get("reproduce"), str) or not record["reproduce"]:
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        try:
            actual = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            actual = {}
        if not validate_document(actual):
            print(f"stale requirement trace: {OUTPUT_PATH.relative_to(ROOT)}")
            return 1
        print("requirements trace valid: 149/149 story, 16/16 edge, 15/15 cross-cutting")
        return 0
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_bytes(encoded_document())
    print(f"wrote {OUTPUT_PATH.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
