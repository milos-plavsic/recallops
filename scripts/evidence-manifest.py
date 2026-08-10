#!/usr/bin/env python3
"""Build and validate a content-addressed, release-specific evidence catalog."""

import argparse
import hashlib
import json
import mimetypes
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SECRET_PATTERNS = {
    "database_url": re.compile(r"postgres(?:ql)?://[^\s\"']+", re.IGNORECASE),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b"),
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def infer_release(path: Path) -> str | None:
    for part in reversed(path.parts):
        candidate = part.removesuffix(path.suffix)
        if SHA_RE.fullmatch(candidate):
            return candidate
    return None


def inspect_artifact(path: Path) -> dict[str, Any]:
    relative = path.relative_to(EVIDENCE).as_posix()
    raw = path.read_text(encoding="utf-8", errors="strict")
    violations = [name for name, pattern in SECRET_PATTERNS.items() if pattern.search(raw)]
    metadata: dict[str, Any] = {}
    if path.suffix == ".json":
        payload = json.loads(raw)
        if isinstance(payload, dict):
            metadata = {
                key: payload[key]
                for key in (
                    "evidence_version",
                    "generated_at",
                    "build_sha",
                    "environment_class",
                    "passed",
                    "limitations",
                )
                if key in payload
            }
    return {
        "path": relative,
        "media_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
        "release_sha": infer_release(path),
        "metadata": metadata,
        "redaction_scan": {"passed": not violations, "violations": violations},
    }


def build(release_sha: str) -> tuple[dict[str, Any], str]:
    if not SHA_RE.fullmatch(release_sha):
        raise SystemExit("--release-sha must be a full lowercase Git SHA")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", release_sha, "HEAD"], cwd=ROOT, check=True
    )
    excluded = {"manifest.json", "REPORT.md"}
    paths = sorted(
        path
        for path in EVIDENCE.rglob("*")
        if path.is_file() and path.name not in excluded
    )
    artifacts = [inspect_artifact(path) for path in paths]
    claims_payload = json.loads((EVIDENCE / "claims.json").read_text(encoding="utf-8"))
    available = {artifact["path"] for artifact in artifacts}
    claim_results = []
    for claim in claims_payload["claims"]:
        expected = [path.replace("<release>", release_sha) for path in claim["artifacts"]]
        missing = [path for path in expected if path not in available]
        claim_results.append({**claim, "resolved_artifacts": expected, "missing": missing})
    release_artifacts = [item for item in artifacts if item["release_sha"] == release_sha]
    violations = [
        {"path": item["path"], "violations": item["redaction_scan"]["violations"]}
        for item in artifacts
        if not item["redaction_scan"]["passed"]
    ]
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "subject": {
            "name": "RecallOps",
            "release_sha": release_sha,
            "repository_head": git("rev-parse", "HEAD"),
            "repository": git("config", "--get", "remote.origin.url"),
        },
        "methodology": {
            "integrity": "SHA-256 content digests over every catalogued artifact",
            "provenance": "release SHA, capture time, environment class, command, pass criteria",
            "redaction": "automated high-signal secret scan plus artifact-specific sanitization",
            "inspiration": ["SLSA provenance", "CycloneDX", "AWS Well-Architected"],
        },
        "summary": {
            "artifact_count": len(artifacts),
            "release_artifact_count": len(release_artifacts),
            "claim_count": len(claim_results),
            "complete_claim_count": sum(not item["missing"] for item in claim_results),
            "redaction_violations": len(violations),
        },
        "claims": claim_results,
        "artifacts": artifacts,
        "validation": {
            "passed": not violations and all(not item["missing"] for item in claim_results),
            "redaction_violations": violations,
        },
    }
    lines = [
        "# RecallOps release evidence report",
        "",
        f"Release: `{release_sha}`",
        f"Generated: `{manifest['generated_at']}`",
        "",
        "## Claim coverage",
        "",
        "| Criterion | Claim | Evidence | Status |",
        "| --- | --- | --- | --- |",
    ]
    for claim in claim_results:
        links = "<br>".join(f"`{path}`" for path in claim["resolved_artifacts"])
        status = "PASS" if not claim["missing"] else "MISSING: " + ", ".join(claim["missing"])
        lines.append(f"| {claim['criterion']} | {claim['claim']} | {links} | {status} |")
    lines.extend(
        [
            "",
            "## Integrity",
            "",
            f"- Catalogued artifacts: {len(artifacts)}",
            f"- Release-specific artifacts: {len(release_artifacts)}",
            f"- Redaction violations: {len(violations)}",
            "- Every artifact digest is recorded in `evidence/manifest.json`.",
            "- Synthetic evidence is labelled and is not represented as production data.",
            "",
        ]
    )
    return manifest, "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    manifest, report = build(args.release_sha)
    (EVIDENCE / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (EVIDENCE / "REPORT.md").write_text(report, encoding="utf-8")
    print(json.dumps(manifest["summary"], indent=2))
    if not manifest["validation"]["passed"] and not args.allow_incomplete:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
