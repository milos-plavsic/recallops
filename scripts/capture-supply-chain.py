#!/usr/bin/env python3
"""Capture locked-dependency, SBOM, scan, OCI-label, and managed-signing evidence."""

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--image-reference", required=True)
    parser.add_argument("--repository", default="recallops")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    ecr = boto3.client("ecr", region_name=args.region)
    scan = ecr.describe_image_scan_findings(
        repositoryName=args.repository,
        imageId={"imageDigest": args.image_digest},
    )
    signing = ecr.describe_image_signing_status(
        repositoryName=args.repository,
        imageId={"imageDigest": args.image_digest},
    )
    configuration = ecr.get_signing_configuration()["signingConfiguration"]
    inspection = json.loads(
        subprocess.check_output(
            ["docker", "image", "inspect", args.image_reference], text=True
        )
    )[0]
    labels = inspection.get("Config", {}).get("Labels", {})
    counts = scan.get("imageScanFindings", {}).get("findingSeverityCounts", {})
    signing_statuses = signing.get("signingStatuses", [])
    signature_status = signing_statuses[0].get("status") if signing_statuses else None
    assertions = {
        "production_lock_present": Path("requirements.lock").is_file(),
        "development_lock_present": Path("requirements-dev.lock").is_file(),
        "cyclonedx_sbom_present": args.sbom.is_file(),
        "exact_digest_scan_complete": scan["imageScanStatus"]["status"] == "COMPLETE",
        "exact_digest_zero_scan_findings": sum(counts.values()) == 0,
        "managed_signing_rule_present": len(configuration.get("rules", [])) > 0,
        "exact_digest_signature_successful": signature_status == "COMPLETE",
        "oci_revision_matches_release": labels.get("org.opencontainers.image.revision")
        == args.release_sha,
        "oci_source_matches_repository": labels.get("org.opencontainers.image.source")
        == "https://github.com/milos-plavsic/recallops",
        "oci_license_is_mit": labels.get("org.opencontainers.image.licenses") == "MIT",
    }
    payload: dict[str, Any] = {
        "evidence_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "build_sha": args.release_sha,
        "environment_class": f"aws-ecr-signed-release-{args.region}",
        "command": "scripts/capture-supply-chain.py",
        "subject": {"image_digest": args.image_digest},
        "materials": {
            "requirements_lock_sha256": digest(Path("requirements.lock")),
            "development_lock_sha256": digest(Path("requirements-dev.lock")),
            "uv_lock_sha256": digest(Path("uv.lock")),
            "dockerfile_sha256": digest(Path("Dockerfile")),
            "sbom_sha256": digest(args.sbom),
        },
        "sbom": {"format": "CycloneDX JSON", "source": "pip-audit against production lock"},
        "scan": {
            "status": scan["imageScanStatus"]["status"],
            "finding_count": sum(counts.values()),
            "severity_counts": counts,
        },
        "signature": {
            "method": "Amazon ECR managed signing with AWS Signer and Notation OCI platform",
            "status": signature_status,
            "rule_count": len(configuration.get("rules", [])),
        },
        "oci_labels": labels,
        "assertions": assertions,
        "passed": all(assertions.values()),
        "redaction": (
            "Account, registry, repository URI, signing profile ARN, task, and credential values "
            "omitted"
        ),
        "limitations": (
            "Registry signature and point-in-time vulnerability scan do not replace admission "
            "policy, continuous rescanning, or hermetic reproducible-build verification."
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
