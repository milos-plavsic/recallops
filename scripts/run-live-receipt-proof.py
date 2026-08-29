#!/usr/bin/env python3
"""Run one synthetic judge journey through live KMS and versioned S3.

The command expects a freshly migrated, disposable CockroachDB database. It emits only bounded,
non-secret proof metadata and a downloaded authority bundle that the network-free Node verifier
accepts against the repository-pinned trust root.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID

import boto3
import psycopg
from fastapi.testclient import TestClient
from pydantic import SecretStr

from recallops.api import create_app
from recallops.authority_bundle import read_bundle_zip
from recallops.canonical import canonical_bytes
from recallops.config import Settings
from recallops.receipt_finalizer import production_worker


def _response(response: Any, status: int, operation: str) -> dict[str, Any]:
    if response.status_code != status:
        raise RuntimeError(f"{operation} failed closed with HTTP {response.status_code}")
    value = response.json()
    if not isinstance(value, dict):
        raise RuntimeError(f"{operation} returned an invalid response")
    return cast(dict[str, Any], value)


def _secret(client: Any, arn: str) -> str:
    response = client.get_secret_value(SecretId=arn)
    value = response.get("SecretString")
    if not isinstance(value, str) or len(value) < 32:
        raise RuntimeError("generated AWS secret is unavailable or too short")
    return value


@contextmanager
def _worker_environment(settings: Settings) -> Iterator[None]:
    values = {
        "RECALLOPS_DATABASE_URL": settings.database_url,
        "RECALLOPS_STORE": "postgres",
        "RECALLOPS_AWS_REGION": settings.aws_region,
        "RECALLOPS_BUILD_SHA": settings.build_sha,
        "RECALLOPS_RELEASE_IMAGE_DIGEST": settings.release_image_digest,
        "RECALLOPS_RECEIPT_RELEASE_ID": str(settings.receipt_release_id),
        "RECALLOPS_RECEIPT_KMS_KEY_ID": str(settings.receipt_kms_key_id),
        "RECALLOPS_RECEIPT_TRUSTED_KEYS_JSON": cast(
            SecretStr, settings.receipt_trusted_keys_json
        ).get_secret_value(),
        "RECALLOPS_RECEIPT_RELEASE_ARTIFACTS_BUCKET": str(
            settings.receipt_release_artifacts_bucket
        ),
        "RECALLOPS_RECEIPT_RELEASE_ARTIFACTS_PREFIX": str(
            settings.receipt_release_artifacts_prefix
        ),
        "RECALLOPS_RECEIPT_RELEASE_ARTIFACTS_MANIFEST_JSON": cast(
            SecretStr, settings.receipt_release_artifacts_manifest_json
        ).get_secret_value(),
        "RECALLOPS_RECEIPT_SUBJECT_PSEUDONYM_KEY_B64": cast(
            SecretStr, settings.receipt_subject_pseudonym_key_b64
        ).get_secret_value(),
        "RECALLOPS_AUTHORITY_BUNDLE_BUCKET": str(settings.authority_bundle_bucket),
        "RECALLOPS_AUTHORITY_BUNDLE_KMS_KEY_ID": str(
            settings.authority_bundle_kms_key_id
        ),
        "RECALLOPS_CAPABILITY_POLICY_VERSION": settings.capability_policy_version,
        "RECALLOPS_RECEIPT_POLICY_VERSION": settings.receipt_policy_version,
        "RECALLOPS_EVALUATION_VERSION": settings.evaluation_version,
    }
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _insert_release(settings: Settings, key_thumbprint: str) -> None:
    with psycopg.connect(settings.database_url) as connection:
        connection.execute(
            """INSERT INTO release_evidence_records
            (release_id,source_sha,image_digest,capability_policy_version,
             receipt_policy_version,evaluation_version,receipt_key_thumbprint,
             live_proof_status,assurance_status)
            VALUES (%s,%s,%s,%s,%s,%s,%s,'pending','pending')""",
            (
                settings.receipt_release_id,
                settings.build_sha,
                settings.release_image_digest,
                settings.capability_policy_version,
                settings.receipt_policy_version,
                settings.evaluation_version,
                key_thumbprint,
            ),
        )


def _archive_binding(database_url: str, receipt_id: UUID) -> tuple[str, str, str]:
    with psycopg.connect(database_url) as connection:
        row = connection.execute(
            """SELECT bundle_object_key,s3_version_id,bundle_digest
            FROM authority_receipts
            WHERE receipt_id=%s AND status='signed' AND public_at IS NOT NULL""",
            (receipt_id,),
        ).fetchone()
    if row is None or not all(isinstance(value, str) and value for value in row):
        raise RuntimeError("signed receipt lacks an exact public S3 version binding")
    return cast(tuple[str, str, str], tuple(row))


def _complete_journey(app: Any) -> UUID:
    origin = "http://testserver"
    operator = TestClient(app)
    started = _response(
        operator.post(
            "/v1/judge/runs",
            headers={"Origin": origin, "Content-Type": "application/json"},
            json={},
        ),
        201,
        "judge run creation",
    )
    run_payload = cast(dict[str, Any], started["run"])
    identity = cast(dict[str, Any], started["identity"])
    run = app.state.judge_repository.get_run(UUID(str(run_payload["run_id"])))
    if run is None:
        raise RuntimeError("judge run was not persisted")
    manifest = _response(
        operator.get("/v1/webmcp/capabilities"), 200, "initial capability manifest"
    )
    incident = cast(
        dict[str, Any],
        _response(operator.get("/v1/webmcp/incident"), 200, "incident inspection")[
            "incident"
        ],
    )
    proposal = _response(
        operator.post(
            "/v1/webmcp/proposal",
            headers={
                "Origin": origin,
                "Content-Type": "application/json",
                "If-Match": f'"{manifest["run_generation"]}:{manifest["epoch"]}"',
                "Idempotency-Key": "live-proof-proposal-0001",
            },
            json={
                "service": incident["service"],
                "service_version": incident["service_version"],
                "symptom": incident["symptom"],
                "rationale": "Use only policy-eligible independently reviewed evidence.",
            },
        ),
        201,
        "proposal staging",
    )
    ui_headers = {
        "Origin": origin,
        "X-CSRF-Token": str(started["csrf_token"]),
        "X-RecallOps-Channel": "ui",
    }
    _response(
        operator.post(
            f"/v1/incidents/{run.source_incident_id}/approval",
            headers={**ui_headers, "X-Workflow-Epoch": "2"},
            json={
                "tenant_id": run.tenant_id,
                "approved": True,
                "actor_id": identity["subject"],
                "proposal_hash": proposal["proposal_digest"],
                "reason": "Operator approved the exact bound proposal digest.",
            },
        ),
        200,
        "operator approval",
    )
    execution = _response(
        operator.post(
            f"/v1/incidents/{run.source_incident_id}/sandbox-execution",
            headers={**ui_headers, "X-Workflow-Epoch": "3"},
            json={
                "tenant_id": run.tenant_id,
                "actor_id": identity["subject"],
                "proposal_hash": proposal["proposal_digest"],
                "idempotency_key": "live-proof-sandbox-0001",
            },
        ),
        201,
        "sandbox execution and observation",
    )
    ready = _response(
        operator.get("/v1/webmcp/capabilities"), 200, "postcheck capability manifest"
    )
    assessment = _response(
        operator.post(
            "/v1/webmcp/assessment",
            headers={
                "Origin": origin,
                "Content-Type": "application/json",
                "If-Match": f'"{ready["run_generation"]}:{ready["epoch"]}"',
                "Idempotency-Key": "live-proof-assessment-0001",
            },
            json={
                "observation_id": execution["observation"]["id"],
                "classification": "not_recovered",
                "rationale": "Deliberate disagreement retained for independent review.",
            },
        ),
        201,
        "agent assessment",
    )
    memory = cast(dict[str, Any], assessment["memory"])
    handoff = _response(
        operator.post(
            "/v1/operator/reviewer-handoff",
            headers={"Origin": origin, "X-CSRF-Token": str(started["csrf_token"])},
            json={"purpose": "initial_review", "memory_digest": memory["digest"]},
        ),
        201,
        "reviewer handoff",
    )
    code = urlsplit(str(handoff["reviewer_url"])).fragment.removeprefix("review=")
    reviewer = TestClient(app)
    exchange = _response(
        reviewer.post(
            "/v1/judge/reviewer-exchange",
            headers={"Origin": origin, "Content-Type": "application/json"},
            json={"code": code},
        ),
        200,
        "independent reviewer exchange",
    )
    evidence = _response(
        reviewer.get("/v1/reviewer/evidence"), 200, "reviewer evidence"
    )
    precondition = cast(dict[str, Any], evidence["precondition"])
    disposition = _response(
        reviewer.post(
            "/v1/reviewer/disposition",
            headers={
                "Origin": origin,
                "Content-Type": "application/json",
                "X-CSRF-Token": str(exchange["csrf_token"]),
                "If-Match": (
                    f'"{precondition["generation"]}:{precondition["epoch"]}"'
                ),
            },
            json={
                "decision": "certify",
                "memory_digest": memory["digest"],
                "reason_code": "EVIDENCE_ACCEPTED",
                "note": "Independent reviewer accepts measured evidence and policy verdict.",
            },
        ),
        200,
        "reviewer disposition",
    )
    receipt = cast(dict[str, Any], disposition["receipt"])
    if receipt.get("status") != "pending":
        raise RuntimeError("review did not create exactly one pending receipt")
    return UUID(str(receipt["receipt_id"]))


def run_live_proof(arguments: argparse.Namespace) -> Mapping[str, object]:
    registry_bytes = arguments.registry.read_bytes()
    registry = json.loads(registry_bytes)
    authorized_keys = [
        key
        for key in registry["keys"]
        if key.get("status") == "active"
        and arguments.release_id in key.get("release_ids", [])
    ]
    if len(authorized_keys) != 1:
        raise RuntimeError(
            "requested release must resolve to exactly one active repository-pinned key"
        )
    key = authorized_keys[0]
    manifest_json = arguments.release_manifest.read_text()
    secrets = boto3.client("secretsmanager", region_name=arguments.region)
    settings = Settings(
        database_url=arguments.database_url,
        store="postgres",
        aws_region=arguments.region,
        auth_mode="judge",
        public_origin="http://testserver",
        judge_cookie_secure=False,
        judge_rate_limit_key=SecretStr(_secret(secrets, arguments.judge_secret_arn)),
        build_sha=arguments.source_sha,
        release_image_digest=arguments.image_digest,
        receipt_release_id=arguments.release_id,
        receipt_kms_key_id=arguments.signing_key_arn,
        receipt_trusted_keys_json=SecretStr(registry_bytes.decode("utf-8")),
        receipt_release_artifacts_bucket=arguments.bucket,
        receipt_release_artifacts_prefix=arguments.release_prefix,
        receipt_release_artifacts_manifest_json=SecretStr(manifest_json),
        receipt_subject_pseudonym_key_b64=SecretStr(
            _secret(secrets, arguments.pseudonym_secret_arn)
        ),
        authority_bundle_bucket=arguments.bucket,
        authority_bundle_kms_key_id=arguments.encryption_key_arn,
    )
    _insert_release(settings, str(key["kid"]))
    app = create_app(settings)
    receipt_id = _complete_journey(app)
    with _worker_environment(settings):
        result = production_worker("live-proof-worker").run_once()
    if result.status != "signed" or result.receipt_id != str(receipt_id):
        raise RuntimeError(f"production receipt worker failed closed: {result.status}")

    object_key, version_id, recorded_digest = _archive_binding(
        settings.database_url, receipt_id
    )
    s3 = boto3.client("s3", region_name=arguments.region)
    head = s3.head_object(
        Bucket=arguments.bucket,
        Key=object_key,
        VersionId=version_id,
    )
    if (
        head.get("VersionId") != version_id
        or head.get("ServerSideEncryption") != "aws:kms"
        or head.get("SSEKMSKeyId") != arguments.encryption_key_arn
        or head.get("BucketKeyEnabled") is not True
        or head.get("ObjectLockMode") != "COMPLIANCE"
        or head.get("Metadata", {}).get("bundle-digest") != recorded_digest
    ):
        raise RuntimeError("live S3 object does not satisfy the frozen archive profile")

    response = TestClient(app).get(
        f"/public/evidence/{receipt_id}/authority-bundle.zip"
    )
    if response.status_code != 200:
        raise RuntimeError(f"credential-free bundle download returned {response.status_code}")
    digest = response.headers.get("x-recallops-bundle-digest", "")
    if digest != recorded_digest:
        raise RuntimeError("credential-free download differs from the recorded S3 version")
    files = read_bundle_zip(response.content)
    bundle_root = arguments.output / "authority-bundle"
    for name, value in files.items():
        destination = bundle_root / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value)
    arguments.output.mkdir(parents=True, exist_ok=True)
    (arguments.output / "authority-bundle.zip").write_bytes(response.content)
    completed = subprocess.run(
        [
            "node",
            "tools/verify-authority-bundle.mjs",
            str(bundle_root),
            "--registry",
            str(arguments.registry),
            "--bundle-digest",
            digest,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    verifier = json.loads(completed.stdout)
    if verifier.get("code") != "VERIFIED":
        raise RuntimeError("network-free verifier rejected the downloaded live bundle")
    proof = {
        "bundle_digest": digest,
        "credential_free_download": True,
        "image_digest": arguments.image_digest,
        "key_thumbprint": key["kid"],
        "receipt_id": str(receipt_id),
        "release_id": arguments.release_id,
        "s3_kms_encrypted": True,
        "s3_object_key": object_key,
        "s3_object_lock_mode": "COMPLIANCE",
        "s3_object_lock_retain_until": str(head.get("ObjectLockRetainUntilDate")),
        "s3_version_id": version_id,
        "source_sha": arguments.source_sha,
        "verifier_code": verifier["code"],
        "verifier_event_count": verifier["event_count"],
        "worker_status": result.status,
    }
    (arguments.output / "proof.jcs.json").write_bytes(canonical_bytes(proof))
    return proof


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--database-url", required=True)
    result.add_argument("--release-id", required=True)
    result.add_argument("--source-sha", required=True)
    result.add_argument("--image-digest", required=True)
    result.add_argument("--signing-key-arn", required=True)
    result.add_argument("--encryption-key-arn", required=True)
    result.add_argument("--bucket", required=True)
    result.add_argument("--judge-secret-arn", required=True)
    result.add_argument("--pseudonym-secret-arn", required=True)
    result.add_argument("--release-prefix", required=True)
    result.add_argument("--release-manifest", type=Path, required=True)
    result.add_argument("--registry", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--region", default="us-east-1")
    return result


def main() -> None:
    print(json.dumps(run_live_proof(parser().parse_args()), sort_keys=True))


if __name__ == "__main__":
    main()
