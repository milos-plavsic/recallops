#!/usr/bin/env python3
"""Write the three frozen release documents to exact versioned private S3 objects."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any, Protocol

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from recallops.receipts import canonical_bytes, parse_canonical_json

DOCUMENTS = (
    "evaluation-case.jcs.json",
    "evaluation-result.jcs.json",
    "claims.jcs.json",
)
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024


class S3Client(Protocol):
    def put_object(self, **kwargs: object) -> dict[str, Any]: ...
    def head_object(self, **kwargs: object) -> dict[str, Any]: ...


def _validated_document(path: Path) -> bytes:
    value = path.read_bytes()
    if not value or len(value) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"{path.name} has an invalid size")
    parsed = parse_canonical_json(value)
    if not isinstance(parsed, dict) or canonical_bytes(parsed) != value:
        raise ValueError(f"{path.name} is not a canonical JSON object")
    return value


def _recorded_version(response: dict[str, Any], key_arn: str, digest: str) -> str:
    version = response.get("VersionId")
    if (
        not isinstance(version, str)
        or not version
        or response.get("ServerSideEncryption") != "aws:kms"
        or not hmac.compare_digest(str(response.get("SSEKMSKeyId", "")), key_arn)
    ):
        raise RuntimeError("S3 did not prove exact versioned KMS persistence")
    metadata = response.get("Metadata")
    if metadata is not None and (
        not isinstance(metadata, dict)
        or not hmac.compare_digest(str(metadata.get("sha256", "")), digest)
    ):
        raise RuntimeError("existing S3 release artifact has a different digest")
    return version


def upload_release_artifacts(
    client: S3Client,
    *,
    bucket: str,
    prefix: str,
    kms_key_arn: str,
    root: Path,
) -> bytes:
    if not bucket or not kms_key_arn or prefix.startswith("/") or ".." in prefix.split("/"):
        raise ValueError("release artifact destination is invalid")
    normalized = prefix.rstrip("/")
    if not normalized.startswith("releases/"):
        raise ValueError("release artifacts must use the releases/ prefix")
    manifest: dict[str, dict[str, str]] = {}
    for name in DOCUMENTS:
        value = _validated_document(root / name)
        digest = hashlib.sha256(value).hexdigest()
        checksum = base64.b64encode(hashlib.sha256(value).digest()).decode("ascii")
        key = f"{normalized}/{name}"
        try:
            response = client.put_object(
                Bucket=bucket,
                Key=key,
                Body=value,
                ContentType="application/json",
                CacheControl="public, max-age=31536000, immutable",
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=kms_key_arn,
                BucketKeyEnabled=True,
                ChecksumAlgorithm="SHA256",
                ChecksumSHA256=checksum,
                IfNoneMatch="*",
                Metadata={"sha256": digest, "synthetic": "true"},
            )
        except ClientError as error:
            status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            code = error.response.get("Error", {}).get("Code")
            if status not in {409, 412} and code not in {
                "ConditionalRequestConflict",
                "PreconditionFailed",
            }:
                raise RuntimeError("release artifact upload failed") from error
            try:
                response = client.head_object(Bucket=bucket, Key=key)
            except (BotoCoreError, ClientError) as head_error:
                raise RuntimeError("release artifact retry could not be reconciled") from head_error
        except BotoCoreError as error:
            raise RuntimeError("release artifact upload failed") from error
        manifest[name] = {
            "sha256": digest,
            "version_id": _recorded_version(response, kms_key_arn, digest),
        }
    return canonical_bytes(manifest)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--kms-key-arn", required=True)
    parser.add_argument("--root", type=Path, default=Path("artifacts/release"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()
    manifest = upload_release_artifacts(
        boto3.client("s3", region_name=args.region),
        bucket=args.bucket,
        prefix=args.prefix,
        kms_key_arn=args.kms_key_arn,
        root=args.root,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(manifest)
    print(
        json.dumps(
            {
                "document_count": len(DOCUMENTS),
                "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            }
        )
    )


if __name__ == "__main__":
    main()
