"""Private, versioned S3 persistence for finalized authority bundles."""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from botocore.exceptions import BotoCoreError, ClientError

from recallops.resilience import DependencyUnavailable


class S3BundleClient(Protocol):
    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...
    def head_object(self, **kwargs: object) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class ArchivedBundle:
    bucket: str
    object_key: str
    version_id: str
    bundle_digest: str


class S3AuthorityBundleArchive:
    """Write-once adapter; bucket versioning and a dedicated KMS key are mandatory."""

    def __init__(self, client: S3BundleClient, bucket: str, kms_key_id: str) -> None:
        if not bucket or not kms_key_id:
            raise ValueError("authority bundle bucket and KMS key are required")
        self._client = client
        self._bucket = bucket
        self._kms_key_id = kms_key_id

    @staticmethod
    def object_key(receipt_id: UUID) -> str:
        return f"synthetic-authority-bundles/{receipt_id}/authority-bundle.zip"

    def persist(self, receipt_id: UUID, archive: bytes, bundle_digest: str) -> ArchivedBundle:
        if not archive or len(archive) > 8 * 1024 * 1024:
            raise ValueError("authority bundle archive has invalid size")
        if len(bundle_digest) != 64 or bundle_digest.lower() != bundle_digest:
            raise ValueError("authority bundle digest is invalid")
        key = self.object_key(receipt_id)
        checksum = base64.b64encode(hashlib.sha256(archive).digest()).decode("ascii")
        try:
            response = self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=archive,
                ContentType="application/zip",
                ContentDisposition=f'attachment; filename="recallops-authority-{receipt_id}.zip"',
                CacheControl="public, max-age=31536000, immutable",
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=self._kms_key_id,
                BucketKeyEnabled=True,
                ChecksumAlgorithm="SHA256",
                ChecksumSHA256=checksum,
                IfNoneMatch="*",
                Metadata={
                    "bundle-digest": bundle_digest,
                    "receipt-id": str(receipt_id),
                    "synthetic": "true",
                },
            )
        except ClientError as error:
            status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            code = error.response.get("Error", {}).get("Code")
            if status not in {409, 412} and code not in {
                "ConditionalRequestConflict",
                "PreconditionFailed",
            }:
                raise DependencyUnavailable("s3_authority_bundle") from error
            return self._resolve_existing(key, receipt_id, bundle_digest)
        except BotoCoreError as error:
            raise DependencyUnavailable("s3_authority_bundle") from error
        return self._validated_result(response, key, receipt_id, bundle_digest)

    def _resolve_existing(
        self, key: str, receipt_id: UUID, bundle_digest: str
    ) -> ArchivedBundle:
        try:
            response = self._client.head_object(Bucket=self._bucket, Key=key)
        except (BotoCoreError, ClientError) as error:
            raise DependencyUnavailable("s3_authority_bundle") from error
        metadata = response.get("Metadata")
        if not isinstance(metadata, Mapping) or not hmac.compare_digest(
            str(metadata.get("bundle-digest", "")), bundle_digest
        ):
            raise DependencyUnavailable("s3_authority_bundle_conflict")
        return self._validated_result(response, key, receipt_id, bundle_digest)

    def _validated_result(
        self,
        response: Mapping[str, object],
        key: str,
        receipt_id: UUID,
        bundle_digest: str,
    ) -> ArchivedBundle:
        version = response.get("VersionId")
        encryption = response.get("ServerSideEncryption")
        if not isinstance(version, str) or not version:
            raise DependencyUnavailable("s3_bucket_versioning")
        if encryption != "aws:kms":
            raise DependencyUnavailable("s3_authority_bundle_encryption")
        return ArchivedBundle(
            bucket=self._bucket,
            object_key=key,
            version_id=version,
            bundle_digest=bundle_digest,
        )
