"""Credential-free serving boundary for already-finalized synthetic receipts."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

import boto3
import psycopg
from botocore.exceptions import BotoCoreError, ClientError
from psycopg.rows import dict_row

from recallops.authority_bundle import BundleError, read_bundle_zip, validate_bundle_files
from recallops.resilience import DependencyUnavailable, aws_client_config


@dataclass(frozen=True)
class FinalizedPublicReceipt:
    receipt_id: UUID
    bundle_digest: str
    object_key: str
    version_id: str
    source_sha: str
    image_digest: str


class PublicReceiptRepository(Protocol):
    def finalized_public(self, receipt_id: UUID) -> FinalizedPublicReceipt | None: ...


class PostgresPublicReceiptRepository:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def finalized_public(self, receipt_id: UUID) -> FinalizedPublicReceipt | None:
        with psycopg.connect(
            self._database_url, row_factory=dict_row, autocommit=True
        ) as connection:
            row = connection.execute(
                """SELECT receipt_id,bundle_digest,bundle_object_key,s3_version_id,
                source_sha,image_digest FROM authority_receipts
                WHERE receipt_id=%s AND status='signed' AND synthetic
                  AND public_at IS NOT NULL AND bundle_digest IS NOT NULL
                  AND bundle_object_key IS NOT NULL AND s3_version_id IS NOT NULL""",
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        return FinalizedPublicReceipt(
            receipt_id=row["receipt_id"],
            bundle_digest=row["bundle_digest"],
            object_key=row["bundle_object_key"],
            version_id=row["s3_version_id"],
            source_sha=row["source_sha"],
            image_digest=row["image_digest"],
        )


class BundleObjectClient(Protocol):
    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...


class PublicBundleService:
    def __init__(
        self,
        repository: PublicReceiptRepository,
        client: BundleObjectClient,
        bucket: str,
    ) -> None:
        self._repository = repository
        self._client = client
        self._bucket = bucket

    @classmethod
    def aws(
        cls, database_url: str, region: str, bucket: str
    ) -> PublicBundleService:
        client = boto3.client(
            "s3",
            region_name=region,
            config=aws_client_config(2.0, 15.0, 3),
        )
        return cls(PostgresPublicReceiptRepository(database_url), client, bucket)

    def download(self, receipt_id: UUID) -> tuple[bytes, FinalizedPublicReceipt] | None:
        record = self._repository.finalized_public(receipt_id)
        if record is None:
            return None
        try:
            response = self._client.get_object(
                Bucket=self._bucket,
                Key=record.object_key,
                VersionId=record.version_id,
            )
            body = response.get("Body")
            archive = body.read(8 * 1024 * 1024 + 1) if hasattr(body, "read") else body
        except (BotoCoreError, ClientError, OSError) as error:
            raise DependencyUnavailable("s3_authority_bundle") from error
        if not isinstance(archive, bytes):
            raise DependencyUnavailable("s3_authority_bundle")
        try:
            files = read_bundle_zip(archive)
            digest = validate_bundle_files(files)
        except BundleError as error:
            raise DependencyUnavailable("s3_authority_bundle_integrity") from error
        if not hmac.compare_digest(digest, record.bundle_digest):
            raise DependencyUnavailable("s3_authority_bundle_integrity")
        return archive, record
