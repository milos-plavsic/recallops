from typing import Protocol
from urllib.parse import unquote, urlsplit

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from recallops.domain import EvidenceVerification
from recallops.resilience import DependencyUnavailable, aws_client_config


class EvidenceVerifier(Protocol):
    def verify(self, verification: EvidenceVerification, references: list[str]) -> bool: ...


class ManualOnlyEvidenceVerifier:
    """Local-safe verifier: manual attestations work, elevated claims fail closed."""

    def verify(self, verification: EvidenceVerification, references: list[str]) -> bool:
        del references
        return verification is EvidenceVerification.MANUAL_ATTESTATION


class AwsEvidenceVerifier:
    """Verify evidence using read-only AWS APIs and narrowly defined URI contracts.

    Supported references are ``cloudwatch://alarm/<name>`` for alarms currently in
    OK state and ``s3://<bucket>/<key>`` for evidence objects that exist. HTTP URLs
    are deliberately rejected to avoid turning evidence validation into an SSRF
    primitive.
    """

    def __init__(
        self,
        region: str,
        evidence_bucket: str | None,
        connect_timeout: float,
        read_timeout: float,
        max_attempts: int,
    ) -> None:
        config = aws_client_config(connect_timeout, read_timeout, max_attempts)
        self._cloudwatch = boto3.client("cloudwatch", region_name=region, config=config)
        self._s3 = boto3.client("s3", region_name=region, config=config)
        self._evidence_bucket = evidence_bucket

    def verify(self, verification: EvidenceVerification, references: list[str]) -> bool:
        if verification is EvidenceVerification.MANUAL_ATTESTATION:
            return True
        if not references:
            return False
        try:
            return all(self._verify_reference(reference) for reference in references)
        except (BotoCoreError, ClientError) as error:
            raise DependencyUnavailable("aws_evidence_verification") from error

    def _verify_reference(self, reference: str) -> bool:
        parsed = urlsplit(reference)
        if parsed.scheme == "cloudwatch" and parsed.netloc == "alarm":
            alarm_name = unquote(parsed.path.lstrip("/"))
            if not alarm_name or "/" in alarm_name:
                return False
            response = self._cloudwatch.describe_alarms(AlarmNames=[alarm_name])
            alarms = response.get("MetricAlarms", []) + response.get("CompositeAlarms", [])
            return len(alarms) == 1 and alarms[0].get("StateValue") == "OK"
        if parsed.scheme == "s3" and parsed.netloc == self._evidence_bucket:
            key = unquote(parsed.path.lstrip("/"))
            if not key:
                return False
            self._s3.head_object(Bucket=parsed.netloc, Key=key)
            return True
        return False
