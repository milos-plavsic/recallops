import json
from typing import Any, Protocol

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from recallops.domain import IncidentAnalysis, IncidentCreate
from recallops.resilience import DependencyUnavailable, aws_client_config


class EvidenceArchive(Protocol):
    def archive(self, incident: IncidentCreate, analysis: IncidentAnalysis) -> None: ...


class NullEvidenceArchive:
    def archive(self, incident: IncidentCreate, analysis: IncidentAnalysis) -> None:
        return None


def evidence_payload(
    incident: IncidentCreate, analysis: IncidentAnalysis
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "incident": incident.model_dump(mode="json"),
        "analysis": analysis.model_dump(
            mode="json", exclude={"memories": {"__all__": {"memory": {"embedding"}}}}
        ),
    }


class S3EvidenceArchive:
    def __init__(
        self,
        region: str,
        bucket: str,
        connect_timeout: float = 2.0,
        read_timeout: float = 15.0,
        max_attempts: int = 3,
    ) -> None:
        self._client = boto3.client(
            "s3",
            region_name=region,
            config=aws_client_config(connect_timeout, read_timeout, max_attempts),
        )
        self._bucket = bucket

    def archive(self, incident: IncidentCreate, analysis: IncidentAnalysis) -> None:
        key = f"tenants/{incident.tenant_id}/incidents/{analysis.incident_id}/analysis.json"
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=json.dumps(
                    evidence_payload(incident, analysis), separators=(",", ":")
                ).encode(),
                ContentType="application/json",
                ServerSideEncryption="AES256",
                Metadata={
                    "service": incident.service,
                    "service-version": incident.service_version,
                },
            )
        except (BotoCoreError, ClientError) as error:
            raise DependencyUnavailable("s3_evidence") from error
