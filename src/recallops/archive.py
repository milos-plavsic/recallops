from typing import Protocol

import boto3

from recallops.domain import IncidentAnalysis, IncidentCreate


class EvidenceArchive(Protocol):
    def archive(self, incident: IncidentCreate, analysis: IncidentAnalysis) -> None: ...


class NullEvidenceArchive:
    def archive(self, incident: IncidentCreate, analysis: IncidentAnalysis) -> None:
        return None


class S3EvidenceArchive:
    def __init__(self, region: str, bucket: str) -> None:
        self._client = boto3.client("s3", region_name=region)
        self._bucket = bucket

    def archive(self, incident: IncidentCreate, analysis: IncidentAnalysis) -> None:
        key = f"tenants/{incident.tenant_id}/incidents/{analysis.incident_id}/analysis.json"
        self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=analysis.model_dump_json().encode(),
            ContentType="application/json",
            ServerSideEncryption="AES256",
            Metadata={"service": incident.service, "service-version": incident.service_version},
        )
