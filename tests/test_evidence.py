from typing import Any

from recallops.domain import EvidenceVerification
from recallops.evidence import AwsEvidenceVerifier, ManualOnlyEvidenceVerifier


class FakeCloudWatch:
    def describe_alarms(self, **kwargs: Any) -> dict[str, Any]:
        name = kwargs["AlarmNames"][0]
        return {"MetricAlarms": [{"AlarmName": name, "StateValue": "OK"}]}


class FakeS3:
    def __init__(self) -> None:
        self.requests: list[dict[str, str]] = []

    def head_object(self, **kwargs: str) -> dict[str, object]:
        self.requests.append(kwargs)
        return {}


def aws_verifier(monkeypatch: Any) -> tuple[AwsEvidenceVerifier, FakeS3]:
    cloudwatch = FakeCloudWatch()
    s3 = FakeS3()

    def client(service: str, **kwargs: Any) -> object:
        del kwargs
        return cloudwatch if service == "cloudwatch" else s3

    monkeypatch.setattr("recallops.evidence.boto3.client", client)
    return AwsEvidenceVerifier("us-east-1", "evidence-bucket", 1, 2, 1), s3


def test_manual_only_verifier_fails_closed_for_elevated_claims() -> None:
    verifier = ManualOnlyEvidenceVerifier()
    assert verifier.verify(EvidenceVerification.MANUAL_ATTESTATION, [])
    assert not verifier.verify(
        EvidenceVerification.SYSTEM_OBSERVED, ["cloudwatch://alarm/healthy-service"]
    )


def test_aws_verifier_checks_alarm_state_and_scoped_s3_objects(monkeypatch: Any) -> None:
    verifier, s3 = aws_verifier(monkeypatch)
    assert verifier.verify(
        EvidenceVerification.SYSTEM_OBSERVED,
        ["cloudwatch://alarm/payments-postcondition"],
    )
    assert verifier.verify(
        EvidenceVerification.EXTERNALLY_VERIFIED,
        ["s3://evidence-bucket/tenants/demo/evidence.json"],
    )
    assert s3.requests == [{"Bucket": "evidence-bucket", "Key": "tenants/demo/evidence.json"}]


def test_aws_verifier_rejects_untrusted_schemes_and_buckets(monkeypatch: Any) -> None:
    verifier, _ = aws_verifier(monkeypatch)
    assert not verifier.verify(
        EvidenceVerification.SYSTEM_OBSERVED,
        ["https://169.254.169.254/latest/meta-data/iam/security-credentials"],
    )
    assert not verifier.verify(
        EvidenceVerification.EXTERNALLY_VERIFIED,
        ["s3://attacker-bucket/fabricated.json"],
    )
