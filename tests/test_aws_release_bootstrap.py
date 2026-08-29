from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recallops.receipts import ReceiptPreflightError, canonical_bytes


def script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), path)
    assert spec is not None and spec.loader is not None
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


class Kms:
    def __init__(self, *, key_spec: str = "ECC_NIST_EDWARDS25519") -> None:
        public = Ed25519PrivateKey.generate().public_key()
        self.der = public.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_spec = key_spec

    def get_public_key(self, **kwargs: object) -> dict[str, Any]:
        assert kwargs == {"KeyId": "arn:key"}
        return {
            "KeyId": "arn:key",
            "KeySpec": self.key_spec,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ED25519_SHA_512"],
            "PublicKey": self.der,
        }


def test_initial_kms_key_registry_is_canonical_idempotent_and_rotation_safe(
    tmp_path: Path,
) -> None:
    loaded = script("pin-kms-receipt-key.py")
    encoded = loaded.initial_registry(Kms(), "arn:key", "release-v1")
    target = tmp_path / "keys.json"
    target.write_bytes(
        canonical_bytes(
            {
                "keys": [],
                "registry_version": "trusted-receipt-keys-v1",
                "transitions": [],
            }
        )
    )
    loaded.write_initial_registry(target, encoded)
    assert target.read_bytes() == encoded
    loaded.write_initial_registry(target, encoded)

    other = loaded.initial_registry(Kms(), "arn:key", "release-v1")
    with pytest.raises(ReceiptPreflightError, match="signed key transition"):
        loaded.write_initial_registry(target, other)
    with pytest.raises(ReceiptPreflightError, match="frozen Ed25519"):
        loaded.initial_registry(Kms(key_spec="RSA_2048"), "arn:key", "release-v1")


def test_initial_registry_migrates_only_exact_newline_empty_placeholder(
    tmp_path: Path,
) -> None:
    loaded = script("pin-kms-receipt-key.py")
    target = tmp_path / "keys.json"
    target.write_bytes(loaded.EMPTY_REGISTRY + b"\n")
    encoded = loaded.initial_registry(Kms(), "arn:key", "release-v1")
    loaded.write_initial_registry(target, encoded)
    assert target.read_bytes() == encoded

    target.write_bytes(loaded.EMPTY_REGISTRY + b" \n")
    with pytest.raises(ReceiptPreflightError, match="canonical"):
        loaded.write_initial_registry(target, encoded)


class S3:
    def __init__(self, kms: str) -> None:
        self.kms = kms
        self.requests: list[dict[str, Any]] = []
        self.conflict = False
        self.mismatched = False

    def put_object(self, **kwargs: object) -> dict[str, Any]:
        self.requests.append(dict(kwargs))
        if self.conflict:
            raise ClientError(
                {
                    "Error": {"Code": "PreconditionFailed", "Message": "exists"},
                    "ResponseMetadata": {"HTTPStatusCode": 412},
                },
                "PutObject",
            )
        return {
            "VersionId": f"v-{len(self.requests)}",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms,
        }

    def head_object(self, **kwargs: object) -> dict[str, Any]:
        request = next(item for item in self.requests if item["Key"] == kwargs["Key"])
        return {
            "VersionId": "existing-version",
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": self.kms,
            "Metadata": {"sha256": "0" * 64 if self.mismatched else request["Metadata"]["sha256"]},
        }


def release_documents(root: Path) -> None:
    values = {
        "evaluation-case.jcs.json": {"evaluation_version": "v1", "type": "case"},
        "evaluation-result.jcs.json": {"evaluation_version": "v1", "type": "result"},
        "claims.jcs.json": {"claims": []},
    }
    for name, value in values.items():
        (root / name).write_bytes(canonical_bytes(value))


def test_release_artifacts_are_exact_versioned_kms_objects(tmp_path: Path) -> None:
    loaded = script("upload-release-artifacts.py")
    release_documents(tmp_path)
    client = S3("arn:kms")
    manifest = loaded.upload_release_artifacts(
        client,
        bucket="bucket",
        prefix="releases/release-v1/",
        kms_key_arn="arn:kms",
        root=tmp_path,
    )
    assert len(client.requests) == 3
    assert b'"version_id":"v-1"' in manifest
    assert all(item["IfNoneMatch"] == "*" for item in client.requests)
    assert all(item["BucketKeyEnabled"] is True for item in client.requests)


def test_release_artifact_retry_reconciles_only_identical_object(tmp_path: Path) -> None:
    loaded = script("upload-release-artifacts.py")
    release_documents(tmp_path)
    client = S3("arn:kms")
    client.conflict = True
    manifest = loaded.upload_release_artifacts(
        client,
        bucket="bucket",
        prefix="releases/release-v1",
        kms_key_arn="arn:kms",
        root=tmp_path,
    )
    assert b'"version_id":"existing-version"' in manifest

    client.mismatched = True
    with pytest.raises(RuntimeError, match="different digest"):
        loaded.upload_release_artifacts(
            client,
            bucket="bucket",
            prefix="releases/release-v1",
            kms_key_arn="arn:kms",
            root=tmp_path,
        )


@pytest.mark.parametrize("prefix", ["/releases/x", "releases/a/../b", "other/release"])
def test_release_artifact_destination_is_bounded(tmp_path: Path, prefix: str) -> None:
    loaded = script("upload-release-artifacts.py")
    with pytest.raises(ValueError, match="release artifact"):
        loaded.upload_release_artifacts(
            S3("arn:kms"),
            bucket="bucket",
            prefix=prefix,
            kms_key_arn="arn:kms",
            root=tmp_path,
        )
