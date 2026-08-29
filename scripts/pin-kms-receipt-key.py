#!/usr/bin/env python3
"""Pin the initial live AWS KMS Ed25519 receipt key into the repository registry."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Protocol

import boto3

from recallops.canonical import canonical_bytes
from recallops.receipts import (
    AWS_SIGNING_ALGORITHM,
    KmsReceiptSigner,
    ReceiptPreflightError,
    ReceiptVerificationError,
    TrustedKey,
    TrustedKeyDocument,
    TrustedKeyRegistry,
    jwk_thumbprint,
    public_jwk_from_der,
)

EMPTY_REGISTRY = canonical_bytes(
    {
        "keys": [],
        "registry_version": "trusted-receipt-keys-v1",
        "transitions": [],
    }
)


class KmsClient(Protocol):
    def get_public_key(self, **kwargs: object) -> dict[str, Any]: ...
    def sign(self, **kwargs: object) -> dict[str, Any]: ...


def initial_registry(client: KmsClient, key_id: str, release_id: str) -> bytes:
    response = client.get_public_key(KeyId=key_id)
    public_key = response.get("PublicKey")
    if (
        response.get("KeySpec") != "ECC_NIST_EDWARDS25519"
        or response.get("KeyUsage") != "SIGN_VERIFY"
        or AWS_SIGNING_ALGORITHM not in response.get("SigningAlgorithms", [])
        or not isinstance(public_key, bytes)
    ):
        raise ReceiptPreflightError("KMS key does not match the frozen Ed25519 profile")
    jwk = public_jwk_from_der(public_key)
    kid = jwk_thumbprint(jwk)
    registry = TrustedKeyRegistry(
        TrustedKeyDocument(
            registry_version="trusted-receipt-keys-v1",
            keys=(
                TrustedKey(
                    kid=kid,
                    jwk=jwk,
                    trust="repository_root",
                    status="active",
                    release_ids=(release_id,),
                ),
            ),
            transitions=(),
        )
    )
    verified_kid = KmsReceiptSigner(client, key_id, release_id, registry).preflight()
    if verified_kid != kid:
        raise ReceiptPreflightError("KMS key changed during repository pinning")
    return canonical_bytes(registry.document.model_dump(mode="json"))


def write_initial_registry(path: Path, value: bytes) -> None:
    if path.exists():
        current = path.read_bytes()
        if current == EMPTY_REGISTRY + b"\n":
            current = EMPTY_REGISTRY
        try:
            current_registry = TrustedKeyRegistry.from_bytes(current)
        except ReceiptVerificationError as error:
            raise ReceiptPreflightError("existing trusted registry is not canonical") from error
        if current_registry.document.keys and current != value:
            raise ReceiptPreflightError(
                "trusted registry already has a root; rotation requires a signed key transition"
            )
        if current == value:
            return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--output", type=Path, default=Path("tools/trusted-receipt-keys.json"))
    args = parser.parse_args()
    client = boto3.client("kms", region_name=args.region)
    encoded = initial_registry(client, args.key_id, args.release_id)
    write_initial_registry(args.output, encoded)
    registry = TrustedKeyRegistry.from_bytes(encoded)
    print(f"pinned receipt key kid={registry.document.keys[0].kid} release={args.release_id}")


if __name__ == "__main__":
    main()
