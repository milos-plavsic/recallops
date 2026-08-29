#!/usr/bin/env python3
"""Sign one canonical release statement with the repository-pinned AWS KMS key."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path

import boto3

from recallops.receipts import (
    KmsReceiptSigner,
    TrustedKeyRegistry,
    canonical_bytes,
    parse_canonical_json,
    verify_release_statement_jws,
)
from recallops.release_evidence import ReleaseStatement


def load_canonical_statement(path: Path) -> tuple[ReleaseStatement, bytes]:
    raw = path.read_bytes()
    parsed = parse_canonical_json(raw)
    statement = ReleaseStatement.model_validate(parsed)
    expected = canonical_bytes(statement.model_dump(mode="json"))
    if not hmac.compare_digest(raw, expected):
        raise ValueError("release statement payload is not exact canonical JSON")
    return statement, raw


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata-output", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--trusted-keys", type=Path, required=True)
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    statement, payload = load_canonical_statement(args.payload)
    if statement.identity.release_id != args.release_id:
        raise ValueError("release ID differs between payload and signing command")
    registry = TrustedKeyRegistry.load(args.trusted_keys)
    signer = KmsReceiptSigner(
        boto3.client("kms", region_name=args.region),
        args.key_id,
        args.release_id,
        registry,
    )
    kid = signer.preflight()
    compact = signer.sign_release_statement(statement)
    verified = verify_release_statement_jws(compact, registry, release_id=args.release_id)
    if verified != statement:
        raise RuntimeError("locally verified release statement differs from signed payload")

    compact_bytes = (compact + "\n").encode("ascii")
    metadata = canonical_bytes(
        {
            "assurance_complete": statement.assurance_complete,
            "image_digest": statement.identity.image_digest,
            "jws_sha256": hashlib.sha256(compact.encode("ascii")).hexdigest(),
            "key_thumbprint": kid,
            "live_proof_complete": statement.live_proof_complete,
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "release_id": statement.identity.release_id,
            "release_ready": statement.release_ready,
            "source_sha": statement.identity.source_sha,
            "statement_version": statement.statement_version,
        }
    )
    if args.output.exists() or args.metadata_output.exists():
        raise FileExistsError("refusing to overwrite release statement output")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.metadata_output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("xb") as destination:
        destination.write(compact_bytes)
    with args.metadata_output.open("xb") as destination:
        destination.write(metadata)
    print(
        json.dumps(
            {
                "jws_sha256": hashlib.sha256(compact.encode("ascii")).hexdigest(),
                "key_thumbprint": kid,
                "release_ready": statement.release_ready,
                "verified": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
