#!/usr/bin/env python3
"""Generate fixed non-production authority-bundle verifier vectors.

The deterministic private key lives only in the test fixture. Production receipt code has no
local signer and this generator must never be used as a runtime fallback.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recallops.authority_bundle import BUNDLE_DIGEST_DOMAIN, sha256_bytes
from recallops.canonical import canonical_bytes
from recallops.ledger import AuthorityEvent
from recallops.receipts import public_jwk_from_der
from recallops.workflow import RequestChannel

REPOSITORY = Path(__file__).resolve().parents[1]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from tests.test_authority_bundle import (  # noqa: E402 - repository test fixture path
    make_bundle,
    public_der,
    rechain,
    rewrite_checksums,
)

DEFAULT_OUTPUT = REPOSITORY / "artifacts" / "authority-vectors"


def write_bundle(root: Path, files: dict[str, bytes] | object) -> None:
    for path, content in dict(files).items():  # type: ignore[arg-type]
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)


def digest_after_checksums(files: dict[str, bytes]) -> str:
    return sha256_bytes(BUNDLE_DIGEST_DOMAIN + files["checksums.sha256"])


def mutate_signature(files: dict[str, bytes]) -> None:
    protected, payload, signature = files["receipt.jws"].decode().split(".")
    signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    files["receipt.jws"] = f"{protected}.{payload}.{signature}".encode()
    rewrite_checksums(files)


def semantic_bundle(vector: str):
    def mutate_events(events: list[AuthorityEvent]) -> list[AuthorityEvent]:
        if vector == "role_authority":
            events[0] = events[0].model_copy(
                update={
                    "actor_role": "agent",
                    "actor_subject": "agent-42",
                    "channel": RequestChannel.WEBMCP,
                }
            )
        elif vector == "capability_policy":
            capabilities = ("inspect_incident", "protected_override")
            events[0] = events[0].model_copy(update={"capabilities_after": capabilities})
            events[1] = events[1].model_copy(update={"capabilities_before": capabilities})
        return rechain(events)

    def mutate_policy(policy: dict[str, object]) -> None:
        capabilities = policy["capabilities"]
        assert isinstance(capabilities, dict)
        capabilities["INVESTIGATING"] = ["inspect_incident", "protected_override"]

    return make_bundle(
        disposition="activate" if vector == "disposition" else "certify",
        mutate_events=mutate_events
        if vector in {"role_authority", "capability_policy"}
        else None,
        mutate_capability_policy=mutate_policy if vector == "policy_content" else None,
    )[0]


def generate(output: Path) -> None:
    resolved = output.resolve()
    if resolved == Path("/") or resolved == REPOSITORY or REPOSITORY not in resolved.parents:
        raise SystemExit("refusing unsafe authority-vector output path")
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)
    valid, trusted = make_bundle()
    registry = canonical_bytes(trusted.document.model_dump(mode="json"))
    (resolved / "trusted-keys.jcs.json").write_bytes(registry)
    write_bundle(resolved / "valid" / "authority-bundle", valid.files)
    expected: dict[str, dict[str, object]] = {
        "valid": {"code": "VERIFIED", "bundle_digest": valid.bundle_digest}
    }

    base_mutations = {
        "content_replacement": "E_CHECKSUM_MISMATCH",
        "file_deletion": "E_FILE_SET",
        "signature_corruption": "E_SIGNATURE",
        "key_substitution": "E_KEY_BINDING",
        "event_reordering": "E_EVIDENCE_DIGEST",
        "event_deletion": "E_EVIDENCE_DIGEST",
        "event_duplication": "E_EVIDENCE_DIGEST",
        "causal_binding_change": "E_EVIDENCE_DIGEST",
        "build_change": "E_EVIDENCE_DIGEST",
        "duplicate_json_key": "E_JSON_DUPLICATE",
    }
    for name, code in base_mutations.items():
        files = dict(valid.files)
        digest = valid.bundle_digest
        if name == "content_replacement":
            files["claims.json"] = files["claims.json"].replace(
                b"verified-synthetic", b"tampered-synthetic"
            )
        elif name == "file_deletion":
            files.pop("claims.json")
        elif name == "signature_corruption":
            mutate_signature(files)
            digest = digest_after_checksums(files)
        elif name == "key_substitution":
            files["public.jwk.json"] = canonical_bytes(
                public_jwk_from_der(
                    public_der(Ed25519PrivateKey.from_private_bytes(b"z" * 32))
                )
            )
            rewrite_checksums(files)
            digest = digest_after_checksums(files)
        elif name == "duplicate_json_key":
            files["manifest.jcs.json"] = b'{"x":1,"x":2}'
            rewrite_checksums(files)
            digest = digest_after_checksums(files)
        else:
            lines = files["events.ndjson"].splitlines()
            if name == "event_reordering":
                lines[2], lines[3] = lines[3], lines[2]
            elif name == "event_deletion":
                del lines[3]
            elif name == "event_duplication":
                lines.insert(3, lines[3])
            else:
                event = json.loads(lines[-1 if name == "causal_binding_change" else 0])
                if name == "causal_binding_change":
                    event["object_digest"] = "f" * 64
                    lines[-1] = canonical_bytes(event)
                else:
                    event["build_sha"] = "f" * 40
                    lines[0] = canonical_bytes(event)
            files["events.ndjson"] = b"\n".join(lines) + b"\n"
            rewrite_checksums(files)
            digest = digest_after_checksums(files)
        write_bundle(resolved / "tampered" / name / "authority-bundle", files)
        expected[name] = {"code": code, "bundle_digest": digest}

    semantic = {
        "role_authority": "E_ACTOR_AUTHORITY",
        "capability_policy": "E_CAPABILITY_POLICY",
        "policy_content": "E_POLICY_BINDING",
        "disposition": "E_DISPOSITION",
    }
    for name, code in semantic.items():
        bundle = semantic_bundle(name)
        write_bundle(resolved / "tampered" / name / "authority-bundle", bundle.files)
        expected[name] = {"code": code, "bundle_digest": bundle.bundle_digest}

    (resolved / "expected-results.jcs.json").write_bytes(
        canonical_bytes({"schema_version": "authority-vectors-v1", "vectors": expected})
    )
    (resolved / "README.md").write_text(
        """# Fixed authority verifier vectors

These bundles are synthetic, deterministic, and signed only by the published test key. The key is
not a production trust root. Regenerate with `uv run python scripts/generate-authority-vectors.py`
and verify with `uv run python scripts/verify-authority-vectors.py`. The valid case must pass; every
tampered case must fail with the exact code in `expected-results.jcs.json`.
""",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    generate(args.output)
    subprocess.run(
        ["uv", "run", "python", "scripts/verify-authority-vectors.py", "--root", str(args.output)],
        cwd=REPOSITORY,
        check=True,
    )


if __name__ == "__main__":
    main()
