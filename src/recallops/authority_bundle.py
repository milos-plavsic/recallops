"""Deterministic, independently verifiable authority-bundle construction.

The digest graph is deliberately one-way::

    auxiliary evidence -> evidence index -> manifest -> JWS -> checksums -> bundle digest

The bundle digest is stored outside the bundle.  No private signing material and no
network client exists in this module.
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, model_validator

from recallops.canonical import canonical_bytes
from recallops.ledger import AuthorityEvent, canonical_event_payload
from recallops.receipts import (
    ReceiptManifest,
    ReceiptVerificationError,
    TrustedKeyRegistry,
    jwk_thumbprint,
    parse_canonical_json,
    verify_causal_bindings,
    verify_receipt_jws,
)

BUNDLE_DIGEST_DOMAIN: Final = b"recallops-authority-bundle-v1\x00"
BUNDLE_FORMAT_VERSION: Final = "authority-bundle-v1"
MAX_BUNDLE_BYTES: Final = 8 * 1024 * 1024
MAX_FILE_BYTES: Final = 2 * 1024 * 1024
HEX_DIGEST = r"^[a-f0-9]{64}$"

AUXILIARY_PATHS: Final = (
    "public.jwk.json",
    "events.ndjson",
    "policy/capability-policy.json",
    "policy/receipt-policy.json",
    "evaluation/case.json",
    "evaluation/result.json",
    "release.json",
    "claims.json",
)
SIGNED_PATHS: Final = (
    "evidence-index.jcs.json",
    "manifest.jcs.json",
    "receipt.jws",
)
DOCUMENTATION_PATHS: Final = ("README.md",)
CHECKSUM_PATH: Final = "checksums.sha256"
ALLOWED_PATHS: Final = frozenset(
    (*AUXILIARY_PATHS, *SIGNED_PATHS, *DOCUMENTATION_PATHS, CHECKSUM_PATH)
)


class BundleError(ValueError):
    """A bundle cannot be constructed without weakening a frozen binding."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceIndexEntry(_StrictModel):
    path: str
    sha256: str = Field(pattern=HEX_DIGEST)
    size: int = Field(ge=1, le=MAX_FILE_BYTES)

    @model_validator(mode="after")
    def validate_path(self) -> EvidenceIndexEntry:
        if self.path not in AUXILIARY_PATHS:
            raise ValueError("evidence index path is not allowlisted")
        return self


class EvidenceIndex(_StrictModel):
    index_version: str = BUNDLE_FORMAT_VERSION
    entries: tuple[EvidenceIndexEntry, ...] = Field(min_length=len(AUXILIARY_PATHS))

    @model_validator(mode="after")
    def validate_entries(self) -> EvidenceIndex:
        paths = tuple(item.path for item in self.entries)
        if paths != AUXILIARY_PATHS:
            raise ValueError("evidence index must contain every auxiliary path in frozen order")
        return self


class FrozenRelease(_StrictModel):
    release_id: str = Field(min_length=3, max_length=100)
    source_sha: str = Field(pattern=r"^[a-f0-9]{40}([a-f0-9]{24})?$")
    image_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    capability_policy_version: str = Field(min_length=3, max_length=80)
    receipt_policy_version: str = Field(min_length=3, max_length=80)
    evaluation_version: str = Field(min_length=3, max_length=80)
    claim_registry_digest: str = Field(pattern=HEX_DIGEST)
    receipt_key_thumbprint: str = Field(min_length=43, max_length=43)


@dataclass(frozen=True)
class AuthorityBundle:
    files: Mapping[str, bytes]
    evidence_index_digest: str
    checksums_digest: str
    bundle_digest: str

    def deterministic_zip(self) -> bytes:
        output = io.BytesIO()
        with zipfile.ZipFile(
            output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
        ) as archive:
            for path in sorted(self.files):
                info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.flag_bits = 0x800
                archive.writestr(info, self.files[path])
        value = output.getvalue()
        if len(value) > MAX_BUNDLE_BYTES:
            raise BundleError("deterministic authority archive exceeds size limit")
        return value


@dataclass(frozen=True)
class PreparedEvidence:
    files: Mapping[str, bytes]
    index: EvidenceIndex
    index_bytes: bytes
    index_digest: str


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def bundle_digest(checksum_bytes: bytes) -> str:
    return hashlib.sha256(BUNDLE_DIGEST_DOMAIN + checksum_bytes).hexdigest()


def canonical_event_lines(events: Sequence[AuthorityEvent]) -> bytes:
    if not events:
        raise BundleError("authority bundle requires an event prefix")
    lines = [
        canonical_bytes({**canonical_event_payload(event), "event_hash": event.event_hash})
        for event in events
    ]
    if any(b"\n" in line or b"\r" in line for line in lines):
        raise BundleError("canonical authority event contains a line separator")
    return b"\n".join(lines) + b"\n"


def _safe_file(path: str, value: bytes) -> bytes:
    pure = PurePosixPath(path)
    if path not in ALLOWED_PATHS or pure.is_absolute() or ".." in pure.parts:
        raise BundleError(f"bundle path is not allowlisted: {path}")
    if not value or len(value) > MAX_FILE_BYTES:
        raise BundleError(f"bundle file has invalid size: {path}")
    return value


def _canonical_document(path: str, value: object) -> bytes:
    encoded = canonical_bytes(value)
    _safe_file(path, encoded)
    return encoded


def _checksum_file(files: Mapping[str, bytes]) -> bytes:
    paths = sorted(files)
    if CHECKSUM_PATH in paths:
        raise BundleError("checksum file cannot cover itself")
    return "".join(f"{sha256_bytes(files[path])}  {path}\n" for path in paths).encode("ascii")


def _validate_receipt_and_release(
    manifest: ReceiptManifest,
    receipt_jws: str,
    public_jwk: Mapping[str, object],
    release: FrozenRelease,
    trusted_keys: TrustedKeyRegistry,
) -> None:
    if jwk_thumbprint(public_jwk) != manifest.key_thumbprint:
        raise BundleError("bundle public key does not match receipt thumbprint")
    verified = verify_receipt_jws(
        receipt_jws, trusted_keys, release_id=release.release_id
    )
    if verified != manifest:
        raise BundleError("receipt JWS payload differs from supplied manifest")
    expected = {
        "release_id": manifest.release.release_id,
        "source_sha": manifest.release.source_sha,
        "image_digest": manifest.release.image_digest,
        "capability_policy_version": manifest.capability_policy_version,
        "receipt_policy_version": manifest.receipt_policy_version,
        "evaluation_version": manifest.release.evaluation_version,
        "claim_registry_digest": manifest.release.claim_registry_digest,
        "receipt_key_thumbprint": manifest.key_thumbprint,
    }
    if release.model_dump(mode="json") != expected:
        raise BundleError("frozen release identity differs from signed receipt")


def prepare_evidence(
    *,
    public_jwk: Mapping[str, object],
    events: Sequence[AuthorityEvent],
    capability_policy: object,
    receipt_policy: object,
    evaluation_case: object,
    evaluation_result: object,
    release: FrozenRelease,
    claims: object,
) -> PreparedEvidence:
    """Canonicalize the unsigned evidence so its index can be bound before signing."""
    files: dict[str, bytes] = {
        "public.jwk.json": _canonical_document("public.jwk.json", dict(public_jwk)),
        "events.ndjson": _safe_file("events.ndjson", canonical_event_lines(events)),
        "policy/capability-policy.json": _canonical_document(
            "policy/capability-policy.json", capability_policy
        ),
        "policy/receipt-policy.json": _canonical_document(
            "policy/receipt-policy.json", receipt_policy
        ),
        "evaluation/case.json": _canonical_document("evaluation/case.json", evaluation_case),
        "evaluation/result.json": _canonical_document(
            "evaluation/result.json", evaluation_result
        ),
        "release.json": _canonical_document("release.json", release.model_dump(mode="json")),
        "claims.json": _canonical_document("claims.json", claims),
    }
    if sha256_bytes(files["claims.json"]) != release.claim_registry_digest:
        raise BundleError("claim registry digest differs from frozen release identity")
    index = EvidenceIndex(
        entries=tuple(
            EvidenceIndexEntry(path=path, sha256=sha256_bytes(files[path]), size=len(files[path]))
            for path in AUXILIARY_PATHS
        )
    )
    index_bytes = canonical_bytes(index.model_dump(mode="json"))
    return PreparedEvidence(
        files=MappingProxyType(files),
        index=index,
        index_bytes=index_bytes,
        index_digest=sha256_bytes(index_bytes),
    )


def build_authority_bundle(
    *,
    manifest: ReceiptManifest,
    receipt_jws: str,
    public_jwk: Mapping[str, object],
    events: Sequence[AuthorityEvent],
    capability_policy: object,
    receipt_policy: object,
    evaluation_case: object,
    evaluation_result: object,
    release: FrozenRelease,
    claims: object,
    trusted_keys: TrustedKeyRegistry,
    readme: bytes,
) -> AuthorityBundle:
    """Build a byte-stable bundle after verifying every pre-existing trust binding."""
    if not readme.startswith(b"# RecallOps authority bundle\n"):
        raise BundleError("bundle README must begin with the frozen explanatory heading")
    verify_causal_bindings(events, manifest.digests, manifest.final_disposition)
    prepared = prepare_evidence(
        public_jwk=public_jwk,
        events=events,
        capability_policy=capability_policy,
        receipt_policy=receipt_policy,
        evaluation_case=evaluation_case,
        evaluation_result=evaluation_result,
        release=release,
        claims=claims,
    )
    files = dict(prepared.files)
    if prepared.index_digest != manifest.evidence_index_digest:
        raise BundleError("evidence index digest differs from signed receipt binding")
    _validate_receipt_and_release(manifest, receipt_jws, public_jwk, release, trusted_keys)
    files.update(
        {
            "evidence-index.jcs.json": prepared.index_bytes,
            "manifest.jcs.json": manifest.canonical(),
            "receipt.jws": _safe_file("receipt.jws", receipt_jws.encode("ascii")),
            "README.md": _safe_file("README.md", readme),
        }
    )
    checksum_bytes = _checksum_file(files)
    files[CHECKSUM_PATH] = _safe_file(CHECKSUM_PATH, checksum_bytes)
    if set(files) != ALLOWED_PATHS:
        raise BundleError("bundle file set differs from frozen layout")
    frozen_files = MappingProxyType(dict(sorted(files.items())))
    return AuthorityBundle(
        files=frozen_files,
        evidence_index_digest=prepared.index_digest,
        checksums_digest=sha256_bytes(checksum_bytes),
        bundle_digest=bundle_digest(checksum_bytes),
    )


def parse_checksums(value: bytes) -> dict[str, str]:
    """Strict parser shared by public-download validation and tests."""
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise BundleError("checksum file is not ASCII") from error
    result: dict[str, str] = {}
    for line in text.splitlines(keepends=True):
        match = re.fullmatch(r"([a-f0-9]{64})  ([A-Za-z0-9._/-]+)\n", line)
        if match is None:
            raise BundleError("checksum file has invalid syntax")
        digest, path = match.groups()
        if path in result or path == CHECKSUM_PATH or path not in ALLOWED_PATHS:
            raise BundleError("checksum file has duplicate or forbidden path")
        result[path] = digest
    expected = sorted(ALLOWED_PATHS - {CHECKSUM_PATH})
    if list(result) != expected:
        raise BundleError("checksum file path set or ordering is invalid")
    return result


def validate_bundle_files(files: Mapping[str, bytes]) -> str:
    """Validate the outer deterministic envelope and return its bundle digest."""
    if set(files) != ALLOWED_PATHS:
        raise BundleError("bundle file set differs from frozen layout")
    for path, value in files.items():
        _safe_file(path, value)
    checksums = parse_checksums(files[CHECKSUM_PATH])
    for path, expected in checksums.items():
        if sha256_bytes(files[path]) != expected:
            raise BundleError(f"checksum mismatch: {path}")
    try:
        parsed = parse_canonical_json(files["evidence-index.jcs.json"])
        EvidenceIndex.model_validate(parsed)
    except (ReceiptVerificationError, ValueError) as error:
        raise BundleError("evidence index is not strict canonical evidence") from error
    return bundle_digest(files[CHECKSUM_PATH])


def read_bundle_zip(value: bytes) -> Mapping[str, bytes]:
    """Extract only the exact frozen bundle layout; reject archive parser tricks."""
    if not value or len(value) > MAX_BUNDLE_BYTES:
        raise BundleError("authority archive has invalid size")
    result: dict[str, bytes] = {}
    try:
        with zipfile.ZipFile(io.BytesIO(value), "r") as archive:
            members = archive.infolist()
            if len(members) != len(ALLOWED_PATHS):
                raise BundleError("archive member count differs from frozen layout")
            for member in members:
                path = member.filename
                if member.is_dir() or path in result or path not in ALLOWED_PATHS:
                    raise BundleError("archive contains duplicate or forbidden member")
                if member.file_size < 1 or member.file_size > MAX_FILE_BYTES:
                    raise BundleError("archive member has invalid size")
                if member.compress_size > MAX_FILE_BYTES:
                    raise BundleError("archive compressed member has invalid size")
                mode = member.external_attr >> 16
                if mode and mode & 0o170000 != 0o100000:
                    raise BundleError("archive contains a non-regular member")
                result[path] = archive.read(member)
    except (zipfile.BadZipFile, RuntimeError, OSError) as error:
        raise BundleError("authority archive is not a valid ZIP") from error
    validate_bundle_files(result)
    return MappingProxyType(result)
