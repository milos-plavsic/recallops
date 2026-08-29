"""Canonical, pinned-key authority receipt primitives.

This module deliberately contains verification and the AWS KMS adapter, but no
local/private-key signer. Tests emulate KMS at its API boundary; production has
no algorithm or key fallback.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol, cast
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from recallops.canonical import canonical_bytes, content_digest
from recallops.ledger import ZERO_EVENT_HASH, AuthorityEvent, verify_event
from recallops.workflow import RequestChannel

JOSE_ALGORITHM = "Ed25519"
AWS_KEY_SPEC = "ECC_NIST_EDWARDS25519"
AWS_KEY_USAGE = "SIGN_VERIFY"
AWS_SIGNING_ALGORITHM = "ED25519_SHA_512"
AWS_MESSAGE_TYPE = "RAW"
RECEIPT_TYP = "recallops-authority-receipt+jws"
TRANSITION_TYP = "recallops-receipt-key-transition+jws"
RECEIPT_VERSION = "authority-receipt-v1"
RECEIPT_MANIFEST_MAX_BYTES = 2048
KMS_RAW_MESSAGE_MAX_BYTES = 4096
HEX_DIGEST = r"^[a-f0-9]{64}$"
SOURCE_SHA = r"^[a-f0-9]{40}([a-f0-9]{24})?$"
IMAGE_DIGEST = r"^sha256:[a-f0-9]{64}$"
UTC_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")


class ReceiptError(ValueError):
    """Base class for bounded receipt failures."""


class ReceiptVerificationError(ReceiptError):
    """Canonical bytes, ledger, trust, or signature verification failed."""


class ReceiptPreflightError(ReceiptError):
    """The configured KMS key cannot satisfy the frozen receipt profile."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _require_utc_string(value: str) -> str:
    if not UTC_TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be an RFC 3339 UTC string ending in Z")
    datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    return value


class ReceiptDigestBindings(_StrictModel):
    proposal: str = Field(pattern=HEX_DIGEST)
    execution: str = Field(pattern=HEX_DIGEST)
    observation: str = Field(pattern=HEX_DIGEST)
    assessment: str = Field(pattern=HEX_DIGEST)
    policy_verdict: str = Field(pattern=HEX_DIGEST)
    memory: str = Field(pattern=HEX_DIGEST)
    review: str = Field(pattern=HEX_DIGEST)


class ReceiptSubjects(_StrictModel):
    operator: str = Field(pattern=HEX_DIGEST)
    reviewer: str = Field(pattern=HEX_DIGEST)
    separated: bool


class ReleaseBinding(_StrictModel):
    release_id: str = Field(min_length=3, max_length=100)
    source_sha: str = Field(pattern=SOURCE_SHA)
    image_digest: str = Field(pattern=IMAGE_DIGEST)
    evaluation_version: str = Field(min_length=3, max_length=80)
    claim_registry_digest: str = Field(pattern=HEX_DIGEST)


class ReceiptManifest(_StrictModel):
    receipt_version: Literal["authority-receipt-v1"] = "authority-receipt-v1"
    receipt_policy_version: str = Field(min_length=3, max_length=80)
    capability_policy_version: str = Field(min_length=3, max_length=80)
    run_id: UUID
    tenant_id_hash: str = Field(pattern=HEX_DIGEST)
    scenario_version: str = Field(min_length=3, max_length=80)
    workflow_id: UUID
    final_state: str = Field(min_length=1, max_length=80)
    final_disposition: str = Field(min_length=1, max_length=80)
    first_epoch: str = Field(pattern=r"^(0|[1-9][0-9]*)$")
    last_epoch: str = Field(pattern=r"^[1-9][0-9]*$")
    event_count: str = Field(pattern=r"^[1-9][0-9]*$")
    ledger_first_hash: str = Field(pattern=HEX_DIGEST)
    ledger_head_hash: str = Field(pattern=HEX_DIGEST)
    digests: ReceiptDigestBindings
    subjects: ReceiptSubjects
    release: ReleaseBinding
    evidence_index_digest: str = Field(pattern=HEX_DIGEST)
    asserted_signing_time: str
    expires_at: str
    supersedes_receipt_id: UUID | None = None
    key_thumbprint: str = Field(min_length=43, max_length=43)
    signing_algorithm: Literal["Ed25519"] = "Ed25519"

    _signing_time = field_validator("asserted_signing_time")(_require_utc_string)
    _expiry_time = field_validator("expires_at")(_require_utc_string)

    @model_validator(mode="after")
    def validate_receipt_bounds(self) -> ReceiptManifest:
        if int(self.last_epoch) < int(self.first_epoch):
            raise ValueError("last_epoch precedes first_epoch")
        signing_time = datetime.fromisoformat(
            self.asserted_signing_time.removesuffix("Z") + "+00:00"
        )
        expiry = datetime.fromisoformat(self.expires_at.removesuffix("Z") + "+00:00")
        if expiry <= signing_time:
            raise ValueError("receipt expiry must follow asserted signing time")
        if self.subjects.separated != (self.subjects.operator != self.subjects.reviewer):
            raise ValueError("separation result does not match pseudonymous subjects")
        return self

    def canonical(self) -> bytes:
        encoded = canonical_bytes(self.model_dump(mode="json"))
        if len(encoded) > RECEIPT_MANIFEST_MAX_BYTES:
            raise ReceiptError("canonical receipt manifest exceeds 2048 bytes")
        return encoded


class ReceiptBuildContext(_StrictModel):
    receipt_policy_version: str = Field(min_length=3, max_length=80)
    scenario_version: str = Field(min_length=3, max_length=80)
    final_disposition: str = Field(min_length=1, max_length=80)
    release: ReleaseBinding
    evidence_index_digest: str = Field(pattern=HEX_DIGEST)
    asserted_signing_time: str
    expires_at: str
    key_thumbprint: str = Field(min_length=43, max_length=43)
    supersedes_receipt_id: UUID | None = None

    _signing_time = field_validator("asserted_signing_time")(_require_utc_string)
    _expiry_time = field_validator("expires_at")(_require_utc_string)


class VerifiedLedgerPrefix(_StrictModel):
    run_id: UUID
    tenant_id: str
    workflow_id: UUID
    capability_policy_version: str
    build_sha: str
    first_epoch: int
    last_epoch: int
    event_count: int
    first_hash: str = Field(pattern=HEX_DIGEST)
    head_hash: str = Field(pattern=HEX_DIGEST)
    final_state: str
    operator_subject: str
    reviewer_subject: str


def verify_ledger_prefix(events: Sequence[AuthorityEvent]) -> VerifiedLedgerPrefix:
    if not events:
        raise ReceiptVerificationError("authority ledger prefix is empty")
    expected_previous = ZERO_EVENT_HASH
    first = events[0]
    if (
        first.sequence != 1
        or first.event_type != "RUN_GENESIS"
        or first.state_before != "ABSENT"
        or first.epoch_before != 0
    ):
        raise ReceiptVerificationError("authority ledger prefix does not begin at run genesis")
    operator_subjects: set[str] = set()
    reviewer_subjects: set[str] = set()
    for expected_sequence, event in enumerate(events, start=1):
        if event.sequence != expected_sequence:
            raise ReceiptVerificationError("authority ledger sequence is not contiguous")
        if event.outcome != "accepted":
            raise ReceiptVerificationError("receipt prefix contains non-authority evidence")
        if (
            event.run_id != first.run_id
            or event.tenant_id != first.tenant_id
            or event.workflow_id != first.workflow_id
            or event.policy_version != first.policy_version
            or event.build_sha != first.build_sha
        ):
            raise ReceiptVerificationError("authority ledger boundary changed within prefix")
        if event.epoch_after != event.epoch_before + 1:
            raise ReceiptVerificationError("authority ledger epoch is not contiguous")
        if expected_sequence > 1:
            predecessor = events[expected_sequence - 2]
            if event.epoch_before != predecessor.epoch_after:
                raise ReceiptVerificationError("authority ledger epochs contain a gap")
            if event.state_before != predecessor.state_after:
                raise ReceiptVerificationError("authority ledger states contain a gap")
            if event.capabilities_before != predecessor.capabilities_after:
                raise ReceiptVerificationError("authority ledger capabilities contain a gap")
            if event.recorded_at < predecessor.recorded_at:
                raise ReceiptVerificationError("authority ledger timestamps regress")
        expected_channel = {
            "agent": RequestChannel.WEBMCP,
            "operator": RequestChannel.UI,
            "reviewer": RequestChannel.UI,
            "system": RequestChannel.SYSTEM,
        }[event.actor_role]
        if event.channel is not expected_channel:
            raise ReceiptVerificationError("authority actor role and channel are inconsistent")
        if not verify_event(event, expected_previous):
            raise ReceiptVerificationError("authority ledger hash chain verification failed")
        expected_previous = event.event_hash
        if event.actor_role == "operator":
            operator_subjects.add(event.actor_subject)
        elif event.actor_role == "reviewer":
            reviewer_subjects.add(event.actor_subject)
    if len(operator_subjects) != 1 or len(reviewer_subjects) != 1:
        raise ReceiptVerificationError("receipt requires one stable operator and reviewer subject")
    operator = next(iter(operator_subjects))
    reviewer = next(iter(reviewer_subjects))
    if operator == reviewer:
        raise ReceiptVerificationError("receipt requires independent operator and reviewer")
    return VerifiedLedgerPrefix(
        run_id=first.run_id,
        tenant_id=first.tenant_id,
        workflow_id=first.workflow_id,
        capability_policy_version=first.policy_version,
        build_sha=first.build_sha,
        first_epoch=first.epoch_before,
        last_epoch=events[-1].epoch_after,
        event_count=len(events),
        first_hash=first.event_hash,
        head_hash=events[-1].event_hash,
        final_state=events[-1].state_after,
        operator_subject=operator,
        reviewer_subject=reviewer,
    )


def _pseudonymous_subject(key: bytes, run_id: UUID, role: str, subject: str) -> str:
    material = canonical_bytes(
        {"run_id": str(run_id), "role": role, "subject": subject}
    )
    return hmac.new(key, b"recallops-receipt-subject-v1\x00" + material, hashlib.sha256).hexdigest()


def build_manifest(
    events: Sequence[AuthorityEvent],
    digests: ReceiptDigestBindings,
    context: ReceiptBuildContext,
    *,
    subject_pseudonym_key: bytes,
) -> ReceiptManifest:
    if len(subject_pseudonym_key) < 32:
        raise ReceiptError("subject pseudonymization key must contain at least 256 bits")
    prefix = verify_ledger_prefix(events)
    if prefix.build_sha != context.release.source_sha:
        raise ReceiptVerificationError("ledger build SHA does not match release binding")
    manifest = ReceiptManifest(
        receipt_policy_version=context.receipt_policy_version,
        capability_policy_version=prefix.capability_policy_version,
        run_id=prefix.run_id,
        tenant_id_hash=content_digest(
            "recallops-receipt-tenant-v1",
            {"run_id": str(prefix.run_id), "tenant_id": prefix.tenant_id},
        ),
        scenario_version=context.scenario_version,
        workflow_id=prefix.workflow_id,
        final_state=prefix.final_state,
        final_disposition=context.final_disposition,
        first_epoch=str(prefix.first_epoch),
        last_epoch=str(prefix.last_epoch),
        event_count=str(prefix.event_count),
        ledger_first_hash=prefix.first_hash,
        ledger_head_hash=prefix.head_hash,
        digests=digests,
        subjects=ReceiptSubjects(
            operator=_pseudonymous_subject(
                subject_pseudonym_key, prefix.run_id, "operator", prefix.operator_subject
            ),
            reviewer=_pseudonymous_subject(
                subject_pseudonym_key, prefix.run_id, "reviewer", prefix.reviewer_subject
            ),
            separated=True,
        ),
        release=context.release,
        evidence_index_digest=context.evidence_index_digest,
        asserted_signing_time=context.asserted_signing_time,
        expires_at=context.expires_at,
        supersedes_receipt_id=context.supersedes_receipt_id,
        key_thumbprint=context.key_thumbprint,
    )
    manifest.canonical()
    return manifest


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: str) -> bytes:
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ReceiptVerificationError("JWS uses non-canonical base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ReceiptVerificationError("JWS uses invalid base64url") from error
    if _b64url(decoded) != value:
        raise ReceiptVerificationError("JWS uses non-canonical base64url")
    return decoded


def _reject_constant(value: str) -> None:
    raise ReceiptVerificationError(f"non-I-JSON numeric value: {value}")


def parse_canonical_json(data: bytes) -> object:
    try:
        text = data.decode("utf-8", errors="strict")

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ReceiptVerificationError("duplicate JSON property")
                result[key] = value
            return result

        parsed = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=_reject_constant,
        )
    except ReceiptVerificationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ReceiptVerificationError("invalid canonical JSON") from error
    try:
        recanonicalized = canonical_bytes(parsed)
    except (ValueError, TypeError) as error:
        raise ReceiptVerificationError("JSON is outside the RFC 8785 I-JSON profile") from error
    if recanonicalized != data:
        raise ReceiptVerificationError("JSON bytes are not RFC 8785 canonical")
    return parsed


def public_jwk_from_der(public_key_der: bytes) -> dict[str, str]:
    try:
        public_key = serialization.load_der_public_key(public_key_der)
    except ValueError as error:
        raise ReceiptPreflightError("KMS public key is not valid DER SPKI") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise ReceiptPreflightError("KMS public key is not Ed25519")
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url(raw)}


def public_key_from_jwk(jwk: Mapping[str, object]) -> Ed25519PublicKey:
    if set(jwk) != {"kty", "crv", "x"} or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ReceiptVerificationError("trusted JWK is not an exact Ed25519 public JWK")
    raw = _decode_b64url(str(jwk.get("x", "")))
    if len(raw) != 32:
        raise ReceiptVerificationError("trusted Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def jwk_thumbprint(jwk: Mapping[str, object]) -> str:
    public_key_from_jwk(jwk)
    required = {"crv": "Ed25519", "kty": "OKP", "x": str(jwk["x"])}
    return _b64url(hashlib.sha256(canonical_bytes(required)).digest())


class TrustedKey(_StrictModel):
    kid: str = Field(min_length=43, max_length=43)
    jwk: dict[str, str]
    trust: Literal["repository_root", "transition"]
    status: Literal["active", "retired", "revoked"]
    release_ids: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_key(self) -> TrustedKey:
        if self.kid != jwk_thumbprint(self.jwk):
            raise ValueError("trusted key kid does not match RFC 7638 thumbprint")
        if len(set(self.release_ids)) != len(self.release_ids):
            raise ValueError("trusted key release IDs must be unique")
        return self


class KeyTransition(_StrictModel):
    from_kid: str = Field(min_length=43, max_length=43)
    to_kid: str = Field(min_length=43, max_length=43)
    transition_jws: str = Field(min_length=64, max_length=4096)


class TrustedKeyDocument(_StrictModel):
    registry_version: Literal["trusted-receipt-keys-v1"]
    keys: tuple[TrustedKey, ...]
    transitions: tuple[KeyTransition, ...]


def _protected_header(kid: str, typ: str) -> dict[str, object]:
    return {"alg": JOSE_ALGORITHM, "kid": kid, "typ": typ, "v": 1}


def jws_signing_input(payload: bytes, kid: str, typ: str = RECEIPT_TYP) -> bytes:
    header = canonical_bytes(_protected_header(kid, typ))
    signing_input = f"{_b64url(header)}.{_b64url(payload)}".encode("ascii")
    if len(signing_input) > KMS_RAW_MESSAGE_MAX_BYTES:
        raise ReceiptError("JWS signing input exceeds the KMS RAW message limit")
    return signing_input


def _verify_compact(
    compact: str,
    jwk: Mapping[str, object],
    *,
    expected_kid: str,
    expected_typ: str,
) -> tuple[dict[str, object], bytes]:
    parts = compact.split(".")
    if len(parts) != 3:
        raise ReceiptVerificationError("compact JWS must contain three segments")
    protected_bytes, payload_bytes, signature = map(_decode_b64url, parts)
    protected = parse_canonical_json(protected_bytes)
    if not isinstance(protected, dict) or protected != _protected_header(
        expected_kid, expected_typ
    ):
        raise ReceiptVerificationError("JWS protected header does not match the frozen profile")
    if len(signature) != 64:
        raise ReceiptVerificationError("Ed25519 signature must be 64 bytes")
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    try:
        public_key_from_jwk(jwk).verify(signature, signing_input)
    except InvalidSignature as error:
        raise ReceiptVerificationError("JWS signature verification failed") from error
    payload = parse_canonical_json(payload_bytes)
    if not isinstance(payload, dict):
        raise ReceiptVerificationError("JWS payload must be a canonical JSON object")
    return cast(dict[str, object], payload), payload_bytes


class TrustedKeyRegistry:
    def __init__(self, document: TrustedKeyDocument) -> None:
        self.document = document
        self._keys = {item.kid: item for item in document.keys}
        if len(self._keys) != len(document.keys):
            raise ReceiptVerificationError("trusted-key registry contains duplicate keys")
        roots = [item for item in document.keys if item.trust == "repository_root"]
        if document.keys and len(roots) != 1:
            raise ReceiptVerificationError(
                "trusted-key registry requires exactly one repository root"
            )
        established = {item.kid for item in roots}
        transitions_by_target: dict[str, KeyTransition] = {}
        for transition in document.transitions:
            if transition.to_kid in transitions_by_target:
                raise ReceiptVerificationError("trusted key has multiple predecessor transitions")
            transitions_by_target[transition.to_kid] = transition
        pending = {item.kid for item in document.keys if item.trust == "transition"}
        while pending:
            progressed = False
            for target in tuple(pending):
                candidate_transition = transitions_by_target.get(target)
                if candidate_transition is None or candidate_transition.from_kid not in established:
                    continue
                if candidate_transition.to_kid == candidate_transition.from_kid:
                    raise ReceiptVerificationError("key transition cannot self-authorize")
                source = self._keys.get(candidate_transition.from_kid)
                target_key = self._keys.get(target)
                if source is None or target_key is None:
                    raise ReceiptVerificationError("key transition references an unknown key")
                payload, _ = _verify_compact(
                    candidate_transition.transition_jws,
                    source.jwk,
                    expected_kid=source.kid,
                    expected_typ=TRANSITION_TYP,
                )
                expected = {
                    "from_kid": source.kid,
                    "to_jwk_digest": content_digest("recallops-public-jwk-v1", target_key.jwk),
                    "to_kid": target_key.kid,
                    "transition_version": "receipt-key-transition-v1",
                }
                if payload != expected:
                    raise ReceiptVerificationError("signed key transition does not bind target key")
                established.add(target)
                pending.remove(target)
                progressed = True
            if not progressed:
                raise ReceiptVerificationError(
                    "trusted-key transitions are missing, cyclic, or untrusted"
                )
        unused = set(transitions_by_target) - {
            item.kid for item in document.keys if item.trust == "transition"
        }
        if unused:
            raise ReceiptVerificationError("trusted-key registry contains an unused transition")

    @classmethod
    def load(cls, path: Path) -> TrustedKeyRegistry:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise ReceiptPreflightError("trusted-key registry is unavailable") from error
        parsed = parse_canonical_json(raw)
        try:
            document = TrustedKeyDocument.model_validate(parsed)
        except ValueError as error:
            raise ReceiptVerificationError("trusted-key registry schema is invalid") from error
        return cls(document)

    def resolve(self, kid: str, release_id: str) -> TrustedKey:
        key = self._keys.get(kid)
        if key is None:
            raise ReceiptVerificationError("receipt key is not repository-pinned")
        if key.status != "active" or release_id not in key.release_ids:
            raise ReceiptVerificationError("receipt key is not authorized for this release")
        return key


class KmsClient(Protocol):
    def get_public_key(self, **kwargs: object) -> Mapping[str, object]: ...
    def sign(self, **kwargs: object) -> Mapping[str, object]: ...


class KmsReceiptSigner:
    def __init__(
        self,
        client: KmsClient,
        key_id: str,
        release_id: str,
        trusted_keys: TrustedKeyRegistry,
    ) -> None:
        if not key_id or not release_id:
            raise ReceiptPreflightError("KMS key ID and release ID are required")
        self._client = client
        self._configured_key_id = key_id
        self._release_id = release_id
        self._trusted_keys = trusted_keys
        self._public_key: Ed25519PublicKey | None = None
        self._kid: str | None = None
        self._kms_key_id: str | None = None

    @property
    def kid(self) -> str:
        if self._kid is None:
            raise ReceiptPreflightError("KMS receipt signer has not passed preflight")
        return self._kid

    def preflight(self) -> str:
        try:
            response = self._client.get_public_key(KeyId=self._configured_key_id)
        except Exception as error:  # SDK failures are normalized at this boundary.
            raise ReceiptPreflightError("KMS GetPublicKey preflight failed") from error
        if response.get("KeySpec") != AWS_KEY_SPEC:
            raise ReceiptPreflightError("KMS key spec is not ECC_NIST_EDWARDS25519")
        if response.get("KeyUsage") != AWS_KEY_USAGE:
            raise ReceiptPreflightError("KMS key usage is not SIGN_VERIFY")
        algorithms = response.get("SigningAlgorithms")
        if (
            not isinstance(algorithms, Sequence)
            or isinstance(algorithms, (str, bytes))
            or AWS_SIGNING_ALGORITHM not in algorithms
        ):
            raise ReceiptPreflightError("KMS key does not support ED25519_SHA_512")
        public_der = response.get("PublicKey")
        if not isinstance(public_der, bytes):
            raise ReceiptPreflightError("KMS GetPublicKey did not return DER bytes")
        jwk = public_jwk_from_der(public_der)
        kid = jwk_thumbprint(jwk)
        pinned = self._trusted_keys.resolve(kid, self._release_id)
        if not hmac.compare_digest(canonical_bytes(pinned.jwk), canonical_bytes(jwk)):
            raise ReceiptPreflightError("KMS public key differs from repository-pinned JWK")
        returned_key_id = response.get("KeyId")
        if not isinstance(returned_key_id, str) or not returned_key_id:
            raise ReceiptPreflightError("KMS GetPublicKey did not return a key ARN")
        self._public_key = public_key_from_jwk(jwk)
        self._kid = kid
        self._kms_key_id = returned_key_id
        return kid

    def sign_manifest(self, manifest: ReceiptManifest) -> str:
        if self._public_key is None or self._kid is None or self._kms_key_id is None:
            raise ReceiptPreflightError("KMS receipt signer has not passed preflight")
        if manifest.key_thumbprint != self._kid or manifest.release.release_id != self._release_id:
            raise ReceiptPreflightError("manifest key or release differs from preflight binding")
        payload = manifest.canonical()
        signing_input = jws_signing_input(payload, self._kid)
        try:
            response = self._client.sign(
                KeyId=self._kms_key_id,
                Message=signing_input,
                MessageType=AWS_MESSAGE_TYPE,
                SigningAlgorithm=AWS_SIGNING_ALGORITHM,
            )
        except Exception as error:
            raise ReceiptPreflightError("KMS Sign failed") from error
        if response.get("SigningAlgorithm") != AWS_SIGNING_ALGORITHM:
            raise ReceiptPreflightError("KMS returned an unexpected signing algorithm")
        if response.get("KeyId") != self._kms_key_id:
            raise ReceiptPreflightError("KMS returned an unexpected signing key")
        signature = response.get("Signature")
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ReceiptPreflightError("KMS returned an invalid Ed25519 signature")
        try:
            self._public_key.verify(signature, signing_input)
        except InvalidSignature as error:
            raise ReceiptPreflightError(
                "KMS returned a signature that failed local verification"
            ) from error
        protected, encoded_payload = signing_input.decode("ascii").split(".", 1)
        return f"{protected}.{encoded_payload}.{_b64url(signature)}"


def verify_receipt_jws(
    compact: str,
    trusted_keys: TrustedKeyRegistry,
    *,
    release_id: str,
) -> ReceiptManifest:
    parts = compact.split(".")
    if len(parts) != 3:
        raise ReceiptVerificationError("compact JWS must contain three segments")
    protected = parse_canonical_json(_decode_b64url(parts[0]))
    if not isinstance(protected, dict):
        raise ReceiptVerificationError("JWS protected header must be an object")
    if protected.get("alg") != JOSE_ALGORITHM:
        raise ReceiptVerificationError("only the fully specified Ed25519 algorithm is accepted")
    kid = protected.get("kid")
    if not isinstance(kid, str):
        raise ReceiptVerificationError("JWS protected header has no valid kid")
    key = trusted_keys.resolve(kid, release_id)
    payload, payload_bytes = _verify_compact(
        compact,
        key.jwk,
        expected_kid=kid,
        expected_typ=RECEIPT_TYP,
    )
    try:
        manifest = ReceiptManifest.model_validate(payload)
    except ValueError as error:
        raise ReceiptVerificationError("receipt manifest schema is invalid") from error
    if manifest.canonical() != payload_bytes:
        raise ReceiptVerificationError("receipt payload differs from canonical manifest")
    if manifest.key_thumbprint != kid or manifest.release.release_id != release_id:
        raise ReceiptVerificationError("receipt trust binding does not match protected header")
    return manifest


def production_preflight() -> str:
    """Validate the exact pinned KMS key; there is intentionally no local fallback."""
    import boto3

    from recallops.config import Settings

    settings = Settings()
    if settings.receipt_kms_key_id is None or settings.receipt_release_id is None:
        raise ReceiptPreflightError("receipt KMS key and release ID are required")
    registry = TrustedKeyRegistry.load(settings.receipt_trusted_keys_path)
    client = boto3.client("kms", region_name=settings.aws_region)
    signer = KmsReceiptSigner(
        cast(KmsClient, client),
        settings.receipt_kms_key_id,
        settings.receipt_release_id,
        registry,
    )
    return signer.preflight()


def main() -> None:
    try:
        kid = production_preflight()
    except ReceiptError as error:
        raise SystemExit(f"receipt signing preflight failed: {error}") from None
    print(f"receipt signing preflight passed: kid={kid}")
