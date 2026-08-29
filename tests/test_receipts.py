import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from recallops.canonical import canonical_bytes, content_digest
from recallops.ledger import (
    ZERO_EVENT_HASH,
    AuthorityEvent,
    authority_event_hash,
    canonical_event_payload,
)
from recallops.receipts import (
    AWS_KEY_SPEC,
    AWS_KEY_USAGE,
    AWS_MESSAGE_TYPE,
    AWS_SIGNING_ALGORITHM,
    RECEIPT_TYP,
    TRANSITION_TYP,
    KeyTransition,
    KmsReceiptSigner,
    ReceiptBuildContext,
    ReceiptDigestBindings,
    ReceiptError,
    ReceiptManifest,
    ReceiptPreflightError,
    ReceiptVerificationError,
    ReleaseBinding,
    TrustedKey,
    TrustedKeyDocument,
    TrustedKeyRegistry,
    build_manifest,
    jwk_thumbprint,
    jws_signing_input,
    parse_canonical_json,
    public_jwk_from_der,
    transition_binding_digest,
    verify_ledger_prefix,
    verify_receipt_jws,
)
from recallops.workflow import RequestChannel

RUN_ID = UUID("00000000-0000-0000-0000-000000000042")
WORKFLOW_ID = UUID("10000000-0000-0000-0000-000000000042")
SOURCE_SHA = "a" * 40
RELEASE_ID = "release-2026-08-29"
PSEUDONYM_KEY = b"p" * 32


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def private_key(seed: int = 0) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes((index + seed) % 256 for index in range(32)))


def public_der(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def root_registry(key: Ed25519PrivateKey, release_id: str = RELEASE_ID) -> TrustedKeyRegistry:
    jwk = public_jwk_from_der(public_der(key))
    return TrustedKeyRegistry(
        TrustedKeyDocument(
            registry_version="trusted-receipt-keys-v1",
            keys=(
                TrustedKey(
                    kid=jwk_thumbprint(jwk),
                    jwk=jwk,
                    trust="repository_root",
                    status="active",
                    release_ids=(release_id,),
                ),
            ),
            transitions=(),
        )
    )


def ledger_events() -> list[AuthorityEvent]:
    digests = ReceiptDigestBindings(
        proposal="1" * 64,
        execution="2" * 64,
        observation="3" * 64,
        assessment="4" * 64,
        policy_verdict="5" * 64,
        memory="6" * 64,
        review="7" * 64,
    )
    roles = (
        ("system", "run-allocator", "ABSENT", "INVESTIGATING", None, None),
        (
            "agent",
            "agent-42",
            "INVESTIGATING",
            "AWAITING_OPERATOR_APPROVAL",
            "proposal",
            digests.proposal,
        ),
        (
            "operator",
            "operator-42",
            "AWAITING_OPERATOR_APPROVAL",
            "APPROVED_AWAITING_EXECUTION",
            "proposal",
            digests.proposal,
        ),
        (
            "operator",
            "operator-42",
            "APPROVED_AWAITING_EXECUTION",
            "OBSERVING_POSTCHECK",
            "execution_binding",
            transition_binding_digest(
                "execution", {"execution": digests.execution, "proposal": digests.proposal}
            ),
        ),
        (
            "system",
            "observer-42",
            "OBSERVING_POSTCHECK",
            "POSTCHECK_READY",
            "observation_binding",
            transition_binding_digest(
                "observation",
                {
                    "execution": digests.execution,
                    "observation": digests.observation,
                    "policy_verdict": digests.policy_verdict,
                },
            ),
        ),
        (
            "agent",
            "agent-42",
            "POSTCHECK_READY",
            "PENDING_REVIEW",
            "outcome_binding",
            transition_binding_digest(
                "outcome",
                {
                    "assessment": digests.assessment,
                    "memory": digests.memory,
                    "observation": digests.observation,
                    "policy_verdict": digests.policy_verdict,
                },
            ),
        ),
        (
            "reviewer",
            "reviewer-42",
            "PENDING_REVIEW",
            "REVIEWED",
            "review_binding",
            transition_binding_digest(
                "review",
                {
                    "disposition": hashlib.sha256(b"certify").hexdigest(),
                    "memory": digests.memory,
                    "review": digests.review,
                },
            ),
        ),
    )
    previous = ZERO_EVENT_HASH
    events: list[AuthorityEvent] = []
    for index, (role, subject, before, after, object_type, object_digest) in enumerate(
        roles, start=1
    ):
        event = AuthorityEvent(
            event_id=UUID(f"00000000-0000-0000-0000-{index:012d}"),
            run_id=RUN_ID,
            tenant_id="judge_fixture",
            sequence=index,
            recorded_at=datetime(2026, 8, 29, 1, 2, index, tzinfo=UTC),
            event_type="RUN_GENESIS" if index == 1 else f"{before}_TO_{after}",
            actor_subject=subject,
            actor_role=role,  # type: ignore[arg-type]
            channel=RequestChannel.SYSTEM
            if role == "system"
            else (RequestChannel.WEBMCP if role == "agent" else RequestChannel.UI),
            workflow_id=WORKFLOW_ID,
            epoch_before=index - 1,
            epoch_after=index,
            state_before=before,
            state_after=after,
            capabilities_before=(),
            capabilities_after=(),
            object_type=object_type,
            object_id=str(WORKFLOW_ID) if object_type else None,
            object_digest=object_digest,
            reason_code="ACCEPTED",
            display_summary=f"Authority committed: {before} to {after}",
            policy_version="webmcp-capability-v1",
            build_sha=SOURCE_SHA,
            previous_event_hash=previous,
            event_hash=ZERO_EVENT_HASH,
        )
        event = event.model_copy(
            update={"event_hash": authority_event_hash(previous, canonical_event_payload(event))}
        )
        events.append(event)
        previous = event.event_hash
    return events


def manifest_for(kid: str):
    digests = ReceiptDigestBindings(
        proposal="1" * 64,
        execution="2" * 64,
        observation="3" * 64,
        assessment="4" * 64,
        policy_verdict="5" * 64,
        memory="6" * 64,
        review="7" * 64,
    )
    context = ReceiptBuildContext(
        receipt_policy_version="authority-receipt-policy-v1",
        scenario_version="checkout-latency-v1",
        final_disposition="certify",
        release=ReleaseBinding(
            release_id=RELEASE_ID,
            source_sha=SOURCE_SHA,
            image_digest=f"sha256:{'b' * 64}",
            evaluation_version="governed-benchmark-v1",
            claim_registry_digest="c" * 64,
        ),
        evidence_index_digest="d" * 64,
        asserted_signing_time="2026-08-29T01:03:00Z",
        expires_at="2026-09-05T01:03:00Z",
        key_thumbprint=kid,
    )
    return build_manifest(
        ledger_events(), digests, context, subject_pseudonym_key=PSEUDONYM_KEY
    )


class FakeKms:
    def __init__(self, key: Ed25519PrivateKey, *, corrupt_signature: bool = False) -> None:
        self.key = key
        self.corrupt_signature = corrupt_signature
        self.key_id = "arn:aws:kms:us-east-1:111122223333:key/test-key"
        self.sign_request: dict[str, object] | None = None

    def get_public_key(self, **kwargs: object) -> dict[str, object]:
        assert kwargs == {"KeyId": "alias/recallops-receipt"}
        return {
            "KeyId": self.key_id,
            "KeySpec": AWS_KEY_SPEC,
            "KeyUsage": AWS_KEY_USAGE,
            "SigningAlgorithms": [AWS_SIGNING_ALGORITHM],
            "PublicKey": public_der(self.key),
        }

    def sign(self, **kwargs: object) -> dict[str, object]:
        self.sign_request = kwargs
        message = kwargs["Message"]
        assert isinstance(message, bytes)
        signature = self.key.sign(message)
        if self.corrupt_signature:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return {
            "KeyId": self.key_id,
            "SigningAlgorithm": AWS_SIGNING_ALGORITHM,
            "Signature": signature,
        }


def test_rfc8785_canonical_parser_rejects_noncanonical_and_non_ijson() -> None:
    canonical = '{"a":[3,{"x":"€"}],"b":1}'.encode()
    assert parse_canonical_json(canonical) == {"a": [3, {"x": "€"}], "b": 1}
    for invalid in (
        b'{"b":1,"a":2}',
        b'{"a":1, "b":2}',
        b'{"a":1,"a":2}',
        b'{"n":NaN}',
        b'{"n":9007199254740992}',
    ):
        with pytest.raises(ReceiptVerificationError):
            parse_canonical_json(invalid)


def test_rfc7638_ed25519_thumbprint_fixed_vector() -> None:
    jwk = public_jwk_from_der(public_der(private_key()))
    assert jwk == {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
    }
    assert jwk_thumbprint(jwk) == "1IG2tMH7J2wbJZnOf8LJzQitKf7LMvoAElsuDMVM54Y"


def test_ledger_prefix_and_manifest_are_complete_bounded_and_pseudonymous() -> None:
    key = private_key()
    kid = jwk_thumbprint(public_jwk_from_der(public_der(key)))
    manifest = manifest_for(kid)
    prefix = verify_ledger_prefix(ledger_events())
    assert prefix.event_count == 7 and prefix.head_hash == manifest.ledger_head_hash
    assert len(manifest.canonical()) == 2030
    assert len(jws_signing_input(manifest.canonical(), kid)) == 2862
    encoded = manifest.canonical().decode()
    assert "judge_fixture" not in encoded
    assert "operator-42" not in encoded and "reviewer-42" not in encoded
    assert manifest.subjects.separated is True


def test_manifest_rejects_a_release_from_a_different_build() -> None:
    key = private_key()
    kid = jwk_thumbprint(public_jwk_from_der(public_der(key)))
    context = ReceiptBuildContext(
        receipt_policy_version="authority-receipt-policy-v1",
        scenario_version="checkout-latency-v1",
        final_disposition="certify",
        release=ReleaseBinding(
            release_id=RELEASE_ID,
            source_sha="e" * 40,
            image_digest=f"sha256:{'b' * 64}",
            evaluation_version="governed-benchmark-v1",
            claim_registry_digest="c" * 64,
        ),
        evidence_index_digest="d" * 64,
        asserted_signing_time="2026-08-29T01:03:00Z",
        expires_at="2026-09-05T01:03:00Z",
        key_thumbprint=kid,
    )
    with pytest.raises(ReceiptVerificationError, match="build SHA"):
        build_manifest(
            ledger_events(),
            ReceiptDigestBindings(
                proposal="1" * 64,
                execution="2" * 64,
                observation="3" * 64,
                assessment="4" * 64,
                policy_verdict="5" * 64,
                memory="6" * 64,
                review="7" * 64,
            ),
            context,
            subject_pseudonym_key=PSEUDONYM_KEY,
        )


def test_manifest_requires_a_256_bit_pseudonymization_key() -> None:
    key = private_key()
    kid = jwk_thumbprint(public_jwk_from_der(public_der(key)))
    manifest = manifest_for(kid)
    context = ReceiptBuildContext(
        receipt_policy_version=manifest.receipt_policy_version,
        scenario_version=manifest.scenario_version,
        final_disposition=manifest.final_disposition,
        release=manifest.release,
        evidence_index_digest=manifest.evidence_index_digest,
        asserted_signing_time=manifest.asserted_signing_time,
        expires_at=manifest.expires_at,
        key_thumbprint=kid,
    )
    with pytest.raises(ReceiptError, match="at least 256 bits"):
        build_manifest(
            ledger_events(), manifest.digests, context, subject_pseudonym_key=b"too-short"
        )


def test_jws_signing_input_enforces_kms_raw_message_limit() -> None:
    with pytest.raises(ReceiptError, match="KMS RAW message limit"):
        jws_signing_input(b"x" * 4000, "k" * 43)


def test_manifest_rejects_extra_sensitive_fields_and_nonpositive_validity_window() -> None:
    key = private_key()
    manifest = manifest_for(jwk_thumbprint(public_jwk_from_der(public_der(key))))
    payload = manifest.model_dump(mode="json")
    payload["incident_text"] = "must never enter a compact receipt"
    with pytest.raises(ValueError):
        ReceiptManifest.model_validate(payload)
    payload.pop("incident_text")
    payload["expires_at"] = payload["asserted_signing_time"]
    with pytest.raises(ValueError, match="expiry must follow"):
        ReceiptManifest.model_validate(payload)


@pytest.mark.parametrize(
    "mutation",
    [
        "genesis",
        "sequence",
        "hash",
        "boundary",
        "state_gap",
        "capability_gap",
        "timestamp_regression",
        "channel",
        "same_subject",
    ],
)
def test_ledger_prefix_rejects_gaps_tampering_boundary_changes_and_role_collapse(
    mutation: str,
) -> None:
    events = ledger_events()
    if mutation == "genesis":
        events[0] = events[0].model_copy(update={"event_type": "NOT_GENESIS"})
    elif mutation == "sequence":
        events[2] = events[2].model_copy(update={"sequence": 8})
    elif mutation == "hash":
        events[2] = events[2].model_copy(update={"event_hash": "f" * 64})
    elif mutation == "boundary":
        events[2] = events[2].model_copy(update={"tenant_id": "other"})
    elif mutation == "state_gap":
        events[2] = events[2].model_copy(update={"state_before": "WRONG"})
    elif mutation == "capability_gap":
        events[2] = events[2].model_copy(update={"capabilities_before": ("unexpected",)})
    elif mutation == "timestamp_regression":
        events[2] = events[2].model_copy(
            update={"recorded_at": datetime(2026, 8, 29, 1, 1, 1, tzinfo=UTC)}
        )
    elif mutation == "channel":
        events[2] = events[2].model_copy(update={"channel": RequestChannel.WEBMCP})
    else:
        events[-1] = events[-1].model_copy(update={"actor_subject": "operator-42"})
    with pytest.raises(ReceiptVerificationError):
        verify_ledger_prefix(events)


def test_kms_signing_uses_exact_profile_and_verifies_returned_signature_locally() -> None:
    key = private_key()
    registry = root_registry(key)
    kms = FakeKms(key)
    signer = KmsReceiptSigner(kms, "alias/recallops-receipt", RELEASE_ID, registry)
    kid = signer.preflight()
    assert signer.public_jwk == public_jwk_from_der(public_der(key))
    assert signer.trusted_keys is registry
    manifest = manifest_for(kid)
    compact = signer.sign_manifest(manifest)
    assert verify_receipt_jws(compact, registry, release_id=RELEASE_ID) == manifest
    assert kms.sign_request == {
        "KeyId": kms.key_id,
        "Message": jws_signing_input(manifest.canonical(), kid),
        "MessageType": AWS_MESSAGE_TYPE,
        "SigningAlgorithm": AWS_SIGNING_ALGORITHM,
    }


def test_kms_returned_signature_must_verify_before_receipt_exists() -> None:
    key = private_key()
    signer = KmsReceiptSigner(
        FakeKms(key, corrupt_signature=True),
        "alias/recallops-receipt",
        RELEASE_ID,
        root_registry(key),
    )
    kid = signer.preflight()
    with pytest.raises(ReceiptPreflightError, match="local verification"):
        signer.sign_manifest(manifest_for(kid))


def test_receipt_verifier_rejects_payload_and_signature_tampering() -> None:
    key = private_key()
    registry = root_registry(key)
    signer = KmsReceiptSigner(FakeKms(key), "alias/recallops-receipt", RELEASE_ID, registry)
    kid = signer.preflight()
    compact = signer.sign_manifest(manifest_for(kid))
    protected, payload, signature = compact.split(".")
    tampered_payload = ("A" if payload[0] != "A" else "B") + payload[1:]
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(ReceiptVerificationError):
        verify_receipt_jws(
            f"{protected}.{tampered_payload}.{signature}", registry, release_id=RELEASE_ID
        )
    with pytest.raises(ReceiptVerificationError, match="signature verification"):
        verify_receipt_jws(
            f"{protected}.{payload}.{tampered_signature}", registry, release_id=RELEASE_ID
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("KeySpec", "ECC_NIST_P256", "key spec"),
        ("KeyUsage", "ENCRYPT_DECRYPT", "key usage"),
        ("SigningAlgorithms", ["ED25519_PH_SHA_512"], "does not support"),
    ],
)
def test_kms_preflight_has_no_algorithm_or_key_type_fallback(
    field: str, value: object, message: str
) -> None:
    key = private_key()

    class WrongProfileKms(FakeKms):
        def get_public_key(self, **kwargs: object) -> dict[str, object]:
            response = super().get_public_key(**kwargs)
            response[field] = value
            return response

    signer = KmsReceiptSigner(
        WrongProfileKms(key), "alias/recallops-receipt", RELEASE_ID, root_registry(key)
    )
    with pytest.raises(ReceiptPreflightError, match=message):
        signer.preflight()


def test_cryptographically_valid_deprecated_ed_dsa_header_is_rejected() -> None:
    key = private_key()
    registry = root_registry(key)
    kid = jwk_thumbprint(public_jwk_from_der(public_der(key)))
    payload = manifest_for(kid).canonical()
    protected = canonical_bytes({"alg": "EdDSA", "kid": kid, "typ": RECEIPT_TYP, "v": 1})
    signing_input = f"{b64url(protected)}.{b64url(payload)}".encode()
    compact = f"{signing_input.decode()}.{b64url(key.sign(signing_input))}"
    with pytest.raises(ReceiptVerificationError, match="fully specified Ed25519"):
        verify_receipt_jws(compact, registry, release_id=RELEASE_ID)


def test_key_replacement_requires_a_signed_predecessor_transition() -> None:
    old_key = private_key()
    new_key = private_key(1)
    old_jwk = public_jwk_from_der(public_der(old_key))
    new_jwk = public_jwk_from_der(public_der(new_key))
    old_kid = jwk_thumbprint(old_jwk)
    new_kid = jwk_thumbprint(new_jwk)
    keys = (
        TrustedKey(
            kid=old_kid,
            jwk=old_jwk,
            trust="repository_root",
            status="retired",
            release_ids=("release-1",),
        ),
        TrustedKey(
            kid=new_kid,
            jwk=new_jwk,
            trust="transition",
            status="active",
            release_ids=("release-2",),
        ),
    )
    with pytest.raises(ReceiptVerificationError, match="missing, cyclic, or untrusted"):
        TrustedKeyRegistry(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1", keys=keys, transitions=()
            )
        )

    payload = canonical_bytes(
        {
            "from_kid": old_kid,
            "to_jwk_digest": content_digest("recallops-public-jwk-v1", new_jwk),
            "to_kid": new_kid,
            "transition_version": "receipt-key-transition-v1",
        }
    )
    signing_input = jws_signing_input(payload, old_kid, TRANSITION_TYP)
    transition_jws = f"{signing_input.decode()}.{b64url(old_key.sign(signing_input))}"
    registry = TrustedKeyRegistry(
        TrustedKeyDocument(
            registry_version="trusted-receipt-keys-v1",
            keys=keys,
            transitions=(
                KeyTransition(from_kid=old_kid, to_kid=new_kid, transition_jws=transition_jws),
            ),
        )
    )
    assert registry.resolve(new_kid, "release-2").jwk == new_jwk


def test_registry_file_must_itself_be_canonical_and_pinned(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps({"registry_version": "trusted-receipt-keys-v1", "keys": [], "transitions": []})
    )
    with pytest.raises(ReceiptVerificationError, match="not RFC 8785 canonical"):
        TrustedKeyRegistry.load(path)


def test_unpinned_kms_key_fails_preflight() -> None:
    key = private_key()
    signer = KmsReceiptSigner(
        FakeKms(key),
        "alias/recallops-receipt",
        RELEASE_ID,
        TrustedKeyRegistry(
            TrustedKeyDocument(registry_version="trusted-receipt-keys-v1", keys=(), transitions=())
        ),
    )
    with pytest.raises(ReceiptVerificationError, match="not repository-pinned"):
        signer.preflight()
