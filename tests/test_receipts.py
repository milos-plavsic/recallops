import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

import recallops.receipts as receipts
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
    verify_release_statement_jws,
)
from recallops.release_evidence import (
    ASSURANCE_REQUIREMENTS,
    LIVE_REQUIREMENTS,
    ArtifactAttestation,
    ReleaseIdentity,
    derive_dual_gates,
    release_statement,
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
    return build_manifest(ledger_events(), digests, context, subject_pseudonym_key=PSEUDONYM_KEY)


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
    with pytest.raises(ReceiptPreflightError, match="has not passed"):
        signer.signing_preflight()
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

    probe = signer.signing_preflight()
    protected, payload, signature = probe.split(".")
    assert protected and payload and signature
    assert kms.sign_request["MessageType"] == AWS_MESSAGE_TYPE
    assert kms.sign_request["SigningAlgorithm"] == AWS_SIGNING_ALGORITHM
    probe_payload = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    assert json.loads(probe_payload)["type"] == "recallops-kms-signing-preflight-v1"


def test_kms_signs_and_verifies_acyclic_dual_gate_release_statement() -> None:
    key = private_key()
    registry = root_registry(key)
    signer = KmsReceiptSigner(FakeKms(key), "alias/recallops-receipt", RELEASE_ID, registry)
    kid = signer.preflight()
    identity = ReleaseIdentity(
        release_id=RELEASE_ID,
        source_sha=SOURCE_SHA,
        image_digest=f"sha256:{'b' * 64}",
        capability_policy_version="webmcp-capability-v1",
        receipt_policy_version="authority-receipt-policy-v1",
        evaluation_version="governed-benchmark-v1",
        receipt_key_thumbprint=kid,
    )

    def evidence(kinds: frozenset[str]) -> list[ArtifactAttestation]:
        return [
            ArtifactAttestation(
                artifact_kind=kind,
                artifact_digest=f"{index:064x}",
                release_id=RELEASE_ID,
                source_sha=SOURCE_SHA,
                image_digest=identity.image_digest,
                passed=True,
                path=f"artifacts/release/{kind}.json",
            )
            for index, kind in enumerate(sorted(kinds), start=1)
        ]

    statement = release_statement(
        derive_dual_gates(
            identity,
            live_artifacts=evidence(LIVE_REQUIREMENTS),
            assurance_artifacts=evidence(ASSURANCE_REQUIREMENTS),
        )
    )
    compact = signer.sign_release_statement(statement)
    assert verify_release_statement_jws(compact, registry, release_id=RELEASE_ID) == statement
    with pytest.raises(ReceiptPreflightError, match="release statement"):
        signer.sign_release_statement(
            statement.model_copy(
                update={"identity": identity.model_copy(update={"release_id": "other-release"})}
            )
        )


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
    canonical = b'{"keys":[],"registry_version":"trusted-receipt-keys-v1","transitions":[]}'
    assert TrustedKeyRegistry.from_bytes(canonical).document.keys == ()


def test_repository_trusted_key_registry_is_exact_canonical_bytes() -> None:
    path = Path(__file__).parents[1] / "tools" / "trusted-receipt-keys.json"
    raw = path.read_bytes()
    assert raw == canonical_bytes(json.loads(raw))
    assert TrustedKeyRegistry.load(path).document.registry_version == "trusted-receipt-keys-v1"


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


def test_receipt_schema_and_encoding_guards_cover_all_fail_closed_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="RFC 3339"):
        receipts._require_utc_string("2026-08-29T01:00:00+00:00")
    with pytest.raises(ReceiptError, match="lowercase"):
        transition_binding_digest("execution", {})
    with pytest.raises(ReceiptError, match="lowercase"):
        transition_binding_digest("execution", {"x": "A" * 64})
    manifest = manifest_for(jwk_thumbprint(public_jwk_from_der(public_der(private_key()))))
    with pytest.raises(ValueError, match="last_epoch"):
        ReceiptManifest.model_validate(
            manifest.model_dump(mode="json") | {"first_epoch": "9", "last_epoch": "8"}
        )
    with pytest.raises(ValueError, match="separation"):
        ReceiptManifest.model_validate(
            manifest.model_dump(mode="json")
            | {
                "subjects": {
                    "operator": "a" * 64,
                    "reviewer": "a" * 64,
                    "separated": True,
                }
            }
        )
    monkeypatch.setattr(receipts, "RECEIPT_MANIFEST_MAX_BYTES", 1)
    with pytest.raises(ReceiptError, match="2048"):
        manifest.canonical()
    for value in ("", "*", "A"):
        with pytest.raises(ReceiptVerificationError, match="base64url"):
            receipts._decode_b64url(value)
    monkeypatch.setattr(
        receipts.base64, "b64decode", lambda *a, **k: (_ for _ in ()).throw(ValueError())
    )
    with pytest.raises(ReceiptVerificationError, match="invalid base64url"):
        receipts._decode_b64url("AA")
    monkeypatch.undo()
    with pytest.raises(ReceiptVerificationError, match="non-canonical base64url"):
        receipts._decode_b64url("AB")


def test_canonical_parser_rejects_decoding_schema_and_noncanonical_classes() -> None:
    for value, match in (
        (b"\xff", "invalid canonical JSON"),
        (b"{", "invalid canonical JSON"),
    ):
        with pytest.raises(ReceiptVerificationError, match=match):
            parse_canonical_json(value)


def test_public_key_profiles_reject_invalid_der_algorithm_and_jwk() -> None:
    with pytest.raises(ReceiptPreflightError, match="DER SPKI"):
        public_jwk_from_der(b"not-der")
    rsa = generate_private_key(public_exponent=65537, key_size=2048)
    rsa_der = rsa.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(ReceiptPreflightError, match="not Ed25519"):
        public_jwk_from_der(rsa_der)
    with pytest.raises(ReceiptVerificationError, match="exact Ed25519"):
        receipts.public_key_from_jwk({"kty": "OKP", "crv": "X25519", "x": "x"})
    with pytest.raises(ReceiptVerificationError, match="32 bytes"):
        receipts.public_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": b64url(b"x")})


def test_trusted_key_model_and_registry_reject_every_ambiguous_topology(
    tmp_path: Path,
) -> None:
    key = private_key()
    jwk = public_jwk_from_der(public_der(key))
    kid = jwk_thumbprint(jwk)
    with pytest.raises(ValueError, match="thumbprint"):
        TrustedKey(
            kid="x" * 43,
            jwk=jwk,
            trust="repository_root",
            status="active",
            release_ids=(RELEASE_ID,),
        )
    with pytest.raises(ValueError, match="unique"):
        TrustedKey(
            kid=kid,
            jwk=jwk,
            trust="repository_root",
            status="active",
            release_ids=(RELEASE_ID, RELEASE_ID),
        )
    root = TrustedKey(
        kid=kid,
        jwk=jwk,
        trust="repository_root",
        status="active",
        release_ids=(RELEASE_ID,),
    )
    with pytest.raises(ReceiptVerificationError, match="duplicate keys"):
        TrustedKeyRegistry(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1",
                keys=(root, root),
                transitions=(),
            )
        )
    other_jwk = public_jwk_from_der(public_der(private_key(1)))
    other_root = root.model_copy(update={"kid": jwk_thumbprint(other_jwk), "jwk": other_jwk})
    with pytest.raises(ReceiptVerificationError, match="exactly one"):
        TrustedKeyRegistry(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1",
                keys=(root, other_root),
                transitions=(),
            )
        )
    missing = tmp_path / "missing.json"
    with pytest.raises(ReceiptPreflightError, match="unavailable"):
        TrustedKeyRegistry.load(missing)
    invalid = tmp_path / "invalid.json"
    invalid.write_bytes(canonical_bytes({"registry_version": "trusted-receipt-keys-v1"}))
    with pytest.raises(ReceiptVerificationError, match="schema"):
        TrustedKeyRegistry.load(invalid)
    retired = root.model_copy(update={"status": "retired"})
    retired_registry = TrustedKeyRegistry(
        TrustedKeyDocument(
            registry_version="trusted-receipt-keys-v1", keys=(retired,), transitions=()
        )
    )
    with pytest.raises(ReceiptVerificationError, match="not authorized"):
        retired_registry.resolve(kid, RELEASE_ID)


def test_kms_signer_rejects_uninitialized_configuration_and_all_response_faults() -> None:
    key = private_key()
    registry = root_registry(key)
    with pytest.raises(ReceiptPreflightError, match="required"):
        KmsReceiptSigner(FakeKms(key), "", RELEASE_ID, registry)
    signer = KmsReceiptSigner(FakeKms(key), "alias/recallops-receipt", RELEASE_ID, registry)
    for operation in (
        lambda: signer.kid,
        lambda: signer.public_jwk,
        lambda: signer.sign_manifest(manifest_for("k" * 43)),
        lambda: signer._sign_payload(b"{}", RECEIPT_TYP),
    ):
        with pytest.raises(ReceiptPreflightError, match="preflight"):
            operation()

    class FaultKms(FakeKms):
        response_update: dict[str, object] = {}
        get_error = False
        sign_error = False

        def get_public_key(self, **kwargs: object) -> dict[str, object]:
            if self.get_error:
                raise RuntimeError("kms unavailable")
            return super().get_public_key(**kwargs) | self.response_update

        def sign(self, **kwargs: object) -> dict[str, object]:
            if self.sign_error:
                raise RuntimeError("kms unavailable")
            return super().sign(**kwargs) | self.response_update

    for update, match in (
        ({"SigningAlgorithms": "ED25519_SHA_512"}, "does not support"),
        ({"SigningAlgorithms": b"ED25519_SHA_512"}, "does not support"),
        ({"PublicKey": "not-bytes"}, "DER bytes"),
        ({"KeyId": ""}, "key ARN"),
    ):
        client = FaultKms(key)
        client.response_update = update
        with pytest.raises(ReceiptPreflightError, match=match):
            KmsReceiptSigner(client, "alias/recallops-receipt", RELEASE_ID, registry).preflight()
    client = FaultKms(key)
    client.get_error = True
    with pytest.raises(ReceiptPreflightError, match="GetPublicKey"):
        KmsReceiptSigner(client, "alias/recallops-receipt", RELEASE_ID, registry).preflight()

    client = FaultKms(key)
    signer = KmsReceiptSigner(client, "alias/recallops-receipt", RELEASE_ID, registry)
    kid = signer.preflight()
    with pytest.raises(ReceiptPreflightError, match="manifest key"):
        signer.sign_manifest(manifest_for("x" * 43))
    for update, match in (
        ({"SigningAlgorithm": "wrong"}, "algorithm"),
        ({"KeyId": "wrong"}, "signing key"),
        ({"Signature": "not-bytes"}, "invalid Ed25519"),
        ({"Signature": b"short"}, "invalid Ed25519"),
    ):
        client.response_update = update
        with pytest.raises(ReceiptPreflightError, match=match):
            signer.sign_manifest(manifest_for(kid))
    client.response_update = {}
    client.sign_error = True
    with pytest.raises(ReceiptPreflightError, match="KMS Sign"):
        signer.sign_manifest(manifest_for(kid))


def test_causal_and_ledger_verification_rejects_each_structural_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digests = manifest_for(jwk_thumbprint(public_jwk_from_der(public_der(private_key())))).digests
    events = ledger_events()
    for update in (
        {"state_after": "OTHER"},
        {"object_type": "wrong"},
        {"object_digest": "f" * 64},
    ):
        changed = [
            event.model_copy(update=update) if index == 1 else event
            for index, event in enumerate(events)
        ]
        with pytest.raises(ReceiptVerificationError, match="causal binding"):
            receipts.verify_causal_bindings(changed, digests, "certify")
    with pytest.raises(ReceiptVerificationError, match="empty"):
        verify_ledger_prefix([])
    monkeypatch.setattr(receipts, "verify_event", lambda *args: True)
    mutations = (
        (1, {"outcome": "denied"}, "non-authority"),
        (1, {"epoch_after": 9}, "epoch is not contiguous"),
        (2, {"epoch_before": 8, "epoch_after": 9}, "epochs contain a gap"),
    )
    for index, update, match in mutations:
        changed = list(events)
        changed[index] = changed[index].model_copy(update=update)
        with pytest.raises(ReceiptVerificationError, match=match):
            verify_ledger_prefix(changed)
    no_reviewer = [
        event.model_copy(update={"actor_role": "system", "channel": RequestChannel.SYSTEM})
        if event.actor_role == "reviewer"
        else event
        for event in events
    ]
    with pytest.raises(ReceiptVerificationError, match="stable operator and reviewer"):
        verify_ledger_prefix(no_reviewer)
    same_subject = list(events)
    same_subject[-1] = same_subject[-1].model_copy(update={"actor_subject": "operator-42"})
    with pytest.raises(ReceiptVerificationError, match="independent operator"):
        verify_ledger_prefix(same_subject)


def direct_jws(key: Ed25519PrivateKey, kid: str, payload: object, typ: str = RECEIPT_TYP) -> str:
    payload_bytes = canonical_bytes(payload)
    signing_input = jws_signing_input(payload_bytes, kid, typ)
    return f"{signing_input.decode()}.{b64url(key.sign(signing_input))}"


def test_compact_and_receipt_verifiers_reject_every_schema_and_binding_class() -> None:
    key = private_key()
    registry = root_registry(key)
    kid = jwk_thumbprint(public_jwk_from_der(public_der(key)))
    manifest = manifest_for(kid)
    with pytest.raises(ReceiptVerificationError, match="three segments"):
        receipts._verify_compact(
            "two.parts",
            registry.resolve(kid, RELEASE_ID).jwk,
            expected_kid=kid,
            expected_typ=RECEIPT_TYP,
        )
    for compact, match in (
        (direct_jws(key, kid, manifest.model_dump(mode="json"), "wrong-type"), "protected header"),
        (
            f"{b64url(canonical_bytes(receipts._protected_header(kid, RECEIPT_TYP)))}."
            f"{b64url(canonical_bytes(manifest.model_dump(mode='json')))}.{b64url(b'x')}",
            "64 bytes",
        ),
        (direct_jws(key, kid, ["not-object"]), "canonical JSON object"),
    ):
        with pytest.raises(ReceiptVerificationError, match=match):
            receipts._verify_compact(
                compact,
                registry.resolve(kid, RELEASE_ID).jwk,
                expected_kid=kid,
                expected_typ=RECEIPT_TYP,
            )
    with pytest.raises(ReceiptVerificationError, match="three segments"):
        verify_receipt_jws("bad", registry, release_id=RELEASE_ID)
    protected_list = direct_jws(key, kid, manifest.model_dump(mode="json")).split(".")
    protected_list[0] = b64url(canonical_bytes(["not-object"]))
    with pytest.raises(ReceiptVerificationError, match="protected header"):
        verify_receipt_jws(".".join(protected_list), registry, release_id=RELEASE_ID)
    no_kid = canonical_bytes({"alg": "Ed25519", "typ": RECEIPT_TYP, "v": 1})
    parts = direct_jws(key, kid, manifest.model_dump(mode="json")).split(".")
    parts[0] = b64url(no_kid)
    with pytest.raises(ReceiptVerificationError, match="no valid kid"):
        verify_receipt_jws(".".join(parts), registry, release_id=RELEASE_ID)
    with pytest.raises(ReceiptVerificationError, match="schema"):
        verify_receipt_jws(direct_jws(key, kid, {"x": 1}), registry, release_id=RELEASE_ID)
    uppercase = manifest.model_dump(mode="json")
    uppercase["run_id"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
    with pytest.raises(ReceiptVerificationError, match="canonical manifest"):
        verify_receipt_jws(direct_jws(key, kid, uppercase), registry, release_id=RELEASE_ID)
    wrong_binding = manifest.model_copy(update={"key_thumbprint": "x" * 43})
    with pytest.raises(ReceiptVerificationError, match="trust binding"):
        verify_receipt_jws(
            direct_jws(key, kid, wrong_binding.model_dump(mode="json")),
            registry,
            release_id=RELEASE_ID,
        )


def test_release_statement_verifier_rejects_profile_schema_and_binding() -> None:
    key = private_key()
    registry = root_registry(key)
    kid = jwk_thumbprint(public_jwk_from_der(public_der(key)))
    identity = ReleaseIdentity(
        release_id=RELEASE_ID,
        source_sha=SOURCE_SHA,
        image_digest=f"sha256:{'b' * 64}",
        capability_policy_version="webmcp-capability-v1",
        receipt_policy_version="authority-receipt-policy-v1",
        evaluation_version="governed-benchmark-v1",
        receipt_key_thumbprint=kid,
    )
    statement = receipts.ReleaseStatement(
        identity=identity,
        live_proof_complete=False,
        live_proof_artifact_digest="a" * 64,
        assurance_complete=False,
        assurance_artifact_digest="b" * 64,
        release_ready=False,
    )
    with pytest.raises(ReceiptVerificationError, match="three segments"):
        verify_release_statement_jws("bad", registry, release_id=RELEASE_ID)
    payload = canonical_bytes(statement.model_dump(mode="json"))
    protected = canonical_bytes(
        {"alg": "EdDSA", "kid": kid, "typ": receipts.RELEASE_STATEMENT_TYP, "v": 1}
    )
    signing_input = f"{b64url(protected)}.{b64url(payload)}".encode()
    wrong = f"{signing_input.decode()}.{b64url(key.sign(signing_input))}"
    with pytest.raises(ReceiptVerificationError, match="Ed25519 profile"):
        verify_release_statement_jws(wrong, registry, release_id=RELEASE_ID)
    with pytest.raises(ReceiptVerificationError, match="schema"):
        verify_release_statement_jws(
            direct_jws(key, kid, {"x": 1}, receipts.RELEASE_STATEMENT_TYP),
            registry,
            release_id=RELEASE_ID,
        )
    wrong_binding = statement.model_copy(
        update={"identity": identity.model_copy(update={"release_id": "other-release"})}
    )
    with pytest.raises(ReceiptVerificationError, match="trust binding"):
        verify_release_statement_jws(
            direct_jws(
                key,
                kid,
                wrong_binding.model_dump(mode="json"),
                receipts.RELEASE_STATEMENT_TYP,
            ),
            registry,
            release_id=RELEASE_ID,
        )


def test_registry_transition_and_file_guards_cover_ambiguous_edges(tmp_path: Path) -> None:
    old_key, new_key = private_key(), private_key(1)
    old_jwk, new_jwk = (
        public_jwk_from_der(public_der(old_key)),
        public_jwk_from_der(public_der(new_key)),
    )
    old_kid, new_kid = jwk_thumbprint(old_jwk), jwk_thumbprint(new_jwk)
    root = TrustedKey(
        kid=old_kid,
        jwk=old_jwk,
        trust="repository_root",
        status="retired",
        release_ids=("old-release",),
    )
    successor = TrustedKey(
        kid=new_kid,
        jwk=new_jwk,
        trust="transition",
        status="active",
        release_ids=(RELEASE_ID,),
    )
    payload = canonical_bytes(
        {
            "from_kid": old_kid,
            "to_jwk_digest": "f" * 64,
            "to_kid": new_kid,
            "transition_version": "receipt-key-transition-v1",
        }
    )
    signing_input = jws_signing_input(payload, old_kid, TRANSITION_TYP)
    transition = KeyTransition(
        from_kid=old_kid,
        to_kid=new_kid,
        transition_jws=f"{signing_input.decode()}.{b64url(old_key.sign(signing_input))}",
    )
    with pytest.raises(ReceiptVerificationError, match="multiple predecessor"):
        TrustedKeyRegistry(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1",
                keys=(root, successor),
                transitions=(transition, transition),
            )
        )
    with pytest.raises(ReceiptVerificationError, match="does not bind"):
        TrustedKeyRegistry(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1",
                keys=(root, successor),
                transitions=(transition,),
            )
        )
    unused = KeyTransition(
        from_kid=old_kid,
        to_kid=old_kid,
        transition_jws="x" * 64,
    )
    with pytest.raises(ReceiptVerificationError, match="unused transition"):
        TrustedKeyRegistry(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1",
                keys=(root,),
                transitions=(unused,),
            )
        )
    path = tmp_path / "valid-keys.json"
    path.write_bytes(
        canonical_bytes(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1", keys=(), transitions=()
            ).model_dump(mode="json")
        )
    )
    assert TrustedKeyRegistry.load(path).document.keys == ()


def test_kms_preflight_rejects_registry_key_material_mismatch() -> None:
    key = private_key()
    other_jwk = public_jwk_from_der(public_der(private_key(1)))

    class MismatchedRegistry:
        def resolve(self, kid: str, release_id: str):
            return type("Pinned", (), {"jwk": other_jwk})()

    signer = KmsReceiptSigner(
        FakeKms(key),
        "alias/recallops-receipt",
        RELEASE_ID,
        MismatchedRegistry(),  # type: ignore[arg-type]
    )
    with pytest.raises(ReceiptPreflightError, match="differs"):
        signer.preflight()


def test_release_statement_requires_string_kid() -> None:
    key = private_key()
    registry = root_registry(key)
    header = canonical_bytes(
        {"alg": "Ed25519", "kid": 1, "typ": receipts.RELEASE_STATEMENT_TYP, "v": 1}
    )
    payload = canonical_bytes({"x": 1})
    signing_input = f"{b64url(header)}.{b64url(payload)}".encode()
    compact = f"{signing_input.decode()}.{b64url(key.sign(signing_input))}"
    with pytest.raises(ReceiptVerificationError, match="no valid kid"):
        verify_release_statement_jws(compact, registry, release_id=RELEASE_ID)


def test_production_preflight_and_cli_are_fail_closed_and_report_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from types import SimpleNamespace

    import recallops.config as config

    monkeypatch.setattr(
        config,
        "Settings",
        lambda: SimpleNamespace(
            receipt_kms_key_id=None,
            receipt_release_id=None,
            receipt_trusted_keys_json=None,
        ),
    )
    with pytest.raises(ReceiptPreflightError, match="required"):
        receipts.production_preflight()

    settings = SimpleNamespace(
        receipt_kms_key_id="alias/key",
        receipt_release_id=RELEASE_ID,
        receipt_trusted_keys_path=Path("keys.json"),
        receipt_trusted_keys_json=None,
        aws_region="eu-west-1",
    )
    monkeypatch.setattr(config, "Settings", lambda: settings)
    sentinel_registry = root_registry(private_key())
    monkeypatch.setattr(receipts.TrustedKeyRegistry, "load", lambda path: sentinel_registry)
    monkeypatch.setattr("boto3.client", lambda name, region_name: object())

    class Signer:
        def __init__(self, client: object, key: str, release: str, registry: object) -> None:
            assert key == "alias/key" and release == RELEASE_ID

        def preflight(self) -> str:
            return "K" * 43

        def signing_preflight(self) -> str:
            return "protected.payload.signature"

    monkeypatch.setattr(receipts, "KmsReceiptSigner", Signer)
    assert receipts.production_preflight() == "K" * 43
    registry_json = (
        '{"keys":[],"registry_version":"trusted-receipt-keys-v1","transitions":[]}'
    )
    settings.receipt_trusted_keys_json = SimpleNamespace(
        get_secret_value=lambda: registry_json
    )
    monkeypatch.setattr(
        receipts.TrustedKeyRegistry, "from_bytes", lambda value: sentinel_registry
    )
    assert receipts.production_preflight() == "K" * 43
    monkeypatch.setattr(receipts, "production_preflight", lambda: "K" * 43)
    receipts.main()
    assert "preflight passed" in capsys.readouterr().out
    monkeypatch.setattr(
        receipts,
        "production_preflight",
        lambda: (_ for _ in ()).throw(ReceiptPreflightError("closed")),
    )
    with pytest.raises(SystemExit, match="preflight failed"):
        receipts.main()
