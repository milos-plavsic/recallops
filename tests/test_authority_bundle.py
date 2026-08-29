import base64
import io
import json
import subprocess
import zipfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import recallops.authority_bundle as authority_bundle
from recallops.authority_bundle import (
    ALLOWED_PATHS,
    AUXILIARY_PATHS,
    BUNDLE_DIGEST_DOMAIN,
    BundleError,
    FrozenRelease,
    build_authority_bundle,
    parse_checksums,
    prepare_evidence,
    sha256_bytes,
    validate_bundle_files,
)
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
    AWS_SIGNING_ALGORITHM,
    TRANSITION_TYP,
    KeyTransition,
    KmsReceiptSigner,
    ReceiptBuildContext,
    ReceiptDigestBindings,
    ReceiptError,
    ReceiptVerificationError,
    ReleaseBinding,
    TrustedKey,
    TrustedKeyDocument,
    TrustedKeyRegistry,
    build_manifest,
    jwk_thumbprint,
    jws_signing_input,
    public_jwk_from_der,
    transition_binding_digest,
)
from recallops.workflow import CAPABILITIES, RequestChannel, WorkflowState

RUN_ID = UUID("20000000-0000-0000-0000-000000000042")
WORKFLOW_ID = UUID("30000000-0000-0000-0000-000000000042")
SOURCE_SHA = "a" * 40
RELEASE_ID = "release-bundle-vector-v1"
IMAGE_DIGEST = f"sha256:{'b' * 64}"
PSEUDONYM_KEY = b"bundle-subject-pseudonym-key-32b"
README = b"""# RecallOps authority bundle

Verify offline with the repository-pinned key registry:

    node tools/verify-authority-bundle.mjs <bundle-directory> --registry <trusted-keys.json>

The receipt proves integrity and the supplied accepted authority prefix. It does not prove
external truth, physical human identity, trusted time, completeness of denied attempts, or
production-remediation safety. The scenario and evaluation are synthetic.
"""


def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


def public_der(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class FakeKms:
    key_id = "arn:aws:kms:us-east-1:111122223333:key/bundle-vector"

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self.key = key

    def get_public_key(self, **kwargs: object) -> dict[str, object]:
        assert kwargs == {"KeyId": "alias/recallops-bundle-vector"}
        return {
            "KeyId": self.key_id,
            "KeySpec": AWS_KEY_SPEC,
            "KeyUsage": AWS_KEY_USAGE,
            "SigningAlgorithms": [AWS_SIGNING_ALGORITHM],
            "PublicKey": public_der(self.key),
        }

    def sign(self, **kwargs: object) -> dict[str, object]:
        message = kwargs["Message"]
        assert isinstance(message, bytes)
        return {
            "KeyId": self.key_id,
            "SigningAlgorithm": AWS_SIGNING_ALGORITHM,
            "Signature": self.key.sign(message),
        }


def registry(key: Ed25519PrivateKey) -> TrustedKeyRegistry:
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
                    release_ids=(RELEASE_ID,),
                ),
            ),
            transitions=(),
        )
    )


def receipt_digests() -> ReceiptDigestBindings:
    return ReceiptDigestBindings(
        proposal="1" * 64,
        execution="2" * 64,
        observation="3" * 64,
        assessment="4" * 64,
        policy_verdict="5" * 64,
        memory="6" * 64,
        review="7" * 64,
    )


def events_for(
    digests: ReceiptDigestBindings, disposition: str = "certify"
) -> list[AuthorityEvent]:
    disposition_digest = sha256_bytes(disposition.encode())
    steps = (
        ("system", "allocator", "ABSENT", "INVESTIGATING", None, None),
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
            "observer",
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
                    "disposition": disposition_digest,
                    "memory": digests.memory,
                    "review": digests.review,
                },
            ),
        ),
    )
    previous = ZERO_EVENT_HASH
    events: list[AuthorityEvent] = []
    for index, (role, subject, before, after, object_type, object_digest) in enumerate(
        steps, start=1
    ):
        before_capabilities = () if before == "ABSENT" else CAPABILITIES[WorkflowState(before)]
        event = AuthorityEvent(
            event_id=UUID(f"40000000-0000-0000-0000-{index:012d}"),
            run_id=RUN_ID,
            tenant_id="judge-bundle-vector",
            sequence=index,
            recorded_at=datetime(2026, 8, 29, 4, 0, index, tzinfo=UTC),
            event_type="RUN_GENESIS" if index == 1 else f"{before}_TO_{after}",
            actor_subject=subject,
            actor_role=role,  # type: ignore[arg-type]
            channel=(
                RequestChannel.SYSTEM
                if role == "system"
                else RequestChannel.WEBMCP
                if role == "agent"
                else RequestChannel.UI
            ),
            workflow_id=WORKFLOW_ID,
            epoch_before=index - 1,
            epoch_after=index,
            state_before=before,
            state_after=after,
            capabilities_before=before_capabilities,
            capabilities_after=CAPABILITIES[WorkflowState(after)],
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


def rechain(events: list[AuthorityEvent]) -> list[AuthorityEvent]:
    previous = ZERO_EVENT_HASH
    result: list[AuthorityEvent] = []
    for event in events:
        candidate = event.model_copy(
            update={"previous_event_hash": previous, "event_hash": ZERO_EVENT_HASH}
        )
        candidate = candidate.model_copy(
            update={
                "event_hash": authority_event_hash(previous, canonical_event_payload(candidate))
            }
        )
        result.append(candidate)
        previous = candidate.event_hash
    return result


def make_bundle(
    *,
    disposition: str = "certify",
    mutate_events: Callable[[list[AuthorityEvent]], list[AuthorityEvent]] | None = None,
    mutate_capability_policy: Callable[[dict[str, object]], None] | None = None,
):
    key = private_key()
    trusted = registry(key)
    jwk = public_jwk_from_der(public_der(key))
    kid = jwk_thumbprint(jwk)
    digests = receipt_digests()
    claims = {
        "claims": [
            {
                "claim_id": "authority.webmcp-boundary",
                "scope": "server-authoritative WebMCP capability policy",
                "status": "verified-synthetic",
            }
        ],
        "schema_version": "claim-registry-v1",
    }
    claim_digest = sha256_bytes(canonical_bytes(claims))
    release = FrozenRelease(
        release_id=RELEASE_ID,
        source_sha=SOURCE_SHA,
        image_digest=IMAGE_DIGEST,
        capability_policy_version="webmcp-capability-v1",
        receipt_policy_version="authority-receipt-policy-v1",
        evaluation_version="governed-benchmark-v1",
        claim_registry_digest=claim_digest,
        receipt_key_thumbprint=kid,
    )
    events = events_for(digests, disposition)
    if mutate_events is not None:
        events = rechain(mutate_events(events))
    capability_policy = {
        "capabilities": {state.value: list(CAPABILITIES[state]) for state in WorkflowState},
        "policy_version": "webmcp-capability-v1",
        "protected_transitions": ["approve", "execute", "review"],
    }
    if mutate_capability_policy is not None:
        mutate_capability_policy(capability_policy)
    receipt_policy = {
        "algorithm": "Ed25519",
        "policy_version": "authority-receipt-policy-v1",
        "trust_anchor": "repository-pinned",
    }
    evaluation_case = {
        "case_id": "checkout-latency-42",
        "evaluation_version": "governed-benchmark-v1",
        "synthetic": True,
    }
    evaluation_result = {
        "case_id": "checkout-latency-42",
        "evaluation_version": "governed-benchmark-v1",
        "result": "unsafe-similarity-shortcut-rejected",
        "synthetic": True,
    }
    prepared = prepare_evidence(
        public_jwk=jwk,
        events=events,
        capability_policy=capability_policy,
        receipt_policy=receipt_policy,
        evaluation_case=evaluation_case,
        evaluation_result=evaluation_result,
        release=release,
        claims=claims,
    )
    manifest = build_manifest(
        events,
        digests,
        ReceiptBuildContext(
            receipt_policy_version=release.receipt_policy_version,
            scenario_version="checkout-latency-v1",
            final_disposition=disposition,
            release=ReleaseBinding(
                release_id=release.release_id,
                source_sha=release.source_sha,
                image_digest=release.image_digest,
                evaluation_version=release.evaluation_version,
                claim_registry_digest=release.claim_registry_digest,
            ),
            evidence_index_digest=prepared.index_digest,
            asserted_signing_time="2026-08-29T04:01:00Z",
            expires_at="2026-09-05T04:01:00Z",
            key_thumbprint=kid,
        ),
        subject_pseudonym_key=PSEUDONYM_KEY,
    )
    signer = KmsReceiptSigner(FakeKms(key), "alias/recallops-bundle-vector", RELEASE_ID, trusted)
    signer.preflight()
    jws = signer.sign_manifest(manifest)
    bundle = build_authority_bundle(
        manifest=manifest,
        receipt_jws=jws,
        public_jwk=jwk,
        events=events,
        capability_policy=capability_policy,
        receipt_policy=receipt_policy,
        evaluation_case=evaluation_case,
        evaluation_result=evaluation_result,
        release=release,
        claims=claims,
        trusted_keys=trusted,
        readme=README,
    )
    return bundle, trusted


def write_vector(root: Path, files: dict[str, bytes] | object) -> None:
    for path, content in dict(files).items():  # type: ignore[arg-type]
        destination = root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(content)


def write_registry(path: Path, trusted: TrustedKeyRegistry) -> None:
    path.write_bytes(canonical_bytes(trusted.document.model_dump(mode="json")))


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def run_verifier(root: Path, registry_path: Path, digest: str | None = None):
    command = [
        "node",
        "tools/verify-authority-bundle.mjs",
        str(root),
        "--registry",
        str(registry_path),
    ]
    if digest is not None:
        command.extend(["--bundle-digest", digest])
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    return result, json.loads(result.stdout)


def test_bundle_digest_graph_is_acyclic_and_zip_is_deterministic() -> None:
    bundle, _ = make_bundle()
    assert set(bundle.files) == ALLOWED_PATHS
    assert set(parse_checksums(bundle.files["checksums.sha256"])) == ALLOWED_PATHS - {
        "checksums.sha256"
    }
    assert set(item.path for item in prepare_index(bundle).entries) == set(AUXILIARY_PATHS)
    assert validate_bundle_files(bundle.files) == bundle.bundle_digest
    assert bundle.bundle_digest == sha256_bytes(
        BUNDLE_DIGEST_DOMAIN + bundle.files["checksums.sha256"]
    )
    assert bundle.deterministic_zip() == bundle.deterministic_zip()


def prepare_index(bundle):
    from recallops.authority_bundle import EvidenceIndex

    return EvidenceIndex.model_validate(json.loads(bundle.files["evidence-index.jcs.json"]))


def test_network_free_node_verifier_accepts_valid_bundle(tmp_path: Path) -> None:
    bundle, trusted = make_bundle()
    vector = tmp_path / "valid"
    write_vector(vector, bundle.files)
    registry_path = tmp_path / "trusted-keys.json"
    write_registry(registry_path, trusted)
    result, report = run_verifier(vector, registry_path, bundle.bundle_digest)
    assert result.returncode == 0, result.stdout + result.stderr
    assert report == {
        "ok": True,
        "code": "VERIFIED",
        "verifier": "authority-bundle-verifier-v1",
        "bundle_digest": bundle.bundle_digest,
        "event_count": 7,
        "release_id": RELEASE_ID,
    }


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    [
        ("content", "E_CHECKSUM_MISMATCH"),
        ("missing", "E_FILE_SET"),
        ("signature", "E_SIGNATURE"),
        ("index", "E_INDEX_BINDING"),
        ("key", "E_KEY_BINDING"),
        ("external_digest", "E_BUNDLE_DIGEST"),
        ("duplicate_json", "E_JSON_DUPLICATE"),
        ("unpaired_surrogate", "E_IJSON"),
    ],
)
def test_node_verifier_rejects_material_tampering_with_stable_codes(
    tmp_path: Path, mutation: str, expected_code: str
) -> None:
    bundle, trusted = make_bundle()
    files = dict(bundle.files)
    digest = bundle.bundle_digest
    if mutation == "content":
        files["claims.json"] = files["claims.json"].replace(
            b"verified-synthetic", b"tampered-synthetic"
        )
    elif mutation == "missing":
        files.pop("claims.json")
    elif mutation == "signature":
        encoded = files["receipt.jws"].decode()
        protected, payload, signature = encoded.split(".")
        signature = ("A" if signature[0] != "A" else "B") + signature[1:]
        files["receipt.jws"] = f"{protected}.{payload}.{signature}".encode()
        rewrite_checksums(files)
        digest = sha256_bytes(BUNDLE_DIGEST_DOMAIN + files["checksums.sha256"])
    elif mutation == "index":
        parsed = json.loads(files["evidence-index.jcs.json"])
        parsed["entries"][0]["size"] += 1
        files["evidence-index.jcs.json"] = canonical_bytes(parsed)
        rewrite_checksums(files)
        digest = sha256_bytes(BUNDLE_DIGEST_DOMAIN + files["checksums.sha256"])
    elif mutation == "key":
        replacement = public_jwk_from_der(
            public_der(Ed25519PrivateKey.from_private_bytes(b"x" * 32))
        )
        files["public.jwk.json"] = canonical_bytes(replacement)
        rewrite_checksums(files)
        digest = sha256_bytes(BUNDLE_DIGEST_DOMAIN + files["checksums.sha256"])
    elif mutation in {"duplicate_json", "unpaired_surrogate"}:
        files["manifest.jcs.json"] = (
            b'{"x":1,"x":2}' if mutation == "duplicate_json" else b'{"x":"\\ud800"}'
        )
        rewrite_checksums(files)
        digest = sha256_bytes(BUNDLE_DIGEST_DOMAIN + files["checksums.sha256"])
    else:
        digest = "f" * 64
    vector = tmp_path / mutation
    write_vector(vector, files)
    registry_path = tmp_path / "trusted-keys.json"
    write_registry(registry_path, trusted)
    result, report = run_verifier(vector, registry_path, digest)
    assert result.returncode == 1
    assert report["ok"] is False and report["code"] == expected_code


def rewrite_checksums(files: dict[str, bytes]) -> None:
    files["checksums.sha256"] = "".join(
        f"{sha256_bytes(files[path])}  {path}\n"
        for path in sorted(ALLOWED_PATHS - {"checksums.sha256"})
    ).encode()


def test_builder_rejects_release_claim_index_and_readme_mismatches() -> None:
    bundle, _ = make_bundle()
    with pytest.raises(BundleError, match="checksum mismatch"):
        validate_bundle_files({**bundle.files, "claims.json": b"{}"})
    with pytest.raises(ReceiptError, match="unknown transition"):
        transition_binding_digest("unknown", {"x": "1" * 64})


@pytest.mark.parametrize(
    ("vector", "expected_code"),
    [
        ("actor_authority", "E_ACTOR_AUTHORITY"),
        ("capability", "E_CAPABILITY_POLICY"),
        ("policy", "E_POLICY_BINDING"),
        ("disposition", "E_DISPOSITION"),
    ],
)
def test_signed_but_policy_invalid_vectors_fail_semantically(
    tmp_path: Path, vector: str, expected_code: str
) -> None:
    def mutate_events(events: list[AuthorityEvent]) -> list[AuthorityEvent]:
        if vector == "actor_authority":
            events[0] = events[0].model_copy(
                update={
                    "actor_role": "agent",
                    "actor_subject": "agent-42",
                    "channel": RequestChannel.WEBMCP,
                }
            )
        elif vector == "capability":
            bad = ("inspect_incident", "protected_override")
            events[0] = events[0].model_copy(update={"capabilities_after": bad})
            events[1] = events[1].model_copy(update={"capabilities_before": bad})
        return events

    def mutate_policy(policy: dict[str, object]) -> None:
        if vector == "policy":
            capabilities = policy["capabilities"]
            assert isinstance(capabilities, dict)
            capabilities["INVESTIGATING"] = ["inspect_incident", "protected_override"]

    bundle, trusted = make_bundle(
        disposition="activate" if vector == "disposition" else "certify",
        mutate_events=mutate_events if vector in {"actor_authority", "capability"} else None,
        mutate_capability_policy=mutate_policy if vector == "policy" else None,
    )
    root = tmp_path / vector
    write_vector(root, bundle.files)
    registry_path = tmp_path / "trusted-keys.json"
    write_registry(registry_path, trusted)
    result, report = run_verifier(root, registry_path, bundle.bundle_digest)
    assert result.returncode == 1
    assert report["code"] == expected_code


def test_bundle_builder_refuses_to_sign_around_a_broken_causal_binding() -> None:
    def break_review(events: list[AuthorityEvent]) -> list[AuthorityEvent]:
        events[-1] = events[-1].model_copy(update={"object_digest": "f" * 64})
        return events

    with pytest.raises(ReceiptVerificationError, match="exact review_binding"):
        make_bundle(mutate_events=break_review)


def test_node_verifier_requires_and_accepts_predecessor_signed_key_rotation(
    tmp_path: Path,
) -> None:
    bundle, _ = make_bundle()
    root = tmp_path / "bundle"
    write_vector(root, bundle.files)
    old_key = Ed25519PrivateKey.from_private_bytes(b"x" * 32)
    current_key = private_key()
    old_jwk = public_jwk_from_der(public_der(old_key))
    current_jwk = public_jwk_from_der(public_der(current_key))
    old_kid, current_kid = jwk_thumbprint(old_jwk), jwk_thumbprint(current_jwk)
    keys = (
        TrustedKey(
            kid=old_kid,
            jwk=old_jwk,
            trust="repository_root",
            status="retired",
            release_ids=("predecessor-release",),
        ),
        TrustedKey(
            kid=current_kid,
            jwk=current_jwk,
            trust="transition",
            status="active",
            release_ids=(RELEASE_ID,),
        ),
    )
    missing = tmp_path / "missing-transition.json"
    missing.write_bytes(
        canonical_bytes(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1",
                keys=keys,
                transitions=(),
            ).model_dump(mode="json")
        )
    )
    result, report = run_verifier(root, missing, bundle.bundle_digest)
    assert result.returncode == 1 and report["code"] == "E_TRUST_TRANSITION"

    transition_payload = canonical_bytes(
        {
            "from_kid": old_kid,
            "to_jwk_digest": content_digest("recallops-public-jwk-v1", current_jwk),
            "to_kid": current_kid,
            "transition_version": "receipt-key-transition-v1",
        }
    )
    signing_input = jws_signing_input(transition_payload, old_kid, TRANSITION_TYP)
    transition = f"{signing_input.decode()}.{b64url(old_key.sign(signing_input))}"
    rotated = tmp_path / "valid-transition.json"
    rotated.write_bytes(
        canonical_bytes(
            TrustedKeyDocument(
                registry_version="trusted-receipt-keys-v1",
                keys=keys,
                transitions=(
                    KeyTransition(
                        from_kid=old_kid,
                        to_kid=current_kid,
                        transition_jws=transition,
                    ),
                ),
            ).model_dump(mode="json")
        )
    )
    result, report = run_verifier(root, rotated, bundle.bundle_digest)
    assert result.returncode == 0 and report["code"] == "VERIFIED"


def test_bundle_models_and_file_guards_reject_nonfrozen_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        authority_bundle.EvidenceIndexEntry(path="other.json", sha256="a" * 64, size=1)
    entries = tuple(
        authority_bundle.EvidenceIndexEntry(path=path, sha256="a" * 64, size=1)
        for path in reversed(AUXILIARY_PATHS)
    )
    with pytest.raises(ValueError, match="frozen order"):
        authority_bundle.EvidenceIndex(entries=entries)
    with pytest.raises(BundleError, match="event prefix"):
        authority_bundle.canonical_event_lines([])
    monkeypatch.setattr(authority_bundle, "canonical_bytes", lambda value: b"bad\nline")
    with pytest.raises(BundleError, match="line separator"):
        authority_bundle.canonical_event_lines(events_for(receipt_digests())[:1])
    for path, value in (("unknown", b"x"), ("README.md", b"")):
        with pytest.raises(BundleError, match="bundle (path|file)"):
            authority_bundle._safe_file(path, value)
    with pytest.raises(BundleError, match="invalid size"):
        authority_bundle._safe_file("README.md", b"x" * (authority_bundle.MAX_FILE_BYTES + 1))
    with pytest.raises(BundleError, match="cover itself"):
        authority_bundle._checksum_file({"checksums.sha256": b"x"})


def test_bundle_builder_rejects_each_outer_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    bundle, trusted = make_bundle()
    manifest = authority_bundle.ReceiptManifest.model_validate(
        json.loads(bundle.files["manifest.jcs.json"])
    )
    release = FrozenRelease.model_validate(json.loads(bundle.files["release.json"]))
    public_jwk = json.loads(bundle.files["public.jwk.json"])
    jws = bundle.files["receipt.jws"].decode()

    with pytest.raises(BundleError, match="public key"):
        authority_bundle._validate_receipt_and_release(
            manifest,
            jws,
            {**public_jwk, "x": base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()},
            release,
            trusted,
        )
    monkeypatch.setattr(
        authority_bundle,
        "verify_receipt_jws",
        lambda *args, **kwargs: manifest.model_copy(update={"final_disposition": "reject"}),
    )
    with pytest.raises(BundleError, match="payload differs"):
        authority_bundle._validate_receipt_and_release(manifest, jws, public_jwk, release, trusted)
    monkeypatch.setattr(authority_bundle, "verify_receipt_jws", lambda *a, **k: manifest)
    with pytest.raises(BundleError, match="frozen release"):
        authority_bundle._validate_receipt_and_release(
            manifest,
            jws,
            public_jwk,
            release.model_copy(update={"evaluation_version": "different-v1"}),
            trusted,
        )


def test_prepare_and_build_reject_claim_readme_index_and_layout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, trusted = make_bundle()
    manifest = authority_bundle.ReceiptManifest.model_validate(
        json.loads(bundle.files["manifest.jcs.json"])
    )
    release = FrozenRelease.model_validate(json.loads(bundle.files["release.json"]))
    public_jwk = json.loads(bundle.files["public.jwk.json"])
    events = [
        AuthorityEvent.model_validate(json.loads(line))
        for line in bundle.files["events.ndjson"].splitlines()
    ]
    common = {
        "public_jwk": public_jwk,
        "events": events,
        "capability_policy": json.loads(bundle.files["policy/capability-policy.json"]),
        "receipt_policy": json.loads(bundle.files["policy/receipt-policy.json"]),
        "evaluation_case": json.loads(bundle.files["evaluation/case.json"]),
        "evaluation_result": json.loads(bundle.files["evaluation/result.json"]),
        "release": release,
        "claims": json.loads(bundle.files["claims.json"]),
    }
    with pytest.raises(BundleError, match="claim registry"):
        prepare_evidence(**{**common, "claims": {"claims": []}})
    with pytest.raises(BundleError, match="README"):
        build_authority_bundle(
            manifest=manifest,
            receipt_jws=bundle.files["receipt.jws"].decode(),
            trusted_keys=trusted,
            readme=b"wrong",
            **common,
        )
    with pytest.raises(BundleError, match="evidence index"):
        build_authority_bundle(
            manifest=manifest.model_copy(update={"evidence_index_digest": "f" * 64}),
            receipt_jws=bundle.files["receipt.jws"].decode(),
            trusted_keys=trusted,
            readme=README,
            **common,
        )
    original_checksum = authority_bundle._checksum_file

    def add_extra(files: dict[str, bytes]) -> bytes:
        result = original_checksum(files)
        files["unexpected"] = b"x"
        return result

    monkeypatch.setattr(authority_bundle, "_checksum_file", add_extra)
    with pytest.raises(BundleError, match="file set"):
        build_authority_bundle(
            manifest=manifest,
            receipt_jws=bundle.files["receipt.jws"].decode(),
            trusted_keys=trusted,
            readme=README,
            **common,
        )


@pytest.mark.parametrize(
    "value,match",
    [
        (b"\xff", "not ASCII"),
        (b"bad\n", "invalid syntax"),
        ((f"{'a' * 64}  checksums.sha256\n").encode(), "forbidden path"),
        ((f"{'a' * 64}  README.md\n" * 2).encode(), "duplicate"),
        ((f"{'a' * 64}  README.md\n").encode(), "path set or ordering"),
    ],
)
def test_checksum_parser_rejects_every_malformed_class(value: bytes, match: str) -> None:
    with pytest.raises(BundleError, match=match):
        parse_checksums(value)


def test_outer_validation_rejects_file_set_and_noncanonical_index() -> None:
    bundle, _ = make_bundle()
    missing = dict(bundle.files)
    missing.pop("README.md")
    with pytest.raises(BundleError, match="file set"):
        validate_bundle_files(missing)
    malformed = dict(bundle.files)
    malformed["evidence-index.jcs.json"] = b"{}"
    rewrite_checksums(malformed)
    with pytest.raises(BundleError, match="strict canonical"):
        validate_bundle_files(malformed)


def test_zip_reader_rejects_size_count_members_and_parser_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(BundleError, match="invalid size"):
        authority_bundle.read_bundle_zip(b"")
    with pytest.raises(BundleError, match="valid ZIP"):
        authority_bundle.read_bundle_zip(b"not-a-zip")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("README.md", b"x")
    with pytest.raises(BundleError, match="member count"):
        authority_bundle.read_bundle_zip(output.getvalue())

    bundle, _ = make_bundle()
    original_limit = authority_bundle.MAX_BUNDLE_BYTES
    monkeypatch.setattr(authority_bundle, "MAX_BUNDLE_BYTES", 1)
    with pytest.raises(BundleError, match="exceeds size"):
        bundle.deterministic_zip()
    with pytest.raises(BundleError, match="invalid size"):
        authority_bundle.read_bundle_zip(b"xx")
    monkeypatch.setattr(authority_bundle, "MAX_BUNDLE_BYTES", original_limit)


@pytest.mark.parametrize("fault", ["forbidden", "size", "compressed", "mode"])
def test_zip_reader_rejects_each_member_metadata_class(
    fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Member:
        def __init__(self, name: str) -> None:
            self.filename = name
            self.file_size = 1
            self.compress_size = 1
            self.external_attr = 0o100644 << 16

        def is_dir(self) -> bool:
            return False

    members = [Member(path) for path in sorted(ALLOWED_PATHS)]
    if fault == "forbidden":
        members[0].filename = "forbidden"
    elif fault == "size":
        members[0].file_size = 0
    elif fault == "compressed":
        members[0].compress_size = authority_bundle.MAX_FILE_BYTES + 1
    else:
        members[0].external_attr = 0o120777 << 16

    class Archive:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def infolist(self):
            return members

        def read(self, member: Member) -> bytes:
            return b"x"

    monkeypatch.setattr(authority_bundle.zipfile, "ZipFile", Archive)
    with pytest.raises(BundleError, match="archive (contains|member|compressed)"):
        authority_bundle.read_bundle_zip(b"zip")
