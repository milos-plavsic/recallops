import pytest

from recallops.release_evidence import (
    ASSURANCE_REQUIREMENTS,
    LIVE_REQUIREMENTS,
    ArtifactAttestation,
    DualGateResult,
    GateResult,
    ReleaseIdentity,
    ReleaseStatement,
    derive_dual_gates,
    release_statement,
)


def identity(*, source: str = "a" * 40, image: str = f"sha256:{'b' * 64}") -> ReleaseIdentity:
    return ReleaseIdentity(
        release_id="release-2026-08-29",
        source_sha=source,
        image_digest=image,
        capability_policy_version="webmcp-capability-v1",
        receipt_policy_version="authority-receipt-policy-v1",
        evaluation_version="governed-benchmark-v1",
        receipt_key_thumbprint="k" * 43,
    )


def artifacts(required: frozenset[str], release: ReleaseIdentity):
    return [
        ArtifactAttestation(
            artifact_kind=kind,
            artifact_digest=f"{index:064x}",
            release_id=release.release_id,
            source_sha=release.source_sha,
            image_digest=release.image_digest,
            passed=True,
            path=f"artifacts/release/{kind}.json",
        )
        for index, kind in enumerate(sorted(required), start=1)
    ]


def test_dual_gates_complete_only_for_every_passing_exact_release_artifact() -> None:
    release = identity()
    gates = derive_dual_gates(
        release,
        live_artifacts=artifacts(LIVE_REQUIREMENTS, release),
        assurance_artifacts=artifacts(ASSURANCE_REQUIREMENTS, release),
    )
    assert gates.live_proof.complete and gates.assurance.complete and gates.release_ready
    statement = release_statement(gates)
    assert statement.release_ready
    assert statement.live_proof_artifact_digest == gates.live_proof.artifact_digest
    assert statement.assurance_artifact_digest == gates.assurance.artifact_digest


def test_missing_failed_mismatched_and_duplicate_artifacts_each_keep_gate_red() -> None:
    release = identity()
    live = artifacts(LIVE_REQUIREMENTS, release)
    missing_kind = live.pop().artifact_kind
    assurance = artifacts(ASSURANCE_REQUIREMENTS, release)
    assurance[0] = assurance[0].model_copy(update={"passed": False})
    assurance[1] = assurance[1].model_copy(update={"source_sha": "c" * 40})
    assurance.append(assurance[2])
    gates = derive_dual_gates(
        release,
        live_artifacts=live,
        assurance_artifacts=assurance,
    )
    assert not gates.release_ready
    assert gates.live_proof.missing == (missing_kind,)
    assert gates.assurance.failed == (assurance[0].artifact_kind,)
    assert gates.assurance.mismatched == tuple(
        sorted({assurance[1].artifact_kind, assurance[2].artifact_kind})
    )


def test_gate_digest_is_deterministic_and_order_independent() -> None:
    release = identity()
    live = artifacts(LIVE_REQUIREMENTS, release)
    first = derive_dual_gates(release, live_artifacts=live, assurance_artifacts=[])
    second = derive_dual_gates(release, live_artifacts=reversed(live), assurance_artifacts=[])
    assert first == second
    changed = live[0].model_copy(update={"artifact_digest": "f" * 64})
    third = derive_dual_gates(
        release,
        live_artifacts=[changed, *live[1:]],
        assurance_artifacts=[],
    )
    assert third.live_proof.artifact_digest != first.live_proof.artifact_digest


def test_models_reject_self_asserted_green_status() -> None:
    release = identity()
    with pytest.raises(ValueError, match="completion differs"):
        GateResult(
            gate="live_proof",
            complete=True,
            artifact_digest="a" * 64,
            present=(),
            missing=("deployed_journey",),
            failed=(),
            mismatched=(),
        )
    live = GateResult(
        gate="live_proof",
        complete=False,
        artifact_digest="a" * 64,
        present=(),
        missing=("deployed_journey",),
        failed=(),
        mismatched=(),
    )
    assurance = GateResult(
        gate="assurance",
        complete=False,
        artifact_digest="b" * 64,
        present=(),
        missing=("python_branch_coverage",),
        failed=(),
        mismatched=(),
    )
    with pytest.raises(ValueError, match="intersection"):
        DualGateResult(
            identity=release,
            live_proof=live,
            assurance=assurance,
            release_ready=True,
        )
    with pytest.raises(ValueError, match="intersection"):
        ReleaseStatement(
            identity=release,
            live_proof_complete=False,
            live_proof_artifact_digest="a" * 64,
            assurance_complete=False,
            assurance_artifact_digest="b" * 64,
            release_ready=True,
        )
