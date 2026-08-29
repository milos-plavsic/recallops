"""Build-bound claim evidence and independently derived readiness gates."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from recallops.canonical import content_digest

HEX_DIGEST = r"^[a-f0-9]{64}$"
SOURCE_SHA = r"^[a-f0-9]{40}([a-f0-9]{24})?$"
IMAGE_DIGEST = r"^sha256:[a-f0-9]{64}$"

LIVE_REQUIREMENTS = frozenset(
    {
        "deployed_journey",
        "refresh_reset",
        "public_bundle_download",
        "accessibility_smoke",
        "native_chrome_webmcp",
        "chatgpt_site_tools",
    }
)
ASSURANCE_REQUIREMENTS = frozenset(
    {
        "python_branch_coverage",
        "cockroach_boundaries",
        "governed_benchmark",
        "authority_vectors",
        "offline_verifier",
        "provenance",
        "artifact_manifest",
        "security_scans",
    }
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ReleaseIdentity(_StrictModel):
    release_id: str = Field(min_length=3, max_length=100)
    source_sha: str = Field(pattern=SOURCE_SHA)
    image_digest: str = Field(pattern=IMAGE_DIGEST)
    capability_policy_version: str = Field(min_length=3, max_length=80)
    receipt_policy_version: str = Field(min_length=3, max_length=80)
    evaluation_version: str = Field(min_length=3, max_length=80)
    receipt_key_thumbprint: str = Field(min_length=43, max_length=43)


class ArtifactAttestation(_StrictModel):
    artifact_kind: str = Field(pattern=r"^[a-z][a-z0-9_]{2,79}$")
    artifact_digest: str = Field(pattern=HEX_DIGEST)
    release_id: str = Field(min_length=3, max_length=100)
    source_sha: str = Field(pattern=SOURCE_SHA)
    image_digest: str = Field(pattern=IMAGE_DIGEST)
    passed: bool
    path: str = Field(min_length=1, max_length=500)


class GateResult(_StrictModel):
    gate: Literal["live_proof", "assurance"]
    complete: bool
    artifact_digest: str = Field(pattern=HEX_DIGEST)
    present: tuple[str, ...]
    missing: tuple[str, ...]
    failed: tuple[str, ...]
    mismatched: tuple[str, ...]

    @model_validator(mode="after")
    def completion_matches_findings(self) -> GateResult:
        expected = not self.missing and not self.failed and not self.mismatched
        if self.complete != expected:
            raise ValueError("gate completion differs from its evidence findings")
        return self


class DualGateResult(_StrictModel):
    identity: ReleaseIdentity
    live_proof: GateResult
    assurance: GateResult
    release_ready: bool

    @model_validator(mode="after")
    def readiness_is_intersection(self) -> DualGateResult:
        if self.release_ready != (self.live_proof.complete and self.assurance.complete):
            raise ValueError("release readiness must be the intersection of both gates")
        return self


class ReleaseStatement(_StrictModel):
    statement_version: Literal["recallops-release-statement-v1"] = "recallops-release-statement-v1"
    identity: ReleaseIdentity
    live_proof_complete: bool
    live_proof_artifact_digest: str = Field(pattern=HEX_DIGEST)
    assurance_complete: bool
    assurance_artifact_digest: str = Field(pattern=HEX_DIGEST)
    release_ready: bool

    @model_validator(mode="after")
    def readiness_is_intersection(self) -> ReleaseStatement:
        if self.release_ready != (self.live_proof_complete and self.assurance_complete):
            raise ValueError("signed readiness must be the intersection of both gates")
        return self


def _derive_gate(
    gate: Literal["live_proof", "assurance"],
    required: frozenset[str],
    identity: ReleaseIdentity,
    artifacts: Iterable[ArtifactAttestation],
) -> GateResult:
    by_kind: dict[str, ArtifactAttestation] = {}
    duplicates: set[str] = set()
    for artifact in artifacts:
        if artifact.artifact_kind in by_kind:
            duplicates.add(artifact.artifact_kind)
        by_kind[artifact.artifact_kind] = artifact
    present = tuple(sorted(required & set(by_kind)))
    missing = tuple(sorted(required - set(by_kind)))
    failed = tuple(sorted(kind for kind in present if not by_kind[kind].passed))
    mismatched = set(duplicates)
    for kind in present:
        artifact = by_kind[kind]
        if (
            artifact.release_id != identity.release_id
            or artifact.source_sha != identity.source_sha
            or artifact.image_digest != identity.image_digest
        ):
            mismatched.add(kind)
    digest = content_digest(
        "recallops-gate-artifacts-v1",
        {
            "gate": gate,
            "identity": identity.model_dump(mode="json"),
            "required": sorted(required),
            "artifacts": [by_kind[kind].model_dump(mode="json") for kind in sorted(by_kind)],
        },
    )
    mismatched_tuple = tuple(sorted(mismatched))
    return GateResult(
        gate=gate,
        complete=not missing and not failed and not mismatched_tuple,
        artifact_digest=digest,
        present=present,
        missing=missing,
        failed=failed,
        mismatched=mismatched_tuple,
    )


def derive_dual_gates(
    identity: ReleaseIdentity,
    *,
    live_artifacts: Iterable[ArtifactAttestation],
    assurance_artifacts: Iterable[ArtifactAttestation],
) -> DualGateResult:
    live = _derive_gate("live_proof", LIVE_REQUIREMENTS, identity, live_artifacts)
    assurance = _derive_gate("assurance", ASSURANCE_REQUIREMENTS, identity, assurance_artifacts)
    return DualGateResult(
        identity=identity,
        live_proof=live,
        assurance=assurance,
        release_ready=live.complete and assurance.complete,
    )


def release_statement(gates: DualGateResult) -> ReleaseStatement:
    return ReleaseStatement(
        identity=gates.identity,
        live_proof_complete=gates.live_proof.complete,
        live_proof_artifact_digest=gates.live_proof.artifact_digest,
        assurance_complete=gates.assurance.complete,
        assurance_artifact_digest=gates.assurance.artifact_digest,
        release_ready=gates.release_ready,
    )
