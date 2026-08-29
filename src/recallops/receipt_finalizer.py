"""Fail-closed production orchestration for authority-receipt finalization.

The worker deliberately performs KMS and S3 calls outside the authority transaction. A claimed
request already binds one immutable ledger prefix; retries rebuild byte-identical material from
that prefix and the frozen release record before the database accepts the archived result.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import socket
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast
from uuid import UUID

import psycopg
from botocore.exceptions import BotoCoreError, ClientError
from psycopg.rows import dict_row

from recallops.authority_archive import ArchivedBundle
from recallops.authority_bundle import (
    BundleError,
    FrozenRelease,
    build_authority_bundle,
    prepare_evidence,
    sha256_bytes,
)
from recallops.canonical import canonical_bytes, content_digest
from recallops.domain import PolicyVerdict, PostcheckAssessment
from recallops.ledger import AuthorityEvent
from recallops.receipt_outbox import (
    ReceiptRequest,
    SignedReceiptResult,
    claim_receipt_request,
    finalize_receipt_request,
    release_receipt_failure,
)
from recallops.receipts import (
    JOSE_ALGORITHM,
    KmsClient,
    KmsReceiptSigner,
    ReceiptBuildContext,
    ReceiptDigestBindings,
    ReceiptError,
    ReceiptManifest,
    ReceiptVerificationError,
    ReleaseBinding,
    TrustedKeyRegistry,
    build_manifest,
    parse_canonical_json,
)
from recallops.resilience import DependencyUnavailable
from recallops.sandbox import policy_verdict_digest
from recallops.workflow import CAPABILITIES, WorkflowState

HEX_DIGEST = re.compile(r"^[a-f0-9]{64}$")
SOURCE_SHA = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
README = b"""# RecallOps authority bundle

This synthetic evidence bundle is independently verifiable with the repository's network-free
Node verifier. It proves integrity and conformance of the supplied server-authoritative capability
chain; it does not prove external truth, physical human presence, trusted time, or completeness
against a compromised signer.
"""


class ReceiptMaterialError(ReceiptError):
    """The immutable request cannot be matched to complete frozen receipt material."""


@dataclass(frozen=True)
class ReceiptDocuments:
    evaluation_case: Mapping[str, object]
    evaluation_result: Mapping[str, object]
    claims: Mapping[str, object]
    readme: bytes = README


class ReceiptDocumentSource(Protocol):
    def load(self, evaluation_version: str) -> ReceiptDocuments: ...


class FilesystemReceiptDocumentSource:
    """Load only strict canonical release artifacts produced by the evaluation pipeline."""

    def __init__(self, root: Path) -> None:
        self._root = root

    @staticmethod
    def _document(path: Path) -> Mapping[str, object]:
        try:
            value = path.read_bytes()
        except OSError as error:
            raise ReceiptMaterialError("required release evidence is unavailable") from error
        if not value or len(value) > MAX_DOCUMENT_BYTES:
            raise ReceiptMaterialError("release evidence has an invalid size")
        parsed = parse_canonical_json(value)
        if not isinstance(parsed, dict):
            raise ReceiptMaterialError("release evidence must be a canonical JSON object")
        return cast(Mapping[str, object], parsed)

    def load(self, evaluation_version: str) -> ReceiptDocuments:
        case = self._document(self._root / "evaluation-case.jcs.json")
        result = self._document(self._root / "evaluation-result.jcs.json")
        claims = self._document(self._root / "claims.jcs.json")
        return _validated_documents(case, result, claims, evaluation_version)


def _validated_documents(
    case: Mapping[str, object],
    result: Mapping[str, object],
    claims: Mapping[str, object],
    evaluation_version: str,
) -> ReceiptDocuments:
    if (
        case.get("evaluation_version") != evaluation_version
        or result.get("evaluation_version") != evaluation_version
    ):
        raise ReceiptMaterialError("release evaluation version does not match receipt request")
    return ReceiptDocuments(evaluation_case=case, evaluation_result=result, claims=claims)


class VersionedDocumentClient(Protocol):
    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...


class S3ReceiptDocumentSource:
    """Load digest-pinned release documents from exact immutable S3 versions."""

    _names = (
        "evaluation-case.jcs.json",
        "evaluation-result.jcs.json",
        "claims.jcs.json",
    )

    def __init__(
        self,
        client: VersionedDocumentClient,
        bucket: str,
        prefix: str,
        manifest_json: str,
    ) -> None:
        if not bucket or not prefix or prefix.startswith("/") or ".." in prefix.split("/"):
            raise ReceiptMaterialError("release evidence S3 location is invalid")
        try:
            manifest = json.loads(manifest_json)
        except (TypeError, ValueError) as error:
            raise ReceiptMaterialError("release evidence manifest is invalid JSON") from error
        if not isinstance(manifest, dict) or set(manifest) != set(self._names):
            raise ReceiptMaterialError("release evidence manifest has unexpected documents")
        pins: dict[str, tuple[str, str]] = {}
        for name in self._names:
            pin = manifest[name]
            if not isinstance(pin, dict) or set(pin) != {"sha256", "version_id"}:
                raise ReceiptMaterialError("release evidence manifest pin is invalid")
            digest, version = pin.get("sha256"), pin.get("version_id")
            if (
                not isinstance(digest, str)
                or HEX_DIGEST.fullmatch(digest) is None
                or not isinstance(version, str)
                or not version
                or len(version) > 1024
            ):
                raise ReceiptMaterialError("release evidence manifest pin is invalid")
            pins[name] = (digest, version)
        self._client = client
        self._bucket = bucket
        self._prefix = prefix.rstrip("/")
        self._pins = pins

    def _document(self, name: str) -> Mapping[str, object]:
        digest, version = self._pins[name]
        try:
            response = self._client.get_object(
                Bucket=self._bucket,
                Key=f"{self._prefix}/{name}",
                VersionId=version,
            )
            body = response.get("Body")
            value = body.read(MAX_DOCUMENT_BYTES + 1) if hasattr(body, "read") else body
        except (BotoCoreError, ClientError, OSError) as error:
            raise ReceiptMaterialError("required release evidence is unavailable") from error
        if not isinstance(value, bytes) or not value or len(value) > MAX_DOCUMENT_BYTES:
            raise ReceiptMaterialError("release evidence has an invalid size")
        if not hmac.compare_digest(hashlib.sha256(value).hexdigest(), digest):
            raise ReceiptMaterialError("release evidence digest does not match frozen manifest")
        parsed = parse_canonical_json(value)
        if not isinstance(parsed, dict):
            raise ReceiptMaterialError("release evidence must be a canonical JSON object")
        return cast(Mapping[str, object], parsed)

    def load(self, evaluation_version: str) -> ReceiptDocuments:
        return _validated_documents(
            self._document("evaluation-case.jcs.json"),
            self._document("evaluation-result.jcs.json"),
            self._document("claims.jcs.json"),
            evaluation_version,
        )


@dataclass(frozen=True)
class ReceiptMaterial:
    events: tuple[AuthorityEvent, ...]
    digests: ReceiptDigestBindings
    final_disposition: Literal["certify", "quarantine", "reject"]
    scenario_version: str
    signing_time: str
    expires_at: str
    release: FrozenRelease
    documents: ReceiptDocuments
    capability_policy: Mapping[str, object]
    receipt_policy: Mapping[str, object]


class ReceiptMaterialLoader(Protocol):
    def load(
        self,
        request: ReceiptRequest,
        *,
        release_id: str,
        key_thumbprint: str,
        documents: ReceiptDocuments,
    ) -> ReceiptMaterial: ...


def _utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise ReceiptMaterialError("receipt timestamp lacks a UTC offset")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _one(rows: Sequence[Mapping[str, Any]], description: str) -> Mapping[str, Any]:
    if len(rows) != 1:
        raise ReceiptMaterialError(f"receipt requires exactly one {description}")
    return rows[0]


def capability_policy_document(version: str) -> Mapping[str, object]:
    return {
        "capabilities": {state.value: list(CAPABILITIES[state]) for state in WorkflowState},
        "policy_version": version,
        "protected_transitions": ["approve", "execute", "review"],
    }


def receipt_policy_document(version: str) -> Mapping[str, object]:
    return {
        "algorithm": JOSE_ALGORITHM,
        "policy_version": version,
        "trust_anchor": "repository-pinned",
    }


class PostgresReceiptMaterialLoader:
    """Resolve a claimed prefix to exact domain evidence and one frozen release identity."""

    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def load(
        self,
        request: ReceiptRequest,
        *,
        release_id: str,
        key_thumbprint: str,
        documents: ReceiptDocuments,
    ) -> ReceiptMaterial:
        with psycopg.connect(self._database_url, row_factory=dict_row) as connection:
            identity_rows = connection.execute(
                """SELECT r.scenario_version,r.source_incident_id,r.build_sha,
                   r.capability_policy_version,e.source_sha,e.image_digest,
                   e.receipt_policy_version,e.evaluation_version,e.receipt_key_thumbprint
                FROM judge_runs r
                JOIN release_evidence_records e ON e.release_id=%s
                WHERE r.run_id=%s AND r.tenant_id=%s""",
                (release_id, request.run_id, request.tenant_id),
            ).fetchall()
            identity = _one(identity_rows, "run and frozen release identity")
            expected_identity = (
                request.source_sha,
                request.image_digest,
                request.receipt_policy_version,
                request.evaluation_version,
                key_thumbprint,
            )
            actual_identity = (
                identity["source_sha"],
                identity["image_digest"],
                identity["receipt_policy_version"],
                identity["evaluation_version"],
                identity["receipt_key_thumbprint"],
            )
            if (
                actual_identity != expected_identity
                or identity["build_sha"] != request.source_sha
                or not SOURCE_SHA.fullmatch(request.source_sha)
                or request.image_digest == f"sha256:{'0' * 64}"
                or (request.publish_public and not request.synthetic)
            ):
                raise ReceiptMaterialError("run, request, and frozen release identity differ")
            event_rows = connection.execute(
                """SELECT * FROM authority_events
                WHERE run_id=%s AND tenant_id=%s AND sequence <= %s
                ORDER BY sequence""",
                (request.run_id, request.tenant_id, request.target_sequence),
            ).fetchall()
            events = tuple(AuthorityEvent.model_validate(dict(row)) for row in event_rows)
            head_rows = connection.execute(
                """SELECT last_sequence,last_event_hash,closed FROM authority_ledger_heads
                WHERE run_id=%s AND tenant_id=%s""",
                (request.run_id, request.tenant_id),
            ).fetchall()
            head = _one(head_rows, "authority ledger head")
            if (
                len(events) != request.target_sequence
                or not events
                or events[-1].event_hash != request.target_ledger_hash
                or head["last_sequence"] != request.target_sequence
                or head["last_event_hash"] != request.target_ledger_hash
                or bool(head["closed"])
                or events[-1].state_after != "REVIEWED"
                or events[-1].object_type != "review_binding"
                or events[-1].object_id is None
                or HEX_DIGEST.fullmatch(events[-1].object_id) is None
            ):
                raise ReceiptMaterialError("claimed receipt target is not the exact review prefix")
            evidence_rows = connection.execute(
                """SELECT x.proposal_hash,x.execution_digest,o.observation_digest,
                   a.id AS assessment_id,a.observation_id,a.incident_id,a.tenant_id,
                   a.agent_subject,a.classification AS assessment_classification,
                   a.rationale,a.observation_digest AS assessment_observation_digest,
                   a.created_at AS assessment_created_at,
                   v.classification AS verdict_classification,v.policy_version AS verdict_policy,
                   v.checks_passed,v.checks_failed,
                   v.observation_digest AS verdict_observation_digest,
                   v.computed_at,
                   m.assessment_digest,m.verdict_digest,m.memory_digest,m.expires_at,
                   m.state AS memory_state,m.valid AS memory_valid,m.source_incident_id,
                   m.service,m.service_version,m.action,m.outcome_semantics,m.outcome_score,
                   m.compatibility_policy,m.compatibility_policy_version,
                   m.governance_policy_version,m.created_at AS memory_created_at
                FROM sandbox_executions x
                JOIN approvals p ON p.incident_id=x.incident_id AND p.tenant_id=x.tenant_id
                  AND p.approved=true AND p.proposal_hash=x.proposal_hash
                JOIN postcheck_observations o ON o.execution_id=x.id
                  AND o.incident_id=x.incident_id AND o.tenant_id=x.tenant_id
                  AND o.proposal_hash=x.proposal_hash AND o.execution_digest=x.execution_digest
                JOIN postcheck_policy_verdicts v ON v.observation_id=o.id
                  AND v.incident_id=o.incident_id AND v.tenant_id=o.tenant_id
                  AND v.observation_digest=o.observation_digest
                JOIN postcheck_assessments a ON a.observation_id=o.id
                  AND a.incident_id=o.incident_id AND a.tenant_id=o.tenant_id
                  AND a.observation_digest=o.observation_digest
                JOIN memories m ON m.source_incident_id=o.incident_id AND m.tenant_id=o.tenant_id
                  AND m.observation_digest=o.observation_digest
                WHERE x.incident_id=%s AND x.tenant_id=%s""",
                (identity["source_incident_id"], request.tenant_id),
            ).fetchall()
            evidence = _one(evidence_rows, "bound execution and evidence chain")
        assessment = PostcheckAssessment(
            id=evidence["assessment_id"],
            observation_id=evidence["observation_id"],
            incident_id=evidence["incident_id"],
            tenant_id=evidence["tenant_id"],
            agent_subject=evidence["agent_subject"],
            classification=evidence["assessment_classification"],
            rationale=evidence["rationale"],
            observation_digest=evidence["assessment_observation_digest"],
            created_at=evidence["assessment_created_at"],
        )
        assessment_digest = content_digest(
            "recallops-assessment-v1",
            {
                "observation_digest": assessment.observation_digest,
                "agent_subject": assessment.agent_subject,
                "classification": assessment.classification.value,
                "rationale": assessment.rationale,
                "created_at": _utc(assessment.created_at),
            },
        )
        verdict = PolicyVerdict(
            classification=evidence["verdict_classification"],
            policy_version=evidence["verdict_policy"],
            checks_passed=evidence["checks_passed"],
            checks_failed=evidence["checks_failed"],
            observation_digest=evidence["verdict_observation_digest"],
            computed_at=evidence["computed_at"],
        )
        verdict_digest = policy_verdict_digest(verdict)
        memory_digest = content_digest(
            "recallops-memory-v1",
            {
                "source_incident_id": str(evidence["source_incident_id"]),
                "service": evidence["service"],
                "service_version": evidence["service_version"],
                "action": evidence["action"],
                "observation_digest": evidence["observation_digest"],
                "assessment_digest": assessment_digest,
                "verdict_digest": verdict_digest,
                "outcome_semantics": evidence["outcome_semantics"],
                "outcome_score": evidence["outcome_score"],
                "compatibility_policy": evidence["compatibility_policy"],
                "compatibility_policy_version": evidence["compatibility_policy_version"],
                "governance_policy_version": evidence["governance_policy_version"],
                "created_at": _utc(evidence["memory_created_at"]),
            },
        )
        if (
            assessment_digest != evidence["assessment_digest"]
            or verdict_digest != evidence["verdict_digest"]
            or memory_digest != evidence["memory_digest"]
            or evidence["expires_at"] is None
            or evidence["expires_at"] <= request.created_at
        ):
            raise ReceiptMaterialError("stored evidence digests or lifetime do not verify")
        dispositions: dict[str, tuple[Literal["certify", "quarantine", "reject"], str, bool]] = {
            "MEMORY_CERTIFY": ("certify", "active", True),
            "MEMORY_QUARANTINE": ("quarantine", "quarantined", False),
            "MEMORY_REJECT": ("reject", "rejected", False),
        }
        disposition = dispositions.get(events[-1].reason_code)
        if disposition is None or disposition[1:] != (
            evidence["memory_state"],
            evidence["memory_valid"],
        ):
            raise ReceiptMaterialError("review disposition differs from governed memory state")
        digests = ReceiptDigestBindings(
            proposal=evidence["proposal_hash"],
            execution=evidence["execution_digest"],
            observation=evidence["observation_digest"],
            assessment=assessment_digest,
            policy_verdict=verdict_digest,
            memory=evidence["memory_digest"],
            review=events[-1].object_id,
        )
        claim_digest = sha256_bytes(canonical_bytes(dict(documents.claims)))
        release = FrozenRelease(
            release_id=release_id,
            source_sha=request.source_sha,
            image_digest=request.image_digest,
            capability_policy_version=identity["capability_policy_version"],
            receipt_policy_version=request.receipt_policy_version,
            evaluation_version=request.evaluation_version,
            claim_registry_digest=claim_digest,
            receipt_key_thumbprint=key_thumbprint,
        )
        return ReceiptMaterial(
            events=events,
            digests=digests,
            final_disposition=disposition[0],
            scenario_version=identity["scenario_version"],
            signing_time=_utc(request.created_at),
            expires_at=_utc(evidence["expires_at"]),
            release=release,
            documents=documents,
            capability_policy=capability_policy_document(identity["capability_policy_version"]),
            receipt_policy=receipt_policy_document(request.receipt_policy_version),
        )


class ReceiptSigner(Protocol):
    @property
    def kid(self) -> str: ...

    @property
    def public_jwk(self) -> Mapping[str, str]: ...

    @property
    def trusted_keys(self) -> TrustedKeyRegistry: ...

    def sign_manifest(self, manifest: ReceiptManifest) -> str: ...


class BundleArchive(Protocol):
    def persist(self, receipt_id: UUID, archive: bytes, bundle_digest: str) -> ArchivedBundle: ...


@dataclass(frozen=True)
class ReceiptWorkerResult:
    status: Literal["idle", "signed", "retrying", "dead_lettered"]
    receipt_id: str | None = None
    failure_code: str | None = None


class ReceiptFinalizationWorker:
    def __init__(
        self,
        *,
        database_url: str,
        worker_id: str,
        release_id: str,
        subject_pseudonym_key: bytes,
        documents: ReceiptDocumentSource,
        loader: ReceiptMaterialLoader,
        signer: ReceiptSigner,
        archive: BundleArchive,
        max_attempts: int = 8,
        lease_seconds: int = 120,
    ) -> None:
        if not worker_id or not release_id or len(subject_pseudonym_key) < 32:
            raise ValueError("receipt worker identity, release, and pseudonym key are required")
        self._database_url = database_url
        self._worker_id = worker_id
        self._release_id = release_id
        self._subject_pseudonym_key = subject_pseudonym_key
        self._documents = documents
        self._loader = loader
        self._signer = signer
        self._archive = archive
        self._max_attempts = max_attempts
        self._lease_seconds = lease_seconds

    def run_once(self) -> ReceiptWorkerResult:
        request = claim_receipt_request(self._database_url, self._worker_id, self._lease_seconds)
        if request is None:
            return ReceiptWorkerResult(status="idle")
        try:
            documents = self._documents.load(request.evaluation_version)
            material = self._loader.load(
                request,
                release_id=self._release_id,
                key_thumbprint=self._signer.kid,
                documents=documents,
            )
            prepared = prepare_evidence(
                public_jwk=self._signer.public_jwk,
                events=material.events,
                capability_policy=material.capability_policy,
                receipt_policy=material.receipt_policy,
                evaluation_case=documents.evaluation_case,
                evaluation_result=documents.evaluation_result,
                release=material.release,
                claims=documents.claims,
            )
            manifest = build_manifest(
                material.events,
                material.digests,
                ReceiptBuildContext(
                    receipt_policy_version=request.receipt_policy_version,
                    scenario_version=material.scenario_version,
                    final_disposition=material.final_disposition,
                    release=ReleaseBinding(
                        release_id=material.release.release_id,
                        source_sha=material.release.source_sha,
                        image_digest=material.release.image_digest,
                        evaluation_version=material.release.evaluation_version,
                        claim_registry_digest=material.release.claim_registry_digest,
                    ),
                    evidence_index_digest=prepared.index_digest,
                    asserted_signing_time=material.signing_time,
                    expires_at=material.expires_at,
                    key_thumbprint=self._signer.kid,
                ),
                subject_pseudonym_key=self._subject_pseudonym_key,
            )
            compact = self._signer.sign_manifest(manifest)
            bundle = build_authority_bundle(
                manifest=manifest,
                receipt_jws=compact,
                public_jwk=self._signer.public_jwk,
                events=material.events,
                capability_policy=material.capability_policy,
                receipt_policy=material.receipt_policy,
                evaluation_case=documents.evaluation_case,
                evaluation_result=documents.evaluation_result,
                release=material.release,
                claims=documents.claims,
                trusted_keys=self._signer.trusted_keys,
                readme=documents.readme,
            )
            archived = self._archive.persist(
                request.receipt_id, bundle.deterministic_zip(), bundle.bundle_digest
            )
            result = SignedReceiptResult(
                manifest_digest=hashlib.sha256(manifest.canonical()).hexdigest(),
                jws_compact=compact,
                key_thumbprint=self._signer.kid,
                archived=archived,
            )
            if not finalize_receipt_request(
                self._database_url,
                request,
                self._worker_id,
                manifest,
                result,
            ):
                raise ReceiptMaterialError("receipt finalization lease or binding was lost")
            return ReceiptWorkerResult(status="signed", receipt_id=str(request.receipt_id))
        except DependencyUnavailable as error:
            return self._failed(request, f"DEPENDENCY_{error.dependency.upper()}", retry=True)
        except (ReceiptVerificationError, BundleError, ReceiptMaterialError):
            return self._failed(request, "RECEIPT_MATERIAL_INVALID", retry=False)
        except ReceiptError:
            return self._failed(request, "RECEIPT_SIGNING_FAILED", retry=True)
        except ValueError:
            return self._failed(request, "RECEIPT_MATERIAL_INVALID", retry=False)

    def _failed(self, request: ReceiptRequest, code: str, *, retry: bool) -> ReceiptWorkerResult:
        bounded = re.sub(r"[^A-Z0-9_]", "_", code)[:100]
        terminal = release_receipt_failure(
            self._database_url,
            request,
            self._worker_id,
            bounded,
            max_attempts=self._max_attempts if retry else 1,
        )
        return ReceiptWorkerResult(
            status="dead_lettered" if terminal else "retrying",
            receipt_id=str(request.receipt_id),
            failure_code=bounded,
        )


def receipt_worker_status(database_url: str) -> Mapping[str, int]:
    """Return payload-free receipt backlog signals suitable for alarms and health checks."""
    with psycopg.connect(database_url, row_factory=dict_row) as connection:
        row = connection.execute(
            """SELECT
              count(*) FILTER (WHERE status='pending') AS pending,
              count(*) FILTER (WHERE status='processing') AS processing,
              count(*) FILTER (WHERE status='dead_lettered') AS dead_lettered
            FROM receipt_requests"""
        ).fetchone()
    return {
        "pending": int(row["pending"] if row else 0),
        "processing": int(row["processing"] if row else 0),
        "dead_lettered": int(row["dead_lettered"] if row else 0),
    }


def _subject_pseudonym_key(value: str) -> bytes:
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ReceiptMaterialError("receipt pseudonym key is not canonical base64url")
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError as error:
        raise ReceiptMaterialError("receipt pseudonym key is invalid base64url") from error
    encoded = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if encoded != value or len(decoded) < 32:
        raise ReceiptMaterialError("receipt pseudonym key must contain at least 256 bits")
    return decoded


def production_worker(worker_id: str) -> ReceiptFinalizationWorker:
    """Construct the only production worker profile; no local signer or storage fallback exists."""
    import boto3

    from recallops.authority_archive import S3AuthorityBundleArchive, S3BundleClient
    from recallops.config import Settings

    settings = Settings()
    required = (
        settings.receipt_kms_key_id,
        settings.receipt_release_id,
        settings.authority_bundle_bucket,
        settings.authority_bundle_kms_key_id,
        settings.receipt_subject_pseudonym_key_b64,
        settings.receipt_trusted_keys_json,
        settings.receipt_release_artifacts_bucket,
        settings.receipt_release_artifacts_prefix,
        settings.receipt_release_artifacts_manifest_json,
    )
    if any(value is None for value in required):
        raise ReceiptMaterialError("receipt worker production configuration is incomplete")
    secret = cast(Any, settings.receipt_subject_pseudonym_key_b64).get_secret_value()
    release_manifest = cast(
        Any, settings.receipt_release_artifacts_manifest_json
    ).get_secret_value()
    subject_key = _subject_pseudonym_key(secret)
    registry_json = cast(Any, settings.receipt_trusted_keys_json).get_secret_value()
    registry = TrustedKeyRegistry.from_bytes(registry_json.encode("utf-8"))
    kms = boto3.client("kms", region_name=settings.aws_region)
    signer = KmsReceiptSigner(
        cast(KmsClient, kms),
        cast(str, settings.receipt_kms_key_id),
        cast(str, settings.receipt_release_id),
        registry,
    )
    signer.preflight()
    s3 = boto3.client("s3", region_name=settings.aws_region)
    archive = S3AuthorityBundleArchive(
        cast(S3BundleClient, s3),
        cast(str, settings.authority_bundle_bucket),
        cast(str, settings.authority_bundle_kms_key_id),
    )
    return ReceiptFinalizationWorker(
        database_url=settings.database_url,
        worker_id=worker_id,
        release_id=cast(str, settings.receipt_release_id),
        subject_pseudonym_key=subject_key,
        documents=S3ReceiptDocumentSource(
            cast(VersionedDocumentClient, s3),
            cast(str, settings.receipt_release_artifacts_bucket),
            cast(str, settings.receipt_release_artifacts_prefix),
            release_manifest,
        ),
        loader=PostgresReceiptMaterialLoader(settings.database_url),
        signer=signer,
        archive=archive,
        max_attempts=settings.outbox_max_attempts,
        lease_seconds=settings.outbox_lease_seconds,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Finalize RecallOps authority receipts")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    arguments = parser.parse_args()
    if arguments.limit < 1 or arguments.limit > 1000:
        parser.error("--limit must be between 1 and 1000")
    if arguments.poll_seconds <= 0 or arguments.poll_seconds > 300:
        parser.error("--poll-seconds must be between 0 and 300")
    from recallops.config import Settings

    if arguments.status:
        print(dict(receipt_worker_status(Settings().database_url)))
        return
    worker = production_worker(f"{socket.gethostname()}:{os.getpid()}")
    while True:
        counts = {"signed": 0, "retrying": 0, "dead_lettered": 0}
        for _ in range(arguments.limit):
            result = worker.run_once()
            if result.status == "idle":
                break
            counts[result.status] += 1
        if any(counts.values()) or not arguments.watch:
            print(" ".join(f"{key}={value}" for key, value in counts.items()), flush=True)
        if not arguments.watch:
            return
        time.sleep(arguments.poll_seconds)


if __name__ == "__main__":
    main()
