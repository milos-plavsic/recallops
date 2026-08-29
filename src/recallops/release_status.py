"""Server-authoritative, fail-closed release readiness projection."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Literal, Protocol

import psycopg
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict

from recallops.config import Settings
from recallops.receipts import (
    ReceiptVerificationError,
    TrustedKeyRegistry,
    verify_release_statement_jws,
)

GateStatus = Literal["pending", "passing", "failed", "stale"]


@dataclass(frozen=True)
class ReleaseEvidenceRecord:
    release_id: str
    source_sha: str
    image_digest: str
    capability_policy_version: str
    receipt_policy_version: str
    evaluation_version: str
    receipt_key_thumbprint: str
    live_proof_artifact_digest: str | None
    live_proof_status: GateStatus
    assurance_artifact_digest: str | None
    assurance_status: GateStatus
    release_statement_jws: str | None


class ReleaseEvidenceRepository(Protocol):
    def get(self, release_id: str) -> ReleaseEvidenceRecord | None: ...


class PostgresReleaseEvidenceRepository:
    def __init__(self, database_url: str) -> None:
        self._database_url = database_url

    def get(self, release_id: str) -> ReleaseEvidenceRecord | None:
        with psycopg.connect(
            self._database_url, row_factory=dict_row, autocommit=True
        ) as connection:
            row = connection.execute(
                """SELECT release_id,source_sha,image_digest,capability_policy_version,
                receipt_policy_version,evaluation_version,receipt_key_thumbprint,
                live_proof_artifact_digest,live_proof_status,
                assurance_artifact_digest,assurance_status,release_statement_jws
                FROM release_evidence_records WHERE release_id=%s""",
                (release_id,),
            ).fetchone()
        return ReleaseEvidenceRecord(**row) if row is not None else None


class PublicGateStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: GateStatus
    complete: bool
    artifact_digest: str | None


class PublicReleaseStatus(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    configured: bool
    release_id: str | None
    source_sha: str | None
    image_digest: str | None
    live_proof: PublicGateStatus
    assurance: PublicGateStatus
    signed_statement_verified: bool
    release_ready: bool
    reason: str


def _gate(status: GateStatus, digest: str | None) -> PublicGateStatus:
    return PublicGateStatus(
        status=status,
        complete=status == "passing" and digest is not None,
        artifact_digest=digest,
    )


class ReleaseStatusService:
    def __init__(
        self,
        settings: Settings,
        repository: ReleaseEvidenceRepository | None = None,
        trusted_keys: TrustedKeyRegistry | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._trusted_keys = trusted_keys

    @classmethod
    def production(cls, settings: Settings) -> ReleaseStatusService:
        if settings.receipt_release_id is None:
            return cls(settings)
        return cls(
            settings,
            PostgresReleaseEvidenceRepository(settings.database_url),
            TrustedKeyRegistry.load(settings.receipt_trusted_keys_path),
        )

    def current(self) -> PublicReleaseStatus:
        release_id = self._settings.receipt_release_id
        if release_id is None or self._repository is None or self._trusted_keys is None:
            return self._unavailable(False, "release evidence is not configured")
        record = self._repository.get(release_id)
        if record is None:
            return self._unavailable(True, "release evidence has not been published")
        if not self._identity_matches(record):
            return PublicReleaseStatus(
                configured=True,
                release_id=release_id,
                source_sha=record.source_sha,
                image_digest=record.image_digest,
                live_proof=_gate("stale", record.live_proof_artifact_digest),
                assurance=_gate("stale", record.assurance_artifact_digest),
                signed_statement_verified=False,
                release_ready=False,
                reason="published evidence does not match the running release",
            )
        live = _gate(record.live_proof_status, record.live_proof_artifact_digest)
        assurance = _gate(record.assurance_status, record.assurance_artifact_digest)
        verified = self._statement_matches(record, live.complete, assurance.complete)
        return PublicReleaseStatus(
            configured=True,
            release_id=release_id,
            source_sha=record.source_sha,
            image_digest=record.image_digest,
            live_proof=live,
            assurance=assurance,
            signed_statement_verified=verified,
            release_ready=live.complete and assurance.complete and verified,
            reason=(
                "both independent gates and the pinned-key statement verify"
                if live.complete and assurance.complete and verified
                else "one or more independently derived release proofs remain incomplete"
            ),
        )

    def _identity_matches(self, record: ReleaseEvidenceRecord) -> bool:
        expected = (
            self._settings.receipt_release_id or "",
            self._settings.build_sha,
            self._settings.release_image_digest,
            self._settings.capability_policy_version,
            self._settings.receipt_policy_version,
            self._settings.evaluation_version,
        )
        actual = (
            record.release_id,
            record.source_sha,
            record.image_digest,
            record.capability_policy_version,
            record.receipt_policy_version,
            record.evaluation_version,
        )
        return all(
            hmac.compare_digest(left, right) for left, right in zip(expected, actual, strict=True)
        )

    def _statement_matches(
        self, record: ReleaseEvidenceRecord, live_complete: bool, assurance_complete: bool
    ) -> bool:
        if record.release_statement_jws is None or self._trusted_keys is None:
            return False
        try:
            statement = verify_release_statement_jws(
                record.release_statement_jws,
                self._trusted_keys,
                release_id=record.release_id,
            )
        except ReceiptVerificationError:
            return False
        return (
            hmac.compare_digest(
                statement.identity.receipt_key_thumbprint,
                record.receipt_key_thumbprint,
            )
            and statement.identity.source_sha == record.source_sha
            and statement.identity.image_digest == record.image_digest
            and statement.identity.capability_policy_version == record.capability_policy_version
            and statement.identity.receipt_policy_version == record.receipt_policy_version
            and statement.identity.evaluation_version == record.evaluation_version
            and statement.live_proof_complete == live_complete
            and statement.assurance_complete == assurance_complete
            and statement.live_proof_artifact_digest == record.live_proof_artifact_digest
            and statement.assurance_artifact_digest == record.assurance_artifact_digest
            and statement.release_ready == (live_complete and assurance_complete)
        )

    def _unavailable(self, configured: bool, reason: str) -> PublicReleaseStatus:
        return PublicReleaseStatus(
            configured=configured,
            release_id=self._settings.receipt_release_id,
            source_sha=None,
            image_digest=None,
            live_proof=_gate("pending", None),
            assurance=_gate("pending", None),
            signed_statement_verified=False,
            release_ready=False,
            reason=reason,
        )
