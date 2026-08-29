CREATE TABLE IF NOT EXISTS authority_receipts (
    receipt_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    ledger_head_hash STRING NOT NULL CHECK (ledger_head_hash ~ '^[a-f0-9]{64}$'),
    ledger_last_sequence INT8 NOT NULL CHECK (ledger_last_sequence > 0),
    manifest_digest STRING NULL CHECK (manifest_digest IS NULL OR manifest_digest ~ '^[a-f0-9]{64}$'),
    bundle_digest STRING NULL CHECK (bundle_digest IS NULL OR bundle_digest ~ '^[a-f0-9]{64}$'),
    jws_compact STRING NULL CHECK (jws_compact IS NULL OR length(jws_compact) BETWEEN 64 AND 5000),
    key_thumbprint STRING NULL CHECK (key_thumbprint IS NULL OR length(key_thumbprint) = 43),
    signing_algorithm STRING NULL CHECK (signing_algorithm IS NULL OR signing_algorithm = 'Ed25519'),
    receipt_policy_version STRING NOT NULL CHECK (length(receipt_policy_version) BETWEEN 3 AND 80),
    source_sha STRING NOT NULL CHECK (source_sha ~ '^([a-f0-9]{40}|[a-f0-9]{64})$'),
    image_digest STRING NOT NULL CHECK (image_digest ~ '^sha256:[a-f0-9]{64}$'),
    evaluation_version STRING NOT NULL CHECK (length(evaluation_version) BETWEEN 3 AND 80),
    status STRING NOT NULL CHECK (status IN ('pending','signed','failed','superseded')),
    s3_version_id STRING NULL CHECK (s3_version_id IS NULL OR length(s3_version_id) BETWEEN 1 AND 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    signed_at TIMESTAMPTZ NULL,
    failure_code STRING NULL CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 100),
    CONSTRAINT authority_receipts_run_tenant_fk
        FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id),
    CONSTRAINT authority_receipts_signed_complete CHECK (
        status != 'signed' OR (
            manifest_digest IS NOT NULL AND bundle_digest IS NOT NULL AND jws_compact IS NOT NULL
            AND key_thumbprint IS NOT NULL AND signing_algorithm = 'Ed25519'
            AND s3_version_id IS NOT NULL AND signed_at IS NOT NULL AND failure_code IS NULL
        )
    ),
    CONSTRAINT authority_receipts_failed_bounded CHECK (
        status != 'failed' OR (failure_code IS NOT NULL AND signed_at IS NULL)
    ),
    UNIQUE (receipt_id, run_id, tenant_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS authority_receipts_active_prefix
    ON authority_receipts (run_id, ledger_head_hash, receipt_policy_version)
    WHERE status IN ('pending', 'signed');

CREATE OR REPLACE FUNCTION recallops_guard_authority_receipt()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD).run_id IS DISTINCT FROM (NEW).run_id
       OR (OLD).tenant_id IS DISTINCT FROM (NEW).tenant_id
       OR (OLD).ledger_head_hash IS DISTINCT FROM (NEW).ledger_head_hash
       OR (OLD).ledger_last_sequence IS DISTINCT FROM (NEW).ledger_last_sequence
       OR (OLD).receipt_policy_version IS DISTINCT FROM (NEW).receipt_policy_version
       OR (OLD).source_sha IS DISTINCT FROM (NEW).source_sha
       OR (OLD).image_digest IS DISTINCT FROM (NEW).image_digest
       OR (OLD).evaluation_version IS DISTINCT FROM (NEW).evaluation_version
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
    THEN
        RAISE EXCEPTION 'authority receipt binding is immutable' USING ERRCODE = '23514';
    END IF;
    IF (OLD).status IN ('signed', 'superseded') AND (
       (OLD).manifest_digest IS DISTINCT FROM (NEW).manifest_digest
       OR (OLD).bundle_digest IS DISTINCT FROM (NEW).bundle_digest
       OR (OLD).jws_compact IS DISTINCT FROM (NEW).jws_compact
       OR (OLD).key_thumbprint IS DISTINCT FROM (NEW).key_thumbprint
       OR (OLD).signing_algorithm IS DISTINCT FROM (NEW).signing_algorithm
       OR (OLD).s3_version_id IS DISTINCT FROM (NEW).s3_version_id
       OR (OLD).signed_at IS DISTINCT FROM (NEW).signed_at
    )
    THEN
        RAISE EXCEPTION 'signed authority receipt is immutable' USING ERRCODE = '23514';
    END IF;
    IF NOT (
       ((OLD).status = 'pending' AND (NEW).status IN ('pending','signed','failed'))
       OR ((OLD).status = 'failed' AND (NEW).status IN ('failed','pending'))
       OR ((OLD).status = 'signed' AND (NEW).status IN ('signed','superseded'))
       OR ((OLD).status = 'superseded' AND (NEW).status = 'superseded')
    )
    THEN
        RAISE EXCEPTION 'invalid authority receipt status transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS recallops_authority_receipt_immutable ON authority_receipts;
CREATE TRIGGER recallops_authority_receipt_immutable
BEFORE UPDATE ON authority_receipts
FOR EACH ROW
EXECUTE FUNCTION recallops_guard_authority_receipt();

CREATE TABLE IF NOT EXISTS release_evidence_records (
    release_id STRING PRIMARY KEY CHECK (length(release_id) BETWEEN 3 AND 100),
    source_sha STRING NOT NULL CHECK (source_sha ~ '^([a-f0-9]{40}|[a-f0-9]{64})$'),
    image_digest STRING NOT NULL CHECK (image_digest ~ '^sha256:[a-f0-9]{64}$'),
    capability_policy_version STRING NOT NULL CHECK (length(capability_policy_version) BETWEEN 3 AND 80),
    receipt_policy_version STRING NOT NULL CHECK (length(receipt_policy_version) BETWEEN 3 AND 80),
    evaluation_version STRING NOT NULL CHECK (length(evaluation_version) BETWEEN 3 AND 80),
    receipt_key_thumbprint STRING NOT NULL CHECK (length(receipt_key_thumbprint) = 43),
    live_proof_artifact_digest STRING NULL
        CHECK (live_proof_artifact_digest IS NULL OR live_proof_artifact_digest ~ '^[a-f0-9]{64}$'),
    live_proof_status STRING NOT NULL CHECK (live_proof_status IN ('pending','passing','failed','stale')),
    assurance_artifact_digest STRING NULL
        CHECK (assurance_artifact_digest IS NULL OR assurance_artifact_digest ~ '^[a-f0-9]{64}$'),
    assurance_status STRING NOT NULL CHECK (assurance_status IN ('pending','passing','failed','stale')),
    native_client_version STRING NULL,
    native_client_checked_at TIMESTAMPTZ NULL,
    chatgpt_client_version STRING NULL,
    chatgpt_client_checked_at TIMESTAMPTZ NULL,
    live_s3_version_id STRING NULL,
    assurance_s3_version_id STRING NULL,
    release_statement_jws STRING NULL,
    release_statement_digest STRING NULL
        CHECK (release_statement_digest IS NULL OR release_statement_digest ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finalized_at TIMESTAMPTZ NULL,
    CONSTRAINT release_evidence_passing_has_artifact CHECK (
        live_proof_status != 'passing' OR live_proof_artifact_digest IS NOT NULL
    ),
    CONSTRAINT release_assurance_passing_has_artifact CHECK (
        assurance_status != 'passing' OR assurance_artifact_digest IS NOT NULL
    )
);

CREATE OR REPLACE FUNCTION recallops_guard_release_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD).release_id IS DISTINCT FROM (NEW).release_id
       OR (OLD).source_sha IS DISTINCT FROM (NEW).source_sha
       OR (OLD).image_digest IS DISTINCT FROM (NEW).image_digest
       OR (OLD).capability_policy_version IS DISTINCT FROM (NEW).capability_policy_version
       OR (OLD).receipt_policy_version IS DISTINCT FROM (NEW).receipt_policy_version
       OR (OLD).evaluation_version IS DISTINCT FROM (NEW).evaluation_version
       OR (OLD).receipt_key_thumbprint IS DISTINCT FROM (NEW).receipt_key_thumbprint
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
    THEN
        RAISE EXCEPTION 'release evidence identity is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS recallops_release_identity_immutable ON release_evidence_records;
CREATE TRIGGER recallops_release_identity_immutable
BEFORE UPDATE ON release_evidence_records
FOR EACH ROW
EXECUTE FUNCTION recallops_guard_release_identity();

GRANT SELECT, INSERT, UPDATE ON TABLE authority_receipts TO recallops_api;
GRANT SELECT, INSERT, UPDATE ON TABLE authority_receipts TO recallops_outbox;
GRANT SELECT ON TABLE authority_events TO recallops_outbox;
GRANT SELECT ON TABLE authority_ledger_heads TO recallops_outbox;
GRANT SELECT ON TABLE judge_runs TO recallops_outbox;
GRANT SELECT ON TABLE release_evidence_records TO recallops_api;
GRANT SELECT, INSERT, UPDATE ON TABLE release_evidence_records TO recallops_outbox;
