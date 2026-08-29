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
    synthetic BOOL NOT NULL DEFAULT false,
    bundle_object_key STRING NULL CHECK (
        bundle_object_key IS NULL OR length(bundle_object_key) BETWEEN 16 AND 1024
    ),
    s3_version_id STRING NULL CHECK (s3_version_id IS NULL OR length(s3_version_id) BETWEEN 1 AND 1024),
    public_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    signed_at TIMESTAMPTZ NULL,
    failure_code STRING NULL CHECK (failure_code IS NULL OR length(failure_code) BETWEEN 1 AND 100),
    CONSTRAINT authority_receipts_run_tenant_fk
        FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id),
    CONSTRAINT authority_receipts_signed_complete CHECK (
        status != 'signed' OR (
            manifest_digest IS NOT NULL AND bundle_digest IS NOT NULL AND jws_compact IS NOT NULL
            AND key_thumbprint IS NOT NULL AND signing_algorithm = 'Ed25519'
            AND bundle_object_key IS NOT NULL AND s3_version_id IS NOT NULL
            AND signed_at IS NOT NULL AND failure_code IS NULL
        )
    ),
    CONSTRAINT authority_receipts_failed_bounded CHECK (
        status != 'failed' OR (failure_code IS NOT NULL AND signed_at IS NULL)
    ),
    UNIQUE (receipt_id, run_id, tenant_id)
);

ALTER TABLE authority_receipts ADD COLUMN IF NOT EXISTS synthetic BOOL NOT NULL DEFAULT false;
ALTER TABLE authority_receipts ADD COLUMN IF NOT EXISTS bundle_object_key STRING NULL;
ALTER TABLE authority_receipts ADD COLUMN IF NOT EXISTS public_at TIMESTAMPTZ NULL;
ALTER TABLE authority_receipts DROP CONSTRAINT IF EXISTS authority_receipts_signed_complete;
ALTER TABLE authority_receipts ADD CONSTRAINT authority_receipts_signed_complete CHECK (
    status != 'signed' OR (
        manifest_digest IS NOT NULL AND bundle_digest IS NOT NULL AND jws_compact IS NOT NULL
        AND key_thumbprint IS NOT NULL AND signing_algorithm = 'Ed25519'
        AND bundle_object_key IS NOT NULL AND s3_version_id IS NOT NULL
        AND signed_at IS NOT NULL AND failure_code IS NULL
    )
);
ALTER TABLE authority_receipts DROP CONSTRAINT IF EXISTS authority_receipts_public_finalized;
ALTER TABLE authority_receipts ADD CONSTRAINT authority_receipts_public_finalized CHECK (
    public_at IS NULL OR (
        synthetic AND status = 'signed' AND bundle_object_key IS NOT NULL
        AND s3_version_id IS NOT NULL AND bundle_digest IS NOT NULL
    )
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
       OR (OLD).synthetic IS DISTINCT FROM (NEW).synthetic
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
       OR (OLD).bundle_object_key IS DISTINCT FROM (NEW).bundle_object_key
       OR (OLD).signed_at IS DISTINCT FROM (NEW).signed_at
       OR (OLD).public_at IS DISTINCT FROM (NEW).public_at
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

CREATE TABLE IF NOT EXISTS receipt_requests (
    request_id UUID PRIMARY KEY,
    receipt_id UUID NOT NULL UNIQUE,
    run_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    event_type STRING NOT NULL DEFAULT 'receipt_requested'
        CHECK (event_type = 'receipt_requested'),
    target_sequence INT8 NOT NULL CHECK (target_sequence > 0),
    target_ledger_hash STRING NOT NULL CHECK (target_ledger_hash ~ '^[a-f0-9]{64}$'),
    publish_public BOOL NOT NULL DEFAULT false,
    status STRING NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','processing','delivered','dead_lettered')),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_by STRING NULL CHECK (claimed_by IS NULL OR length(claimed_by) BETWEEN 1 AND 200),
    claimed_until TIMESTAMPTZ NULL,
    attempts INT8 NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error_code STRING NULL CHECK (
        last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 100
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at TIMESTAMPTZ NULL,
    dead_lettered_at TIMESTAMPTZ NULL,
    CONSTRAINT receipt_requests_receipt_fk
        FOREIGN KEY (receipt_id, run_id, tenant_id)
        REFERENCES authority_receipts (receipt_id, run_id, tenant_id),
    CONSTRAINT receipt_requests_status_shape CHECK (
        (status = 'pending' AND delivered_at IS NULL AND dead_lettered_at IS NULL)
        OR (status = 'processing' AND claimed_by IS NOT NULL AND claimed_until IS NOT NULL
            AND delivered_at IS NULL AND dead_lettered_at IS NULL)
        OR (status = 'delivered' AND delivered_at IS NOT NULL AND dead_lettered_at IS NULL)
        OR (status = 'dead_lettered' AND delivered_at IS NULL AND dead_lettered_at IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS receipt_requests_claimable
    ON receipt_requests (status, available_at, created_at);

CREATE OR REPLACE FUNCTION recallops_guard_receipt_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD).receipt_id IS DISTINCT FROM (NEW).receipt_id
       OR (OLD).run_id IS DISTINCT FROM (NEW).run_id
       OR (OLD).tenant_id IS DISTINCT FROM (NEW).tenant_id
       OR (OLD).event_type IS DISTINCT FROM (NEW).event_type
       OR (OLD).target_sequence IS DISTINCT FROM (NEW).target_sequence
       OR (OLD).target_ledger_hash IS DISTINCT FROM (NEW).target_ledger_hash
       OR (OLD).publish_public IS DISTINCT FROM (NEW).publish_public
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
    THEN
        RAISE EXCEPTION 'receipt request binding is immutable' USING ERRCODE = '23514';
    END IF;
    IF NOT (
       ((OLD).status = 'pending' AND (NEW).status IN ('pending','processing','dead_lettered'))
       OR ((OLD).status = 'processing' AND (NEW).status IN ('processing','pending','delivered','dead_lettered'))
       OR ((OLD).status = 'delivered' AND (NEW).status = 'delivered')
       OR ((OLD).status = 'dead_lettered' AND (NEW).status = 'dead_lettered')
    )
    THEN
        RAISE EXCEPTION 'invalid receipt request status transition' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS recallops_receipt_request_immutable ON receipt_requests;
CREATE TRIGGER recallops_receipt_request_immutable
BEFORE UPDATE ON receipt_requests
FOR EACH ROW
EXECUTE FUNCTION recallops_guard_receipt_request();

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
GRANT INSERT ON TABLE receipt_requests TO recallops_api;
GRANT SELECT, UPDATE ON TABLE receipt_requests TO recallops_outbox;
GRANT SELECT ON TABLE authority_events TO recallops_outbox;
GRANT SELECT ON TABLE authority_ledger_heads TO recallops_outbox;
GRANT SELECT ON TABLE judge_runs TO recallops_outbox;
GRANT SELECT ON TABLE release_evidence_records TO recallops_api;
GRANT SELECT, INSERT, UPDATE ON TABLE release_evidence_records TO recallops_outbox;
