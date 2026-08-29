CREATE TABLE IF NOT EXISTS judge_runs (
    run_id UUID PRIMARY KEY,
    tenant_id STRING NOT NULL UNIQUE,
    generation INT8 NOT NULL CHECK (generation > 0),
    scenario_version STRING NOT NULL,
    source_incident_id UUID NOT NULL,
    status STRING NOT NULL CHECK (status IN ('active', 'completed', 'reset', 'expired')),
    operator_subject STRING NOT NULL,
    build_sha STRING NOT NULL,
    capability_policy_version STRING NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    finalized_at TIMESTAMPTZ NULL,
    reset_at TIMESTAMPTZ NULL,
    UNIQUE (run_id, tenant_id),
    FOREIGN KEY (source_incident_id, tenant_id) REFERENCES incidents (id, tenant_id),
    INDEX judge_runs_status_expiry (status, expires_at)
);

ALTER TABLE judge_sessions ADD COLUMN IF NOT EXISTS run_id UUID NULL;
ALTER TABLE judge_sessions ADD COLUMN IF NOT EXISTS session_role STRING NULL;
ALTER TABLE judge_sessions ADD COLUMN IF NOT EXISTS session_generation INT8 NULL;
ALTER TABLE judge_sessions ADD COLUMN IF NOT EXISTS review_handoff_hash STRING NULL;
-- Sessions are deliberately ephemeral. Invalidate every pre-run legacy session at the
-- authority-model upgrade instead of retaining an unbound credential.
DELETE FROM judge_sessions;
ALTER TABLE judge_sessions ALTER COLUMN run_id SET NOT NULL;
ALTER TABLE judge_sessions ALTER COLUMN session_role SET NOT NULL;
ALTER TABLE judge_sessions ALTER COLUMN session_generation SET NOT NULL;
ALTER TABLE judge_sessions ADD CONSTRAINT IF NOT EXISTS judge_sessions_role_check
    CHECK (session_role IS NULL OR session_role IN ('operator', 'reviewer'));
ALTER TABLE judge_sessions ADD CONSTRAINT IF NOT EXISTS judge_sessions_generation_check
    CHECK (session_generation IS NULL OR session_generation > 0);
ALTER TABLE judge_sessions ADD CONSTRAINT IF NOT EXISTS judge_sessions_run_tenant_fk
    FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS judge_sessions_live_role_subject
    ON judge_sessions (run_id, session_role, subject)
    WHERE revoked_at IS NULL AND run_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS review_handoffs (
    code_hash STRING PRIMARY KEY CHECK (code_hash ~ '^[a-f0-9]{64}$'),
    run_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    workflow_id UUID NOT NULL,
    memory_id UUID NOT NULL,
    memory_digest STRING NOT NULL CHECK (memory_digest ~ '^[a-f0-9]{64}$'),
    purpose STRING NOT NULL CHECK (purpose IN ('initial_review', 'revocation')),
    issued_by_subject STRING NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id),
    FOREIGN KEY (workflow_id, tenant_id) REFERENCES webmcp_workflows (workflow_id, tenant_id),
    FOREIGN KEY (memory_id, tenant_id) REFERENCES memories (id, tenant_id),
    INDEX review_handoffs_run_expiry (run_id, expires_at)
);

ALTER TABLE judge_sessions ADD CONSTRAINT IF NOT EXISTS judge_sessions_handoff_fk
    FOREIGN KEY (review_handoff_hash) REFERENCES review_handoffs (code_hash);
ALTER TABLE judge_sessions ADD CONSTRAINT IF NOT EXISTS judge_sessions_role_scope_check
    CHECK (
        (session_role = 'operator' AND review_handoff_hash IS NULL)
        OR (session_role = 'reviewer' AND review_handoff_hash IS NOT NULL)
    );
CREATE UNIQUE INDEX IF NOT EXISTS judge_sessions_one_reviewer_per_handoff
    ON judge_sessions (review_handoff_hash)
    WHERE review_handoff_hash IS NOT NULL;

GRANT SELECT, INSERT, UPDATE ON TABLE judge_runs TO recallops_api;
GRANT SELECT, INSERT, UPDATE ON TABLE review_handoffs TO recallops_api;
