ALTER TABLE memories DROP CONSTRAINT IF EXISTS check_state;
ALTER TABLE memories DROP CONSTRAINT IF EXISTS memories_state_check;
ALTER TABLE memories ADD CONSTRAINT memories_state_check CHECK (state IN (
    'pending_review', 'active', 'quarantined', 'rejected',
    'superseded', 'revoked', 'expired'
));

-- The policy outcome is database-derived and therefore cannot diverge from the score.
ALTER TABLE memories ADD COLUMN IF NOT EXISTS outcome_semantics STRING AS (
    CASE
        WHEN outcome_score > 0 THEN 'positive'
        WHEN outcome_score < 0 THEN 'negative'
        ELSE 'inconclusive'
    END
) STORED;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS observation_digest STRING NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS assessment_digest STRING NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS verdict_digest STRING NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS memory_digest STRING NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS governance_policy_version STRING NOT NULL
    DEFAULT 'memory-governance-v1';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS governance_version INT8 NOT NULL DEFAULT 1
    CHECK (governance_version > 0);
ALTER TABLE memories ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS superseded_at TIMESTAMPTZ NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL;

ALTER TABLE memory_events DROP CONSTRAINT IF EXISTS check_action;
ALTER TABLE memory_events ADD CONSTRAINT memory_events_action_check CHECK (action IN (
    'certify', 'activate', 'quarantine', 'reject', 'supersede', 'revoke', 'expire'
));
ALTER TABLE memory_events ADD COLUMN IF NOT EXISTS reason_code STRING NOT NULL
    DEFAULT 'OTHER_BOUNDED';
ALTER TABLE memory_events ADD COLUMN IF NOT EXISTS memory_digest STRING NULL;
ALTER TABLE memory_events ADD COLUMN IF NOT EXISTS workflow_epoch INT8 NULL
    CHECK (workflow_epoch IS NULL OR workflow_epoch > 0);
ALTER TABLE memory_events ADD COLUMN IF NOT EXISTS run_id UUID NULL;
ALTER TABLE memory_events ADD COLUMN IF NOT EXISTS authority_event_id UUID NULL;
ALTER TABLE memory_events ADD CONSTRAINT IF NOT EXISTS memory_events_run_tenant_fk
    FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id);
