CREATE TABLE IF NOT EXISTS authority_ledger_heads (
    run_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    last_sequence INT8 NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
    last_event_hash STRING NOT NULL DEFAULT repeat('0', 64)
        CHECK (last_event_hash ~ '^[a-f0-9]{64}$'),
    last_receipted_sequence INT8 NOT NULL DEFAULT 0
        CHECK (last_receipted_sequence >= 0 AND last_receipted_sequence <= last_sequence),
    closed BOOL NOT NULL DEFAULT false,
    ledger_version STRING NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (run_id, tenant_id),
    CONSTRAINT authority_ledger_head_run_tenant_fk
        FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS authority_events (
    event_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    sequence INT8 NOT NULL CHECK (sequence > 0),
    recorded_at TIMESTAMPTZ NOT NULL,
    event_type STRING NOT NULL CHECK (length(event_type) BETWEEN 1 AND 100),
    outcome STRING NOT NULL CHECK (outcome IN ('accepted', 'denied', 'observed')),
    actor_subject STRING NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 200),
    actor_role STRING NOT NULL CHECK (actor_role IN ('agent', 'operator', 'reviewer', 'system')),
    channel STRING NOT NULL CHECK (channel IN ('webmcp', 'ui', 'system')),
    workflow_id UUID NOT NULL,
    epoch_before INT8 NOT NULL CHECK (epoch_before >= 0),
    epoch_after INT8 NOT NULL CHECK (epoch_after = epoch_before + 1),
    state_before STRING NOT NULL,
    state_after STRING NOT NULL,
    capabilities_before JSONB NOT NULL,
    capabilities_after JSONB NOT NULL,
    object_type STRING NULL CHECK (object_type IS NULL OR length(object_type) BETWEEN 1 AND 80),
    object_id STRING NULL CHECK (object_id IS NULL OR length(object_id) BETWEEN 1 AND 200),
    object_digest STRING NULL CHECK (object_digest IS NULL OR object_digest ~ '^[a-f0-9]{64}$'),
    reason_code STRING NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 100),
    display_summary STRING NOT NULL CHECK (length(display_summary) BETWEEN 1 AND 240),
    policy_version STRING NOT NULL,
    build_sha STRING NOT NULL,
    previous_event_hash STRING NOT NULL CHECK (previous_event_hash ~ '^[a-f0-9]{64}$'),
    event_hash STRING NOT NULL UNIQUE CHECK (event_hash ~ '^[a-f0-9]{64}$'),
    UNIQUE (run_id, sequence),
    UNIQUE (event_id, run_id, tenant_id, workflow_id),
    CONSTRAINT authority_events_run_tenant_fk
        FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id),
    CONSTRAINT authority_events_workflow_tenant_fk FOREIGN KEY (workflow_id, tenant_id)
        REFERENCES webmcp_workflows (workflow_id, tenant_id),
    INDEX authority_events_run_order (run_id, sequence)
);

CREATE TABLE IF NOT EXISTS activity_observations (
    activity_id UUID PRIMARY KEY,
    run_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    workflow_id UUID NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    source STRING NOT NULL CHECK (source IN ('webmcp', 'browser', 'server')),
    actor_subject STRING NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 200),
    activity_type STRING NOT NULL CHECK (length(activity_type) BETWEEN 1 AND 100),
    tool_name STRING NULL CHECK (tool_name IS NULL OR length(tool_name) BETWEEN 1 AND 100),
    outcome STRING NOT NULL CHECK (length(outcome) BETWEEN 1 AND 80),
    display_summary STRING NOT NULL CHECK (length(display_summary) BETWEEN 1 AND 240),
    authority_event_id UUID NULL,
    object_digest STRING NULL CHECK (object_digest IS NULL OR object_digest ~ '^[a-f0-9]{64}$'),
    build_sha STRING NOT NULL,
    client_instance_id_hash STRING NULL
        CHECK (client_instance_id_hash IS NULL OR client_instance_id_hash ~ '^[a-f0-9]{64}$'),
    CONSTRAINT activity_observations_run_tenant_fk
        FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id),
    CONSTRAINT activity_observations_workflow_tenant_fk FOREIGN KEY (workflow_id, tenant_id)
        REFERENCES webmcp_workflows (workflow_id, tenant_id),
    CONSTRAINT activity_observations_authority_event_fk
        FOREIGN KEY (authority_event_id, run_id, tenant_id, workflow_id)
        REFERENCES authority_events (event_id, run_id, tenant_id, workflow_id),
    INDEX activity_observations_run_order (run_id, recorded_at, activity_id)
);

GRANT SELECT, INSERT, UPDATE ON TABLE authority_ledger_heads TO recallops_api;
GRANT SELECT, INSERT ON TABLE authority_events TO recallops_api;
GRANT SELECT, INSERT ON TABLE activity_observations TO recallops_api;
