CREATE TABLE IF NOT EXISTS execution_attestations (
    incident_id UUID PRIMARY KEY REFERENCES incidents(id),
    tenant_id STRING NOT NULL,
    actor_id STRING NOT NULL,
    action_hash STRING NOT NULL CHECK (length(action_hash) = 64),
    action_taken STRING NOT NULL,
    evidence_refs JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    INDEX executions_tenant_created (tenant_id, created_at DESC)
);
