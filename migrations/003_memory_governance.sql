ALTER TABLE memories ADD COLUMN IF NOT EXISTS state STRING NOT NULL DEFAULT 'active';
ALTER TABLE memories ADD COLUMN IF NOT EXISTS observed_by STRING NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS reviewed_by STRING NULL;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ NULL;

UPDATE memories
SET state = 'quarantined', valid = false
WHERE source_incident_id IS NOT NULL AND observed_by IS NULL;

ALTER TABLE memories ADD CONSTRAINT IF NOT EXISTS memories_state_check
    CHECK (state IN ('pending_review', 'active', 'quarantined', 'superseded', 'revoked'));

CREATE INDEX IF NOT EXISTS memories_governed_lookup
    ON memories (tenant_id, service, state, created_at DESC);

CREATE TABLE IF NOT EXISTS memory_events (
    id UUID PRIMARY KEY,
    memory_id UUID NOT NULL REFERENCES memories(id),
    tenant_id STRING NOT NULL,
    actor_id STRING NOT NULL,
    action STRING NOT NULL CHECK (action IN ('activate', 'quarantine', 'supersede', 'revoke')),
    reason STRING NOT NULL,
    from_state STRING NOT NULL,
    to_state STRING NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    INDEX memory_events_tenant_memory_created (tenant_id, memory_id, created_at DESC)
);
