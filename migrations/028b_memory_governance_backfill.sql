UPDATE memories SET memory_digest = sha256((
    'recallops-legacy-memory-v1' || chr(0) || id::STRING || chr(0) || tenant_id || chr(0)
    || service || chr(0) || service_version || chr(0) || action || chr(0)
    || created_at::STRING
)::BYTES)::STRING,
governance_policy_version = 'legacy-memory-v1'
WHERE memory_digest IS NULL;
ALTER TABLE memories ALTER COLUMN memory_digest SET NOT NULL;
ALTER TABLE memories ADD CONSTRAINT IF NOT EXISTS memories_digest_check
    CHECK (memory_digest ~ '^[a-f0-9]{64}$');
CREATE UNIQUE INDEX IF NOT EXISTS memories_tenant_digest_key
    ON memories (tenant_id, memory_digest);

UPDATE memories SET state='quarantined', valid=false
WHERE state='active' AND outcome_semantics='inconclusive';
UPDATE memories SET
    superseded_at=COALESCE(superseded_at, reviewed_at, created_at)
WHERE state='superseded';
UPDATE memories SET
    revoked_at=COALESCE(revoked_at, reviewed_at, created_at)
WHERE state='revoked';
UPDATE memories SET valid = (state = 'active');
ALTER TABLE memories ADD CONSTRAINT IF NOT EXISTS memories_admissibility_check
    CHECK (valid = (state = 'active'));
ALTER TABLE memories ADD CONSTRAINT IF NOT EXISTS memories_disposition_timestamps_check CHECK (
    (state != 'superseded' OR superseded_at IS NOT NULL)
    AND (state != 'revoked' OR revoked_at IS NOT NULL)
    AND (state != 'expired' OR expires_at IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS memories_admissible_lookup
    ON memories (tenant_id, service, state, expires_at, created_at DESC);

UPDATE memory_events AS e SET memory_digest=m.memory_digest
FROM memories AS m WHERE e.memory_id=m.id AND e.tenant_id=m.tenant_id
  AND e.memory_digest IS NULL;
ALTER TABLE memory_events ALTER COLUMN memory_digest SET NOT NULL;
ALTER TABLE memory_events ADD CONSTRAINT IF NOT EXISTS memory_events_digest_check
    CHECK (memory_digest ~ '^[a-f0-9]{64}$');
