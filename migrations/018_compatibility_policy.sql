ALTER TABLE memories ADD COLUMN IF NOT EXISTS compatibility_policy STRING NOT NULL
    DEFAULT 'exact'
    CHECK (compatibility_policy IN ('exact', 'semver_patch', 'semver_minor'));
ALTER TABLE memories ADD COLUMN IF NOT EXISTS compatibility_policy_version STRING NOT NULL
    DEFAULT 'semver-v1'
    CHECK (length(compatibility_policy_version) BETWEEN 3 AND 80);

CREATE INDEX IF NOT EXISTS memories_compatibility_lookup
    ON memories (tenant_id, service, compatibility_policy, service_version, state, created_at DESC);
