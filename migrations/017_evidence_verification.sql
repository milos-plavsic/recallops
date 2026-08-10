ALTER TABLE memories ADD COLUMN IF NOT EXISTS evidence_verification STRING NOT NULL
    DEFAULT 'manual_attestation'
    CHECK (evidence_verification IN ('manual_attestation', 'system_observed', 'externally_verified'));
ALTER TABLE memories ADD COLUMN IF NOT EXISTS evidence_refs JSONB NOT NULL DEFAULT '[]'::JSONB;
ALTER TABLE memories ADD COLUMN IF NOT EXISTS observation_window_seconds INT8 NULL
    CHECK (observation_window_seconds IS NULL OR observation_window_seconds BETWEEN 1 AND 2592000);
ALTER TABLE memories ADD COLUMN IF NOT EXISTS postconditions JSONB NOT NULL DEFAULT '[]'::JSONB;

ALTER TABLE execution_attestations ADD COLUMN IF NOT EXISTS evidence_verification STRING NOT NULL
    DEFAULT 'manual_attestation'
    CHECK (evidence_verification IN ('manual_attestation', 'system_observed', 'externally_verified'));
