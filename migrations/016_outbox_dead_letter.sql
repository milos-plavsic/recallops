ALTER TABLE evidence_outbox
    ADD COLUMN IF NOT EXISTS dead_lettered_at TIMESTAMPTZ NULL;

CREATE INDEX IF NOT EXISTS evidence_outbox_dead_lettered
    ON evidence_outbox (dead_lettered_at, created_at)
    WHERE dead_lettered_at IS NOT NULL;
