ALTER TABLE approvals ADD COLUMN IF NOT EXISTS proposal_hash STRING NULL
    CHECK (proposal_hash ~ '^[a-f0-9]{64}$');
