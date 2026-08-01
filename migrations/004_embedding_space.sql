ALTER TABLE memories ADD COLUMN IF NOT EXISTS embedding_space STRING NOT NULL
    DEFAULT 'legacy:unknown:v0';
