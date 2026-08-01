CREATE INDEX IF NOT EXISTS memories_embedding_space_lookup
    ON memories (tenant_id, service, embedding_space, state, created_at DESC);
