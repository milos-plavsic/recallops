CREATE VECTOR INDEX IF NOT EXISTS memories_embedding_v2
    ON memories (tenant_id, service, embedding_space, embedding vector_cosine_ops);
