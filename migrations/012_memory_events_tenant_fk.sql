ALTER TABLE memory_events ADD CONSTRAINT IF NOT EXISTS memory_events_memory_tenant_fk
    FOREIGN KEY (memory_id, tenant_id) REFERENCES memories (id, tenant_id);
