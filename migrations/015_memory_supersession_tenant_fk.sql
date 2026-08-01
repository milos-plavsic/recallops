ALTER TABLE memories ADD CONSTRAINT IF NOT EXISTS memories_supersession_tenant_fk
    FOREIGN KEY (superseded_by, tenant_id) REFERENCES memories (id, tenant_id);
