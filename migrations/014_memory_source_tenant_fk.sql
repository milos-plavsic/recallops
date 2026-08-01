ALTER TABLE memories ADD CONSTRAINT IF NOT EXISTS memories_source_incident_tenant_fk
    FOREIGN KEY (source_incident_id, tenant_id) REFERENCES incidents (id, tenant_id);
