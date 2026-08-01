ALTER TABLE evidence_outbox ADD CONSTRAINT IF NOT EXISTS outbox_incident_tenant_fk
    FOREIGN KEY (incident_id, tenant_id) REFERENCES incidents (id, tenant_id);
