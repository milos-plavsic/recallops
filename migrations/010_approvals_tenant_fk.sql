ALTER TABLE approvals ADD CONSTRAINT IF NOT EXISTS approvals_incident_tenant_fk
    FOREIGN KEY (incident_id, tenant_id) REFERENCES incidents (id, tenant_id);
