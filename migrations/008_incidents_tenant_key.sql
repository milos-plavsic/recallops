CREATE UNIQUE INDEX IF NOT EXISTS incidents_id_tenant_key ON incidents (id, tenant_id);
