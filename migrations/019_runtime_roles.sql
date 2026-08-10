-- Runtime identities must not own the schema. These NOLOGIN roles are privilege
-- bundles: deployment automation grants one of them to a separately provisioned
-- LOGIN user whose credential is stored in Secrets Manager.
CREATE ROLE IF NOT EXISTS recallops_api;
CREATE ROLE IF NOT EXISTS recallops_outbox;

-- A compromised runtime credential must not be able to create shadow objects in
-- the application schema. The migration owner retains ownership and can migrate.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

GRANT USAGE ON SCHEMA public TO recallops_api;
GRANT USAGE ON SCHEMA public TO recallops_outbox;

-- API: only the reads and writes exercised by PostgresStore. DELETE, schema
-- mutation, role administration, cluster privileges, and migration-ledger access
-- are intentionally absent.
GRANT SELECT, INSERT, UPDATE ON TABLE incidents TO recallops_api;
GRANT SELECT, INSERT, UPDATE ON TABLE memories TO recallops_api;
GRANT SELECT, INSERT ON TABLE approvals TO recallops_api;
GRANT SELECT, INSERT, UPDATE ON TABLE execution_attestations TO recallops_api;
GRANT INSERT ON TABLE memory_events TO recallops_api;
GRANT INSERT ON TABLE evidence_outbox TO recallops_api;

-- Worker: lease and deliver outbox rows, without reading incident/memory payloads
-- from any other table or changing application/governance state.
GRANT SELECT, UPDATE ON TABLE evidence_outbox TO recallops_outbox;
