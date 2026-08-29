CREATE TABLE IF NOT EXISTS webmcp_idempotency (
    run_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    route STRING NOT NULL CHECK (route IN ('proposal', 'assessment')),
    idempotency_key STRING NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 200),
    request_digest STRING NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    response_payload JSONB NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ NULL,
    PRIMARY KEY (run_id, route, idempotency_key),
    CONSTRAINT webmcp_idempotency_run_tenant_fk
        FOREIGN KEY (run_id, tenant_id) REFERENCES judge_runs (run_id, tenant_id)
);

GRANT SELECT, INSERT, UPDATE ON TABLE webmcp_idempotency TO recallops_api;
