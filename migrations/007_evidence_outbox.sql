CREATE TABLE IF NOT EXISTS evidence_outbox (
    id UUID PRIMARY KEY,
    incident_id UUID NOT NULL UNIQUE REFERENCES incidents(id),
    tenant_id STRING NOT NULL,
    service STRING NOT NULL,
    service_version STRING NOT NULL,
    payload JSONB NOT NULL,
    attempts INT8 NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_by STRING NULL,
    claimed_until TIMESTAMPTZ NULL,
    delivered_at TIMESTAMPTZ NULL,
    last_error STRING NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    INDEX evidence_outbox_pending (delivered_at, available_at, created_at)
);
