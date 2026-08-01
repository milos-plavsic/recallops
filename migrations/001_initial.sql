CREATE DATABASE IF NOT EXISTS recallops;
USE recallops;

SET CLUSTER SETTING feature.vector_index.enabled = true;

CREATE TABLE IF NOT EXISTS memories (
    id UUID PRIMARY KEY,
    tenant_id STRING NOT NULL,
    service STRING NOT NULL,
    service_version STRING NOT NULL,
    symptom STRING NOT NULL,
    action STRING NOT NULL,
    outcome STRING NOT NULL,
    outcome_score FLOAT8 NOT NULL CHECK (outcome_score BETWEEN -1 AND 1),
    confidence FLOAT8 NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    valid BOOL NOT NULL DEFAULT true,
    state STRING NOT NULL DEFAULT 'active'
        CHECK (state IN ('pending_review', 'active', 'quarantined', 'superseded', 'revoked')),
    superseded_by UUID NULL REFERENCES memories(id),
    source_incident_id UUID NULL,
    observed_by STRING NULL,
    reviewed_by STRING NULL,
    reviewed_at TIMESTAMPTZ NULL,
    embedding VECTOR(1024) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    INDEX memories_lookup (tenant_id, service, valid, created_at DESC),
    VECTOR INDEX memories_embedding (tenant_id, service, embedding vector_cosine_ops)
);

CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY,
    tenant_id STRING NOT NULL,
    service STRING NOT NULL,
    service_version STRING NOT NULL,
    symptom STRING NOT NULL,
    idempotency_key STRING NOT NULL,
    status STRING NOT NULL CHECK (status IN ('open', 'mitigated')),
    analysis JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, idempotency_key),
    INDEX incidents_tenant_created (tenant_id, created_at DESC)
);

CREATE TABLE IF NOT EXISTS approvals (
    incident_id UUID PRIMARY KEY REFERENCES incidents(id),
    tenant_id STRING NOT NULL,
    actor_id STRING NOT NULL,
    approved BOOL NOT NULL,
    reason STRING NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    INDEX approvals_tenant_created (tenant_id, created_at DESC)
);
