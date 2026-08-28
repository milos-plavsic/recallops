CREATE TABLE IF NOT EXISTS sandbox_executions (
    id UUID NOT NULL,
    incident_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    actor_id STRING NOT NULL,
    proposal_hash STRING NOT NULL CHECK (proposal_hash ~ '^[a-f0-9]{64}$'),
    action_id STRING NOT NULL CHECK (action_id = 'checkout.reduce_concurrency_and_recycle.v1'),
    simulator_version STRING NOT NULL,
    idempotency_key STRING NOT NULL,
    before_metrics JSONB NOT NULL,
    after_metrics JSONB NOT NULL,
    execution_digest STRING NOT NULL CHECK (execution_digest ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id),
    UNIQUE (id, tenant_id),
    UNIQUE (id, incident_id, tenant_id),
    UNIQUE (tenant_id, idempotency_key),
    CONSTRAINT sandbox_execution_incident_tenant_fk
        FOREIGN KEY (incident_id, tenant_id) REFERENCES incidents (id, tenant_id)
);

CREATE TABLE IF NOT EXISTS postcheck_observations (
    id UUID NOT NULL,
    execution_id UUID NOT NULL,
    incident_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    proposal_hash STRING NOT NULL CHECK (proposal_hash ~ '^[a-f0-9]{64}$'),
    execution_digest STRING NOT NULL CHECK (execution_digest ~ '^[a-f0-9]{64}$'),
    source STRING NOT NULL,
    observation_window_seconds INT8 NOT NULL CHECK (observation_window_seconds BETWEEN 1 AND 3600),
    before_metrics JSONB NOT NULL,
    after_metrics JSONB NOT NULL,
    observation_digest STRING NOT NULL CHECK (observation_digest ~ '^[a-f0-9]{64}$'),
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (incident_id),
    UNIQUE (id, tenant_id),
    UNIQUE (id, incident_id, tenant_id),
    CONSTRAINT postcheck_execution_tenant_fk
        FOREIGN KEY (execution_id, incident_id, tenant_id)
        REFERENCES sandbox_executions (id, incident_id, tenant_id),
    CONSTRAINT postcheck_incident_tenant_fk
        FOREIGN KEY (incident_id, tenant_id) REFERENCES incidents (id, tenant_id)
);

CREATE TABLE IF NOT EXISTS postcheck_policy_verdicts (
    observation_id UUID PRIMARY KEY,
    incident_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    classification STRING NOT NULL CHECK (classification IN (
        'recovered', 'not_recovered', 'inconclusive'
    )),
    policy_version STRING NOT NULL,
    checks_passed JSONB NOT NULL,
    checks_failed JSONB NOT NULL,
    observation_digest STRING NOT NULL CHECK (observation_digest ~ '^[a-f0-9]{64}$'),
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT verdict_observation_tenant_fk
        FOREIGN KEY (observation_id, incident_id, tenant_id)
        REFERENCES postcheck_observations (id, incident_id, tenant_id),
    CONSTRAINT verdict_incident_tenant_fk
        FOREIGN KEY (incident_id, tenant_id) REFERENCES incidents (id, tenant_id)
);

CREATE TABLE IF NOT EXISTS postcheck_assessments (
    id UUID NOT NULL UNIQUE,
    observation_id UUID PRIMARY KEY,
    incident_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    agent_subject STRING NOT NULL,
    classification STRING NOT NULL CHECK (classification IN (
        'recovered', 'not_recovered', 'inconclusive'
    )),
    rationale STRING NOT NULL,
    observation_digest STRING NOT NULL CHECK (observation_digest ~ '^[a-f0-9]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT assessment_observation_tenant_fk
        FOREIGN KEY (observation_id, incident_id, tenant_id)
        REFERENCES postcheck_observations (id, incident_id, tenant_id),
    CONSTRAINT assessment_incident_tenant_fk
        FOREIGN KEY (incident_id, tenant_id) REFERENCES incidents (id, tenant_id)
);

GRANT SELECT, INSERT ON TABLE sandbox_executions TO recallops_api;
GRANT SELECT, INSERT ON TABLE postcheck_observations TO recallops_api;
GRANT SELECT, INSERT ON TABLE postcheck_policy_verdicts TO recallops_api;
GRANT SELECT, INSERT ON TABLE postcheck_assessments TO recallops_api;
