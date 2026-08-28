CREATE TABLE IF NOT EXISTS webmcp_workflows (
    workflow_id UUID NOT NULL,
    tenant_id STRING NOT NULL,
    state STRING NOT NULL CHECK (state IN (
        'INVESTIGATING',
        'AWAITING_OPERATOR_APPROVAL',
        'APPROVED_AWAITING_EXECUTION',
        'OBSERVING_POSTCHECK',
        'POSTCHECK_READY',
        'POSTCHECK_UNAVAILABLE',
        'PENDING_REVIEW',
        'REVIEWED'
    )),
    epoch INT8 NOT NULL CHECK (epoch > 0),
    active BOOL NOT NULL DEFAULT true,
    proposal_hash STRING NULL CHECK (proposal_hash ~ '^[a-f0-9]{64}$'),
    operator_subject STRING NULL,
    reviewer_subject STRING NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workflow_id, tenant_id),
    CONSTRAINT webmcp_workflow_incident_fk
        FOREIGN KEY (workflow_id, tenant_id) REFERENCES incidents(id, tenant_id),
    INDEX webmcp_workflows_tenant_state (tenant_id, active, state, updated_at DESC)
);

GRANT SELECT, INSERT, UPDATE ON TABLE webmcp_workflows TO recallops_api;
