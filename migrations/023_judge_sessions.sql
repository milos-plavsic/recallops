CREATE TABLE IF NOT EXISTS judge_sessions (
    session_hash STRING PRIMARY KEY CHECK (session_hash ~ '^[a-f0-9]{64}$'),
    csrf_hash STRING NOT NULL CHECK (csrf_hash ~ '^[a-f0-9]{64}$'),
    tenant_id STRING NOT NULL,
    subject STRING NOT NULL,
    role STRING NOT NULL CHECK (role IN ('operator', 'reviewer')),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    INDEX judge_sessions_expiry (expires_at)
);

CREATE TABLE IF NOT EXISTS judge_auth_attempts (
    client_hash STRING PRIMARY KEY CHECK (client_hash ~ '^[a-f0-9]{64}$'),
    window_started TIMESTAMPTZ NOT NULL,
    attempts INT8 NOT NULL CHECK (attempts > 0)
);

GRANT SELECT, INSERT, UPDATE ON TABLE judge_sessions TO recallops_api;
GRANT SELECT, INSERT, UPDATE ON TABLE judge_auth_attempts TO recallops_api;
