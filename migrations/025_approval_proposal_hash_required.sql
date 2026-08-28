UPDATE approvals AS a
SET proposal_hash = i.analysis->'proposed_action'->>'action_hash'
FROM incidents AS i
WHERE a.incident_id = i.id AND a.tenant_id = i.tenant_id AND a.proposal_hash IS NULL;

ALTER TABLE approvals ALTER COLUMN proposal_hash SET NOT NULL;
