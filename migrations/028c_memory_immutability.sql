ALTER TABLE memories ADD CONSTRAINT IF NOT EXISTS memories_conclusive_active_check
    CHECK (state != 'active' OR outcome_semantics != 'inconclusive');

CREATE OR REPLACE FUNCTION recallops_guard_memory_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF (OLD).tenant_id IS DISTINCT FROM (NEW).tenant_id
       OR (OLD).service IS DISTINCT FROM (NEW).service
       OR (OLD).service_version IS DISTINCT FROM (NEW).service_version
       OR (OLD).compatibility_policy IS DISTINCT FROM (NEW).compatibility_policy
       OR (OLD).compatibility_policy_version IS DISTINCT FROM (NEW).compatibility_policy_version
       OR (OLD).symptom IS DISTINCT FROM (NEW).symptom
       OR (OLD).action IS DISTINCT FROM (NEW).action
       OR (OLD).outcome IS DISTINCT FROM (NEW).outcome
       OR (OLD).outcome_score IS DISTINCT FROM (NEW).outcome_score
       OR (OLD).confidence IS DISTINCT FROM (NEW).confidence
       OR (OLD).source_incident_id IS DISTINCT FROM (NEW).source_incident_id
       OR (OLD).observed_by IS DISTINCT FROM (NEW).observed_by
       OR (OLD).evidence_verification IS DISTINCT FROM (NEW).evidence_verification
       OR (OLD).evidence_refs IS DISTINCT FROM (NEW).evidence_refs
       OR (OLD).observation_window_seconds IS DISTINCT FROM (NEW).observation_window_seconds
       OR (OLD).postconditions IS DISTINCT FROM (NEW).postconditions
       OR (OLD).observation_digest IS DISTINCT FROM (NEW).observation_digest
       OR (OLD).assessment_digest IS DISTINCT FROM (NEW).assessment_digest
       OR (OLD).verdict_digest IS DISTINCT FROM (NEW).verdict_digest
       OR (OLD).memory_digest IS DISTINCT FROM (NEW).memory_digest
       OR (OLD).governance_policy_version IS DISTINCT FROM (NEW).governance_policy_version
       OR (OLD).embedding_space IS DISTINCT FROM (NEW).embedding_space
       OR (OLD).embedding IS DISTINCT FROM (NEW).embedding
       OR (OLD).created_at IS DISTINCT FROM (NEW).created_at
    THEN
        RAISE EXCEPTION 'memory evidence is immutable' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS recallops_memory_evidence_immutable ON memories;
CREATE TRIGGER recallops_memory_evidence_immutable
BEFORE UPDATE ON memories
FOR EACH ROW
EXECUTE FUNCTION recallops_guard_memory_evidence();
