-- CockroachDB requires read authority on the referencing memory_events table when
-- its parent memory row is updated. Keep that authority out of the API credential:
-- one non-login role owns a policy-enforcing SECURITY DEFINER routine instead.
CREATE ROLE IF NOT EXISTS recallops_governor;
GRANT USAGE, CREATE ON SCHEMA public TO recallops_governor;
-- CockroachDB revalidates the source_incident composite foreign key when the
-- memory row is updated. This is the minimum additional read dependency.
GRANT SELECT ON TABLE incidents TO recallops_governor;
-- memory_events may optionally bind its audit entry to a judge run; the FK is
-- checked for every insert, including the unbound legacy lifecycle path.
GRANT SELECT ON TABLE judge_runs TO recallops_governor;
GRANT SELECT, UPDATE ON TABLE memories TO recallops_governor;
GRANT SELECT, INSERT ON TABLE memory_events TO recallops_governor;
-- The review handoff has a composite foreign key back to memories; CockroachDB
-- checks it on the parent update even though the key columns remain unchanged.
GRANT SELECT ON TABLE review_handoffs TO recallops_governor;

CREATE OR REPLACE FUNCTION recallops_govern_memory(
    p_memory_id UUID,
    p_tenant_id STRING,
    p_actor_id STRING,
    p_action STRING,
    p_reason STRING,
    p_reason_code STRING,
    p_replacement_memory_id UUID
) RETURNS UUID
LANGUAGE PLpgSQL
SECURITY DEFINER
AS $$
DECLARE
    v_state STRING;
    v_outcome_semantics STRING;
    v_observed_by STRING;
    v_memory_digest STRING;
    v_service STRING;
    v_service_version STRING;
    v_replacement_service_version STRING;
    v_replacement_policy STRING;
    v_target STRING;
    v_reviewed_at TIMESTAMPTZ := now();
BEGIN
    IF length(p_actor_id) < 1 OR length(p_actor_id) > 120
       OR length(p_reason) < 3 OR length(p_reason) > 1000 THEN
        RAISE EXCEPTION 'invalid bounded governance actor or reason';
    END IF;
    IF p_reason_code NOT IN (
        'EVIDENCE_ACCEPTED', 'NEEDS_INVESTIGATION', 'INVALID_BINDING',
        'INSUFFICIENT_EVIDENCE', 'POLICY_CONFLICT', 'NEW_CONTRADICTORY_EVIDENCE',
        'POLICY_CHANGE', 'COMPATIBILITY_INVALIDATED', 'DATA_QUALITY', 'OTHER_BOUNDED'
    ) THEN
        RAISE EXCEPTION 'invalid governance reason code';
    END IF;

    SELECT state,outcome_semantics,observed_by,memory_digest,service,service_version
    INTO v_state,v_outcome_semantics,v_observed_by,v_memory_digest,v_service,v_service_version
    FROM public.memories
    WHERE id=p_memory_id AND tenant_id=p_tenant_id FOR UPDATE;
    IF v_state IS NULL THEN
        RETURN NULL;
    END IF;

    v_target := CASE p_action
        WHEN 'certify' THEN 'active'
        WHEN 'activate' THEN 'active'
        WHEN 'quarantine' THEN 'quarantined'
        WHEN 'reject' THEN 'rejected'
        WHEN 'supersede' THEN 'superseded'
        WHEN 'revoke' THEN 'revoked'
        WHEN 'expire' THEN 'expired'
        ELSE NULL
    END;
    IF v_target IS NULL OR NOT (
        (v_state='pending_review' AND v_target IN ('active','quarantined','rejected'))
        OR (v_state='active' AND v_target IN (
            'quarantined','superseded','revoked','expired'
        ))
        OR (v_state='quarantined' AND v_target IN (
            'active','rejected','revoked','expired'
        ))
    ) THEN
        RAISE EXCEPTION 'invalid memory governance transition';
    END IF;
    IF p_action='certify' AND v_outcome_semantics='inconclusive' THEN
        RAISE EXCEPTION 'inconclusive evidence cannot be certified';
    END IF;
    IF p_action='certify' AND p_reason_code!='EVIDENCE_ACCEPTED' THEN
        RAISE EXCEPTION 'certification requires EVIDENCE_ACCEPTED';
    END IF;
    IF p_action='revoke' AND p_reason_code NOT IN (
        'NEW_CONTRADICTORY_EVIDENCE', 'POLICY_CHANGE', 'COMPATIBILITY_INVALIDATED',
        'DATA_QUALITY', 'OTHER_BOUNDED'
    ) THEN
        RAISE EXCEPTION 'invalid revocation reason code';
    END IF;
    IF v_target='active' AND v_observed_by=p_actor_id THEN
        RAISE EXCEPTION 'independent reviewer required for activation';
    END IF;
    IF p_reason_code='OTHER_BOUNDED' AND length(trim(p_reason))=0 THEN
        RAISE EXCEPTION 'OTHER_BOUNDED requires a reviewer note';
    END IF;

    IF v_target='superseded' THEN
        SELECT service_version,compatibility_policy
        INTO v_replacement_service_version,v_replacement_policy
        FROM public.memories
        WHERE id=p_replacement_memory_id
          AND id!=p_memory_id
          AND tenant_id=p_tenant_id
          AND service=v_service
          AND state='active' AND valid
          AND outcome_semantics!='inconclusive'
          AND (expires_at IS NULL OR expires_at > now());
        IF v_replacement_service_version IS NULL THEN
            RAISE EXCEPTION 'active same-tenant replacement memory required';
        END IF;
        IF v_replacement_service_version!=v_service_version AND NOT (
            v_replacement_policy='semver_patch'
            AND v_replacement_service_version
                ~ '^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+].*)?$'
            AND v_service_version ~ '^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+].*)?$'
            AND split_part(ltrim(v_replacement_service_version,'v'),'.',1)
                = split_part(ltrim(v_service_version,'v'),'.',1)
            AND split_part(ltrim(v_replacement_service_version,'v'),'.',2)
                = split_part(ltrim(v_service_version,'v'),'.',2)
            OR v_replacement_policy='semver_minor'
            AND v_replacement_service_version
                ~ '^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+].*)?$'
            AND v_service_version ~ '^v?[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+].*)?$'
            AND split_part(ltrim(v_replacement_service_version,'v'),'.',1)
                = split_part(ltrim(v_service_version,'v'),'.',1)
        ) THEN
            RAISE EXCEPTION 'replacement memory is version-incompatible';
        END IF;
    ELSIF p_replacement_memory_id IS NOT NULL THEN
        RAISE EXCEPTION 'replacement memory is valid only for supersession';
    END IF;

    UPDATE public.memories SET
        state=v_target,
        valid=(v_target='active'),
        reviewed_by=p_actor_id,
        reviewed_at=v_reviewed_at,
        superseded_by=p_replacement_memory_id,
        governance_version=governance_version+1,
        superseded_at=CASE WHEN v_target='superseded'
            THEN v_reviewed_at ELSE superseded_at END,
        revoked_at=CASE WHEN v_target='revoked'
            THEN v_reviewed_at ELSE revoked_at END,
        expires_at=CASE WHEN v_target='expired'
            THEN COALESCE(expires_at,v_reviewed_at) ELSE expires_at END
    WHERE id=p_memory_id AND tenant_id=p_tenant_id;

    INSERT INTO public.memory_events
    (id,memory_id,tenant_id,actor_id,action,reason,reason_code,memory_digest,
     from_state,to_state,created_at)
    VALUES (gen_random_uuid(),p_memory_id,p_tenant_id,p_actor_id,p_action,p_reason,
            p_reason_code,v_memory_digest,v_state,v_target,v_reviewed_at);
    RETURN p_memory_id;
END;
$$;

ALTER FUNCTION recallops_govern_memory(UUID,STRING,STRING,STRING,STRING,STRING,UUID)
    OWNER TO recallops_governor;
REVOKE CREATE ON SCHEMA public FROM recallops_governor;
REVOKE ALL ON FUNCTION
    recallops_govern_memory(UUID,STRING,STRING,STRING,STRING,STRING,UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
    recallops_govern_memory(UUID,STRING,STRING,STRING,STRING,STRING,UUID) TO recallops_api;

REVOKE UPDATE ON TABLE memories FROM recallops_api;
REVOKE INSERT ON TABLE memory_events FROM recallops_api;
