CREATE TABLE brain.memory_consolidation_checkpoints (
    scope_id uuid PRIMARY KEY REFERENCES brain.scopes(id) ON DELETE CASCADE,
    timeline_id uuid NOT NULL,
    change_sequence bigint NOT NULL DEFAULT 0 CHECK (change_sequence >= 0),
    lease_holder uuid,
    lease_token uuid,
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_until timestamptz,
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK ((lease_holder IS NULL AND lease_token IS NULL AND lease_until IS NULL) OR
           (lease_holder IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL))
);

REVOKE ALL ON brain.memory_consolidation_checkpoints FROM PUBLIC;

CREATE FUNCTION brain.claim_memory_consolidation_checkpoint(requested_scope uuid, requested_holder uuid, requested_lease_micros bigint)
RETURNS TABLE(scope_id uuid,timeline_id uuid,change_sequence bigint,lease_holder uuid,lease_token uuid,lease_generation bigint,lease_until timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    IF requested_scope IS NULL OR requested_holder IS NULL OR requested_lease_micros < 5000000 OR requested_lease_micros > 300000000 THEN
        RAISE EXCEPTION USING ERRCODE='22023', MESSAGE='invalid consolidation claim request';
    END IF;
    INSERT INTO brain.memory_consolidation_checkpoints(scope_id,timeline_id)
    SELECT scope.id,state.timeline_id FROM brain.scopes AS scope CROSS JOIN jobs.server_state AS state
    WHERE scope.id=requested_scope AND state.singleton
    ON CONFLICT (scope_id) DO NOTHING;
    RETURN QUERY UPDATE brain.memory_consolidation_checkpoints AS checkpoint
    SET lease_holder=requested_holder,lease_token=gen_random_uuid(),lease_generation=checkpoint.lease_generation+1,
        lease_until=statement_timestamp()+(requested_lease_micros * interval '1 microsecond'),updated_at=statement_timestamp()
    WHERE checkpoint.scope_id=requested_scope AND (checkpoint.lease_until IS NULL OR checkpoint.lease_until <= statement_timestamp())
    RETURNING checkpoint.scope_id,checkpoint.timeline_id,checkpoint.change_sequence,checkpoint.lease_holder,checkpoint.lease_token,checkpoint.lease_generation,checkpoint.lease_until;
END
$function$;

REVOKE ALL ON FUNCTION brain.claim_memory_consolidation_checkpoint(uuid,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.claim_memory_consolidation_checkpoint(uuid,uuid,bigint) TO punaro_app;

CREATE FUNCTION brain.advance_memory_consolidation_checkpoint(requested_scope uuid, requested_token uuid, requested_generation bigint, requested_timeline uuid, requested_sequence bigint)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    UPDATE brain.memory_consolidation_checkpoints AS checkpoint
    SET timeline_id=requested_timeline,change_sequence=requested_sequence,lease_holder=NULL,lease_token=NULL,lease_until=NULL,updated_at=statement_timestamp()
    FROM jobs.server_state AS state
    WHERE state.singleton AND checkpoint.scope_id=requested_scope AND checkpoint.lease_token=requested_token AND checkpoint.lease_generation=requested_generation
      AND checkpoint.lease_until > statement_timestamp() AND requested_timeline=state.timeline_id
      AND requested_sequence >= checkpoint.change_sequence AND requested_sequence <= state.change_sequence;
    RETURN FOUND;
END
$function$;
REVOKE ALL ON FUNCTION brain.advance_memory_consolidation_checkpoint(uuid,uuid,bigint,uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.advance_memory_consolidation_checkpoint(uuid,uuid,bigint,uuid,bigint) TO punaro_app;
