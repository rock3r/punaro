CREATE TABLE brain.memory_consolidation_passes (
    scope_id uuid NOT NULL REFERENCES brain.scopes(id) ON DELETE CASCADE,
    timeline_id uuid NOT NULL,
    start_sequence bigint NOT NULL CHECK (start_sequence >= 0),
    next_sequence bigint NOT NULL CHECK (next_sequence >= start_sequence),
    principal_id uuid NOT NULL,
    project_id uuid NOT NULL,
    lease_token uuid NOT NULL,
    lease_generation bigint NOT NULL CHECK (lease_generation >= 1),
    source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256)=32),
    sources jsonb NOT NULL,
    proposals jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (scope_id,timeline_id,start_sequence,principal_id,project_id)
);

CREATE FUNCTION brain.guard_memory_consolidation_pass()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    PERFORM 1
    FROM brain.memory_consolidation_checkpoints AS checkpoint
    WHERE checkpoint.scope_id=NEW.scope_id
      AND checkpoint.timeline_id=NEW.timeline_id
      AND checkpoint.change_sequence=NEW.start_sequence
      AND checkpoint.lease_token=NEW.lease_token
      AND checkpoint.lease_generation=NEW.lease_generation
      AND checkpoint.lease_until>statement_timestamp();
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='consolidation pass is not fenced by a live checkpoint lease';
    END IF;
    RETURN NEW;
END
$function$;

CREATE TRIGGER memory_consolidation_pass_insert_guard
BEFORE INSERT ON brain.memory_consolidation_passes
FOR EACH ROW EXECUTE FUNCTION brain.guard_memory_consolidation_pass();

CREATE TRIGGER application_mutation_fence
BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON brain.memory_consolidation_passes
FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

REVOKE ALL ON brain.memory_consolidation_passes FROM PUBLIC, punaro_app;
REVOKE ALL ON FUNCTION brain.guard_memory_consolidation_pass() FROM PUBLIC;
GRANT SELECT ON brain.memory_consolidation_passes TO punaro_app;
GRANT INSERT (scope_id,timeline_id,start_sequence,next_sequence,principal_id,project_id,lease_token,lease_generation,source_sha256,sources,proposals)
    ON brain.memory_consolidation_passes TO punaro_app;

CREATE FUNCTION brain.clear_memory_consolidation_passes_on_checkpoint_move()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    DELETE FROM brain.memory_consolidation_passes WHERE scope_id=NEW.scope_id;
    RETURN NULL;
END
$function$;

CREATE TRIGGER memory_consolidation_pass_checkpoint_cleanup
AFTER UPDATE OF timeline_id,change_sequence ON brain.memory_consolidation_checkpoints
FOR EACH ROW WHEN ((OLD.timeline_id,OLD.change_sequence) IS DISTINCT FROM (NEW.timeline_id,NEW.change_sequence))
EXECUTE FUNCTION brain.clear_memory_consolidation_passes_on_checkpoint_move();

REVOKE ALL ON FUNCTION brain.clear_memory_consolidation_passes_on_checkpoint_move() FROM PUBLIC;

CREATE FUNCTION brain.complete_memory_consolidation_pass(
    requested_scope uuid,
    requested_token uuid,
    requested_generation bigint,
    requested_timeline uuid,
    requested_start_sequence bigint,
    requested_next_sequence bigint,
    requested_principal uuid,
    requested_project uuid
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    UPDATE brain.memory_consolidation_checkpoints AS checkpoint
    SET timeline_id=requested_timeline,change_sequence=requested_next_sequence,lease_holder=NULL,lease_token=NULL,lease_until=NULL,updated_at=statement_timestamp()
    FROM jobs.server_state AS state
    WHERE state.singleton AND checkpoint.scope_id=requested_scope AND checkpoint.lease_token=requested_token
      AND checkpoint.lease_generation=requested_generation AND checkpoint.lease_until>statement_timestamp()
      AND checkpoint.timeline_id=requested_timeline AND checkpoint.change_sequence=requested_start_sequence
      AND requested_next_sequence>=checkpoint.change_sequence AND requested_next_sequence<=state.change_sequence
      AND EXISTS (
          SELECT 1 FROM brain.memory_consolidation_passes AS pass
          WHERE pass.scope_id=requested_scope AND pass.timeline_id=requested_timeline
            AND pass.start_sequence=requested_start_sequence AND pass.next_sequence=requested_next_sequence
            AND pass.principal_id=requested_principal AND pass.project_id=requested_project
      );
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    DELETE FROM brain.memory_consolidation_passes AS pass
    WHERE pass.scope_id=requested_scope AND pass.timeline_id=requested_timeline
      AND pass.start_sequence=requested_start_sequence AND pass.next_sequence=requested_next_sequence
      AND pass.principal_id=requested_principal AND pass.project_id=requested_project;
    RETURN true;
END
$function$;

REVOKE ALL ON FUNCTION brain.complete_memory_consolidation_pass(uuid,uuid,bigint,uuid,bigint,bigint,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.complete_memory_consolidation_pass(uuid,uuid,bigint,uuid,bigint,bigint,uuid,uuid) TO punaro_app;

CREATE FUNCTION brain.abandon_memory_consolidation_pass(
    requested_scope uuid,
    requested_token uuid,
    requested_generation bigint,
    requested_timeline uuid,
    requested_start_sequence bigint,
    requested_next_sequence bigint,
    requested_principal uuid,
    requested_project uuid
)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM jobs.assert_application_mutation();
    DELETE FROM brain.memory_consolidation_passes AS pass
    USING brain.memory_consolidation_checkpoints AS checkpoint
    WHERE checkpoint.scope_id=requested_scope AND checkpoint.lease_token=requested_token
      AND checkpoint.lease_generation=requested_generation AND checkpoint.lease_until>statement_timestamp()
      AND checkpoint.timeline_id=requested_timeline AND checkpoint.change_sequence=requested_start_sequence
      AND pass.scope_id=requested_scope AND pass.timeline_id=requested_timeline
      AND pass.start_sequence=requested_start_sequence AND pass.next_sequence=requested_next_sequence
      AND pass.principal_id=requested_principal AND pass.project_id=requested_project;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    UPDATE brain.memory_consolidation_checkpoints AS checkpoint
    SET lease_holder=NULL,lease_token=NULL,lease_until=NULL,updated_at=statement_timestamp()
    WHERE checkpoint.scope_id=requested_scope AND checkpoint.lease_token=requested_token
      AND checkpoint.lease_generation=requested_generation AND checkpoint.lease_until>statement_timestamp()
      AND checkpoint.timeline_id=requested_timeline AND checkpoint.change_sequence=requested_start_sequence;
    RETURN FOUND;
END
$function$;

REVOKE ALL ON FUNCTION brain.abandon_memory_consolidation_pass(uuid,uuid,bigint,uuid,bigint,bigint,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION brain.abandon_memory_consolidation_pass(uuid,uuid,bigint,uuid,bigint,bigint,uuid,uuid) TO punaro_app;
