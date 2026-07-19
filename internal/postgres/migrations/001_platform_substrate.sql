CREATE SCHEMA auth;
CREATE SCHEMA relay;
CREATE SCHEMA attachment;
CREATE SCHEMA brain;
CREATE SCHEMA audit;

CREATE TABLE jobs.server_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    installation_id uuid NOT NULL,
    timeline_id uuid NOT NULL,
    change_sequence bigint NOT NULL DEFAULT 0 CHECK (change_sequence >= 0),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    timeline_started_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

INSERT INTO jobs.server_state (singleton, installation_id, timeline_id)
VALUES (true, gen_random_uuid(), gen_random_uuid());

CREATE FUNCTION jobs.advance_change_sequence()
RETURNS TABLE (installation_id uuid, timeline_id uuid, change_sequence bigint)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    UPDATE jobs.server_state AS state
    SET change_sequence = state.change_sequence + 1
    WHERE state.singleton
    RETURNING state.installation_id, state.timeline_id, state.change_sequence
$function$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON FUNCTION jobs.advance_change_sequence() FROM PUBLIC;
GRANT USAGE ON SCHEMA jobs TO punaro_app;
GRANT SELECT ON jobs.server_state, jobs.schema_migrations TO punaro_app;
GRANT EXECUTE ON FUNCTION jobs.advance_change_sequence() TO punaro_app;
REVOKE CREATE ON SCHEMA jobs, auth, relay, attachment, brain, audit FROM punaro_app;
