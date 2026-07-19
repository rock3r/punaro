CREATE TABLE auth.principals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('owner', 'device', 'service', 'legacy_machine')),
    display_name text NOT NULL CHECK (
        char_length(display_name) BETWEEN 1 AND 128
        AND octet_length(display_name) <= 512
        AND display_name !~ '[[:cntrl:]]'
    ),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    disabled_at timestamptz
);

CREATE TABLE relay.projects (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name text NOT NULL CHECK (
        char_length(display_name) BETWEEN 1 AND 128
        AND octet_length(display_name) <= 512
        AND display_name !~ '[[:cntrl:]]'
    ),
    created_by uuid NOT NULL REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE auth.capability_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id uuid NOT NULL REFERENCES auth.principals(id),
    scope text NOT NULL CHECK (scope IN ('installation', 'project', 'all_projects')),
    project_id uuid REFERENCES relay.projects(id),
    capability text NOT NULL CHECK (capability IN (
        'project.discover',
        'project.create',
        'project.read',
        'project.write',
        'project.identity.attach-unclaimed',
        'project.administer',
        'conversation.send',
        'conversation.receive',
        'conversation.administer',
        'memory.search',
        'memory.read',
        'memory.propose',
        'memory.write',
        'memory.administer',
        'memory.purge',
        'attachment.upload',
        'attachment.download',
        'attachment.delete'
    )),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    revoked_at timestamptz,
    CHECK (
        (scope = 'installation' AND project_id IS NULL AND capability = 'project.create')
        OR
        (scope IN ('project', 'all_projects')
         AND ((scope = 'project' AND project_id IS NOT NULL) OR (scope = 'all_projects' AND project_id IS NULL))
         AND capability <> 'project.create')
    )
);

CREATE UNIQUE INDEX capability_grants_active_unique
ON auth.capability_grants (
    principal_id,
    scope,
    COALESCE(project_id, '00000000-0000-0000-0000-000000000000'::uuid),
    capability
)
WHERE revoked_at IS NULL;

CREATE INDEX capability_grants_authorization_lookup
ON auth.capability_grants (principal_id, capability, project_id, scope)
WHERE revoked_at IS NULL;

CREATE TABLE relay.idempotency_records (
    key uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES auth.principals(id),
    operation text NOT NULL CHECK (operation ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    status text NOT NULL CHECK (status IN ('pending', 'succeeded', 'rejected')),
    resource_id uuid,
    result jsonb,
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    CHECK (
        (status = 'pending' AND result IS NULL AND resource_id IS NULL AND completed_at IS NULL)
        OR
        (status IN ('succeeded', 'rejected') AND result IS NOT NULL AND completed_at IS NOT NULL
         AND octet_length(result::text) <= 65536)
    )
);

CREATE TABLE audit.events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    principal_id uuid,
    project_id uuid,
    action text NOT NULL CHECK (action IN (
        'principal.create', 'project.create', 'grant.create', 'grant.delete',
        'job.enqueue', 'job.complete', 'job.fail'
    )),
    outcome text NOT NULL CHECK (outcome IN ('succeeded', 'rejected')),
    target_kind text NOT NULL CHECK (target_kind IN ('principal', 'project', 'grant', 'job')),
    target_id uuid
);

CREATE TABLE jobs.queue_capacity (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    active_count integer NOT NULL DEFAULT 0 CHECK (active_count >= 0),
    max_depth integer NOT NULL DEFAULT 10000 CHECK (max_depth BETWEEN 1 AND 100000)
);

INSERT INTO jobs.queue_capacity (singleton) VALUES (true);

CREATE TABLE jobs.outbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid REFERENCES relay.projects(id),
    kind text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    payload jsonb NOT NULL CHECK (octet_length(payload::text) <= 262144),
    state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'succeeded', 'failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 25 AND attempts <= max_attempts),
    available_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    lease_holder uuid,
    lease_token uuid,
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_until timestamptz,
    last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[a-z][a-z0-9_.:-]{0,127}$'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    completed_at timestamptz,
    CHECK (
        (state = 'queued' AND lease_holder IS NULL AND lease_token IS NULL AND lease_until IS NULL AND completed_at IS NULL)
        OR
        (state = 'running' AND lease_holder IS NOT NULL AND lease_token IS NOT NULL AND lease_until IS NOT NULL AND completed_at IS NULL)
        OR
        (state IN ('succeeded', 'failed') AND lease_holder IS NULL AND lease_token IS NULL AND lease_until IS NULL AND completed_at IS NOT NULL)
    )
);

CREATE INDEX outbox_claim_order
ON jobs.outbox (kind, available_at, created_at, id)
WHERE state = 'queued';

CREATE INDEX outbox_expired_lease
ON jobs.outbox (kind, lease_until, created_at, id)
WHERE state = 'running';

CREATE FUNCTION jobs.guard_outbox_capacity_and_state()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    capacity_changed integer;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'queued' OR NEW.attempts <> 0 OR NEW.lease_generation <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid initial job state';
        END IF;
        UPDATE jobs.queue_capacity
        SET active_count = active_count + 1
        WHERE singleton AND active_count < max_depth;
        GET DIAGNOSTICS capacity_changed = ROW_COUNT;
        IF capacity_changed <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '54000', MESSAGE = 'job queue capacity exceeded';
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.state IN ('succeeded', 'failed') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'terminal job is immutable';
    END IF;
    IF (OLD.state = 'queued' AND NEW.state NOT IN ('queued', 'running', 'failed'))
       OR (OLD.state = 'running' AND NEW.state NOT IN ('running', 'queued', 'succeeded', 'failed')) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid job state transition';
    END IF;
    IF OLD.state IN ('queued', 'running') AND NEW.state IN ('succeeded', 'failed') THEN
        UPDATE jobs.queue_capacity
        SET active_count = active_count - 1
        WHERE singleton AND active_count > 0;
        GET DIAGNOSTICS capacity_changed = ROW_COUNT;
        IF capacity_changed <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid job queue capacity';
        END IF;
    END IF;
    NEW.updated_at = statement_timestamp();
    RETURN NEW;
END
$function$;

CREATE TRIGGER outbox_capacity_and_state
BEFORE INSERT OR UPDATE ON jobs.outbox
FOR EACH ROW EXECUTE FUNCTION jobs.guard_outbox_capacity_and_state();

CREATE FUNCTION audit.prune_events(p_before timestamptz, p_limit integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    deleted_count bigint;
BEGIN
    IF p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid audit prune limit';
    END IF;
    WITH candidates AS (
        SELECT event_id FROM audit.events
        WHERE occurred_at < p_before
        ORDER BY event_id
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM audit.events AS event
    USING candidates
    WHERE event.event_id = candidates.event_id;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END
$function$;

CREATE FUNCTION jobs.prune_terminal(p_before timestamptz, p_limit integer)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    deleted_count bigint;
BEGIN
    IF p_limit < 1 OR p_limit > 1000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid terminal prune limit';
    END IF;
    WITH candidates AS (
        SELECT id FROM jobs.outbox
        WHERE state IN ('succeeded', 'failed') AND completed_at < p_before
        ORDER BY completed_at, id
        LIMIT p_limit
        FOR UPDATE SKIP LOCKED
    )
    DELETE FROM jobs.outbox AS job
    USING candidates
    WHERE job.id = candidates.id;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END
$function$;

REVOKE ALL ON FUNCTION jobs.guard_outbox_capacity_and_state() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit.prune_events(timestamptz, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION jobs.prune_terminal(timestamptz, integer) FROM PUBLIC;

GRANT USAGE ON SCHEMA auth, relay, jobs, audit TO punaro_app;
GRANT SELECT, INSERT, UPDATE ON auth.principals TO punaro_app;
GRANT SELECT, INSERT, UPDATE ON relay.projects TO punaro_app;
GRANT SELECT, INSERT, UPDATE ON auth.capability_grants TO punaro_app;
GRANT SELECT, INSERT, UPDATE ON relay.idempotency_records TO punaro_app;
GRANT SELECT, INSERT ON audit.events TO punaro_app;
GRANT USAGE, SELECT ON SEQUENCE audit.events_event_id_seq TO punaro_app;
GRANT SELECT ON jobs.queue_capacity TO punaro_app;
GRANT SELECT, INSERT, UPDATE ON jobs.outbox TO punaro_app;
GRANT EXECUTE ON FUNCTION audit.prune_events(timestamptz, integer) TO punaro_app;
GRANT EXECUTE ON FUNCTION jobs.prune_terminal(timestamptz, integer) TO punaro_app;

REVOKE CREATE ON SCHEMA auth, relay, jobs, audit FROM punaro_app;
