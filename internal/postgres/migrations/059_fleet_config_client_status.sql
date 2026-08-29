CREATE TABLE fleet.client_status (
    client_id uuid PRIMARY KEY REFERENCES auth.client_installations (id),
    generation bigint NOT NULL CHECK (generation >= 1),
    applied_digest text CHECK (applied_digest ~ '^[0-9a-f]{64}$'),
    state text NOT NULL CHECK (state IN (
        'current', 'pending', 'applying', 'failed', 'offline', 'drifted', 'unsupported', 'restart_required'
    )),
    activation text CHECK (activation IN (
        'immediate', 'next_turn', 'next_session', 'restart_required'
    )),
    trailer_state text CHECK (trailer_state IS NULL OR trailer_state IN ('missing', 'present', 'collision')),
    alias_state text CHECK (alias_state IS NULL OR alias_state IN ('disabled', 'linked', 'unsupported', 'collision')),
    project_match_state text CHECK (project_match_state IS NULL OR project_match_state IN ('none', 'matched', 'override', 'unmatched')),
    reported_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    report_generation bigint NOT NULL CHECK (report_generation >= 1)
);

CREATE TABLE fleet.client_status_idempotency (
    client_id uuid NOT NULL REFERENCES auth.client_installations (id),
    idempotency_key text NOT NULL CHECK (
        char_length(idempotency_key) BETWEEN 1 AND 128
        AND octet_length(idempotency_key) <= 512
        AND idempotency_key !~ '[[:cntrl:]]'
    ),
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    PRIMARY KEY (client_id, idempotency_key)
);

CREATE FUNCTION fleet.put_client_status(
    p_machine_id text,
    p_generation bigint,
    p_applied_digest text,
    p_state text,
    p_activation text,
    p_trailer_state text,
    p_alias_state text,
    p_project_match_state text,
    p_report_generation bigint,
    p_idempotency_key text,
    p_request_hash text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    target uuid;
    previous_generation bigint;
    previous_hash text;
BEGIN
    SELECT id INTO target
    FROM auth.client_installations
    WHERE machine_id = p_machine_id
      AND lifecycle_state = 'active'
    FOR SHARE;
    IF target IS NULL THEN
        RAISE EXCEPTION 'fleet-config status is not authorized';
    END IF;
    SELECT request_hash INTO previous_hash
    FROM fleet.client_status_idempotency
    WHERE client_id = target AND idempotency_key = p_idempotency_key;
    IF FOUND THEN
        IF previous_hash <> p_request_hash THEN
            RAISE EXCEPTION 'fleet-config status idempotency conflict';
        END IF;
        RETURN;
    END IF;
    SELECT report_generation INTO previous_generation
    FROM fleet.client_status
    WHERE client_id = target;
    IF FOUND AND previous_generation >= p_report_generation THEN
        RAISE EXCEPTION 'fleet-config status generation is stale';
    END IF;
    INSERT INTO fleet.client_status (
        client_id, generation, applied_digest, state, activation,
        trailer_state, alias_state, project_match_state, report_generation
    ) VALUES (
        target, p_generation, p_applied_digest, p_state, p_activation,
        p_trailer_state, p_alias_state, p_project_match_state, p_report_generation
    )
    ON CONFLICT (client_id) DO UPDATE SET
        generation = EXCLUDED.generation,
        applied_digest = EXCLUDED.applied_digest,
        state = EXCLUDED.state,
        activation = EXCLUDED.activation,
        trailer_state = EXCLUDED.trailer_state,
        alias_state = EXCLUDED.alias_state,
        project_match_state = EXCLUDED.project_match_state,
        reported_at = statement_timestamp(),
        report_generation = EXCLUDED.report_generation;
    INSERT INTO fleet.client_status_idempotency (client_id, idempotency_key, request_hash)
    VALUES (target, p_idempotency_key, p_request_hash);
END;
$function$;

REVOKE ALL ON fleet.client_status FROM PUBLIC;
REVOKE ALL ON fleet.client_status_idempotency FROM PUBLIC;
REVOKE ALL ON FUNCTION fleet.put_client_status(text, bigint, text, text, text, text, text, text, bigint, text, text) FROM PUBLIC;
GRANT SELECT ON fleet.client_status TO punaro_app;
GRANT EXECUTE ON FUNCTION fleet.put_client_status(text, bigint, text, text, text, text, text, text, bigint, text, text) TO punaro_app;
