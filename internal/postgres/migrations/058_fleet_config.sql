CREATE SCHEMA fleet;

CREATE TABLE fleet.releases (
    digest text PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
    source_commit text NOT NULL CHECK (
        source_commit ~ '^[0-9a-f]{40}$'
        OR source_commit ~ '^[0-9a-f]{64}$'
    ),
    archive bytea NOT NULL CHECK (octet_length(archive) BETWEEN 1 AND 8388608),
    skill_count integer NOT NULL CHECK (skill_count BETWEEN 0 AND 64),
    file_count integer NOT NULL CHECK (file_count BETWEEN 1 AND 512),
    total_bytes bigint NOT NULL CHECK (total_bytes BETWEEN 1 AND 4194304),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE fleet.desired (
    id boolean PRIMARY KEY DEFAULT true CHECK (id),
    release_digest text NOT NULL REFERENCES fleet.releases (digest),
    generation bigint NOT NULL CHECK (generation >= 1),
    published_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    preview_hash text NOT NULL CHECK (preview_hash ~ '^[0-9a-f]{64}$')
);

CREATE TRIGGER application_mutation_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON fleet.releases
    FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();
CREATE TRIGGER application_mutation_fence
    BEFORE INSERT OR UPDATE OR DELETE OR TRUNCATE ON fleet.desired
    FOR EACH STATEMENT EXECUTE FUNCTION jobs.guard_application_mutation();

REVOKE ALL ON SCHEMA fleet FROM PUBLIC;
GRANT USAGE ON SCHEMA fleet TO punaro_app;
GRANT SELECT ON fleet.releases, fleet.desired TO punaro_app;
REVOKE CREATE ON SCHEMA fleet FROM punaro_app;
