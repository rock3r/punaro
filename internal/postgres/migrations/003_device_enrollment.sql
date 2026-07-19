ALTER TABLE auth.principals
ADD COLUMN auth_generation bigint NOT NULL DEFAULT 0 CHECK (auth_generation >= 0);

CREATE TABLE auth.installation_owner (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    principal_id uuid NOT NULL UNIQUE REFERENCES auth.principals(id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

CREATE TABLE auth.pending_enrollments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_principal_id uuid NOT NULL REFERENCES auth.principals(id),
    client_binding uuid NOT NULL,
    label text NOT NULL CHECK (
        char_length(label) BETWEEN 1 AND 128
        AND octet_length(label) <= 512
        AND label !~ '[[:cntrl:]]'
    ),
    code_digest bytea NOT NULL CHECK (octet_length(code_digest) = 32),
    preview_hash bytea NOT NULL CHECK (octet_length(preview_hash) = 32),
    expires_at timestamptz NOT NULL,
    credential_ttl_seconds integer CHECK (credential_ttl_seconds IS NULL OR credential_ttl_seconds BETWEEN 60 AND 31536000),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    redeemed_at timestamptz,
    redemption_key uuid,
    redeemed_principal_id uuid REFERENCES auth.principals(id),
    credential_lookup_id uuid,
    legacy_principal_id uuid REFERENCES auth.principals(id),
    CHECK (expires_at > created_at),
    CHECK (
        (redeemed_at IS NULL AND redemption_key IS NULL AND redeemed_principal_id IS NULL AND credential_lookup_id IS NULL)
        OR
        (redeemed_at IS NOT NULL AND redemption_key IS NOT NULL AND redeemed_principal_id IS NOT NULL AND credential_lookup_id IS NOT NULL)
    )
);

CREATE INDEX pending_enrollments_active_binding
ON auth.pending_enrollments (client_binding)
WHERE redeemed_at IS NULL;

CREATE TABLE auth.pending_enrollment_grants (
    enrollment_id uuid NOT NULL REFERENCES auth.pending_enrollments(id) ON DELETE CASCADE,
    ordinal smallint NOT NULL CHECK (ordinal BETWEEN 0 AND 1400),
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
    PRIMARY KEY (enrollment_id, ordinal),
    CHECK (
        (scope = 'installation' AND project_id IS NULL AND capability = 'project.create')
        OR
        (scope IN ('project', 'all_projects')
         AND ((scope = 'project' AND project_id IS NOT NULL) OR (scope = 'all_projects' AND project_id IS NULL))
         AND capability <> 'project.create')
    )
);

CREATE TABLE auth.device_credentials (
    lookup_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL UNIQUE REFERENCES auth.principals(id),
    label text NOT NULL CHECK (
        char_length(label) BETWEEN 1 AND 128
        AND octet_length(label) <= 512
        AND label !~ '[[:cntrl:]]'
    ),
    secret_digest bytea NOT NULL CHECK (octet_length(secret_digest) = 32),
    generation bigint NOT NULL DEFAULT 1 CHECK (generation >= 1),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    last_used_at timestamptz,
    expires_at timestamptz,
    rotated_at timestamptz,
    rotation_code_digest bytea CHECK (rotation_code_digest IS NULL OR octet_length(rotation_code_digest) = 32),
    rotation_expected_generation bigint,
    rotation_expires_at timestamptz,
    rotation_completed_at timestamptz,
    revoked_at timestamptz,
    CHECK (expires_at IS NULL OR expires_at > created_at),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (
        (rotation_code_digest IS NULL AND rotation_expected_generation IS NULL AND rotation_expires_at IS NULL AND rotation_completed_at IS NULL)
        OR
        (rotation_code_digest IS NOT NULL AND rotation_expected_generation >= 1 AND rotation_expires_at IS NOT NULL)
    )
);

CREATE INDEX device_credentials_principal_active
ON auth.device_credentials (principal_id)
WHERE revoked_at IS NULL;

CREATE UNIQUE INDEX device_credentials_secret_digest
ON auth.device_credentials (secret_digest);

ALTER TABLE auth.pending_enrollments
ADD CONSTRAINT pending_enrollments_credential_lookup_id_fkey
FOREIGN KEY (credential_lookup_id) REFERENCES auth.device_credentials(lookup_id);

CREATE TABLE auth.legacy_auth_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled boolean NOT NULL DEFAULT true,
    changed_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

INSERT INTO auth.legacy_auth_state (singleton) VALUES (true);

CREATE TABLE auth.legacy_machines (
    principal_id uuid PRIMARY KEY REFERENCES auth.principals(id),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    public_key_digest bytea NOT NULL UNIQUE CHECK (octet_length(public_key_digest) = 32),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'migrated', 'retired')),
    migrated_credential_lookup_id uuid REFERENCES auth.device_credentials(lookup_id),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    changed_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    CHECK ((state = 'migrated') = (migrated_credential_lookup_id IS NOT NULL))
);

CREATE FUNCTION auth.complete_legacy_exchange(p_legacy_principal_id uuid, p_credential_lookup_id uuid)
RETURNS SETOF boolean
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $legacy_exchange$
UPDATE auth.legacy_machines AS machine
SET state = 'migrated',
    migrated_credential_lookup_id = credential.lookup_id,
    changed_at = statement_timestamp()
FROM auth.device_credentials AS credential
WHERE machine.principal_id = p_legacy_principal_id
  AND machine.state = 'pending'
  AND credential.lookup_id = p_credential_lookup_id
  AND EXISTS (
      SELECT 1
      FROM auth.pending_enrollments AS enrollment
      WHERE enrollment.legacy_principal_id = machine.principal_id
        AND enrollment.credential_lookup_id = credential.lookup_id
        AND enrollment.redeemed_principal_id = credential.principal_id
        AND enrollment.redeemed_at IS NOT NULL
  )
RETURNING true
$legacy_exchange$;

REVOKE ALL ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth.complete_legacy_exchange(uuid, uuid) TO punaro_app;

ALTER TABLE audit.events DROP CONSTRAINT events_action_check;
ALTER TABLE audit.events ADD CONSTRAINT events_action_check CHECK (action IN (
    'principal.create', 'project.create', 'grant.create', 'grant.delete',
    'job.enqueue', 'job.complete', 'job.retry', 'job.fail',
    'owner.bootstrap', 'enrollment.create', 'enrollment.redeem',
    'credential.rotate', 'credential.revoke',
    'legacy.register', 'legacy.exchange', 'legacy.retire', 'legacy.disable'
));

ALTER TABLE audit.events DROP CONSTRAINT events_target_kind_check;
ALTER TABLE audit.events ADD CONSTRAINT events_target_kind_check CHECK (target_kind IN (
    'principal', 'project', 'grant', 'job', 'enrollment', 'credential', 'legacy_machine'
));

GRANT SELECT ON auth.installation_owner TO punaro_app;
GRANT SELECT ON auth.pending_enrollments TO punaro_app;
GRANT UPDATE (redeemed_at, redemption_key, redeemed_principal_id, credential_lookup_id) ON auth.pending_enrollments TO punaro_app;
GRANT SELECT ON auth.pending_enrollment_grants TO punaro_app;
GRANT SELECT ON auth.device_credentials TO punaro_app;
GRANT INSERT (lookup_id, principal_id, label, secret_digest, expires_at) ON auth.device_credentials TO punaro_app;
GRANT UPDATE (last_used_at) ON auth.device_credentials TO punaro_app;
GRANT SELECT ON auth.legacy_auth_state TO punaro_app;
GRANT SELECT ON auth.legacy_machines TO punaro_app;

REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON auth.installation_owner FROM punaro_app;
REVOKE INSERT, DELETE, TRUNCATE, REFERENCES, TRIGGER ON auth.pending_enrollments FROM punaro_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON auth.pending_enrollment_grants FROM punaro_app;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON auth.device_credentials FROM punaro_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON auth.legacy_auth_state FROM punaro_app;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON auth.legacy_machines FROM punaro_app;
