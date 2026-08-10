ALTER TABLE auth.pending_enrollments
ADD COLUMN machine_id text;

UPDATE auth.pending_enrollments
SET invalidated_at = COALESCE(invalidated_at, statement_timestamp())
WHERE redeemed_at IS NULL;

ALTER TABLE auth.pending_enrollments
ADD CONSTRAINT pending_enrollments_machine_id_check CHECK (
    machine_id IS NULL OR machine_id ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'
);

CREATE UNIQUE INDEX pending_enrollments_active_machine
ON auth.pending_enrollments (machine_id)
WHERE redeemed_at IS NULL AND invalidated_at IS NULL;

CREATE TABLE auth.client_installations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    machine_id text NOT NULL UNIQUE CHECK (
        machine_id ~ '^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$'
    ),
    label text NOT NULL CHECK (
        char_length(label) BETWEEN 1 AND 128
        AND octet_length(label) <= 512
        AND label !~ '[[:cntrl:]]'
    ),
    principal_id uuid NOT NULL UNIQUE REFERENCES auth.principals(id),
    credential_lookup_id uuid NOT NULL UNIQUE REFERENCES auth.device_credentials(lookup_id),
    generation bigint NOT NULL DEFAULT 1 CHECK (generation >= 1),
    lifecycle_state text NOT NULL DEFAULT 'active' CHECK (lifecycle_state IN ('active', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp(),
    revoked_at timestamptz,
    revocation_reason text CHECK (revocation_reason IN ('lost', 'retired', 'compromised', 'replaced', 'self')),
    self_revoke_idempotency uuid UNIQUE,
    CHECK (
        (lifecycle_state = 'active' AND revoked_at IS NULL AND revocation_reason IS NULL AND self_revoke_idempotency IS NULL)
        OR
        (lifecycle_state = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    )
);

CREATE TABLE relay.client_endpoint_authority (
    client_id uuid PRIMARY KEY REFERENCES auth.client_installations(id),
    endpoint_prefix text NOT NULL UNIQUE CHECK (
        endpoint_prefix ~ '^agent/[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?/$'
    ),
    generation bigint NOT NULL DEFAULT 1 CHECK (generation >= 1),
    created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

INSERT INTO auth.client_installations
(machine_id, label, principal_id, credential_lookup_id, generation, lifecycle_state, created_at, revoked_at, revocation_reason)
SELECT 'device-' || credential.lookup_id::text,
       credential.label,
       credential.principal_id,
       credential.lookup_id,
       credential.generation,
       CASE WHEN credential.revoked_at IS NULL THEN 'active' ELSE 'revoked' END,
       credential.created_at,
       credential.revoked_at,
       CASE WHEN credential.revoked_at IS NULL THEN NULL ELSE 'replaced' END
FROM auth.device_credentials AS credential;

INSERT INTO relay.client_endpoint_authority (client_id, endpoint_prefix, generation, created_at)
SELECT client.id, 'agent/' || client.machine_id || '/', client.generation, client.created_at
FROM auth.client_installations AS client;

UPDATE auth.pending_enrollments AS enrollment
SET machine_id = client.machine_id
FROM auth.client_installations AS client
WHERE enrollment.credential_lookup_id = client.credential_lookup_id;

UPDATE auth.device_credentials
SET expires_at = NULL
WHERE revoked_at IS NULL;

GRANT SELECT ON auth.client_installations TO punaro_app;
GRANT INSERT (machine_id, label, principal_id, credential_lookup_id) ON auth.client_installations TO punaro_app;
GRANT UPDATE (generation, lifecycle_state, revoked_at, revocation_reason, self_revoke_idempotency) ON auth.client_installations TO punaro_app;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON auth.client_installations FROM punaro_app;

GRANT SELECT ON relay.client_endpoint_authority TO punaro_app;
GRANT INSERT (client_id, endpoint_prefix) ON relay.client_endpoint_authority TO punaro_app;
GRANT UPDATE (generation) ON relay.client_endpoint_authority TO punaro_app;
REVOKE DELETE, TRUNCATE, REFERENCES, TRIGGER ON relay.client_endpoint_authority FROM punaro_app;

GRANT UPDATE (generation, revoked_at) ON auth.device_credentials TO punaro_app;
REVOKE INSERT (expires_at) ON auth.device_credentials FROM punaro_app;
