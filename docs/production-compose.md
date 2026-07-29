# Reference production Compose bundle

`deploy/compose/production.yaml` is the reference single-node bundle. It is
not a development shortcut and deliberately refuses to choose an image,
database password, application DSN, or public URL on the operator's behalf.

The default services are only `postgres` and `punarod`. PostgreSQL is pinned to
the reviewed pgvector 18 digest and is forced to same-host loopback. `punarod`
uses that same reviewed loopback boundary, has a read-only root filesystem, no Linux capabilities,
`no-new-privileges`, a bounded temporary filesystem, and loopback-only host
ports. Database credentials are mounted as read-only Compose secrets; neither
credential is an environment variable or image layer.

## First installation

Prepare two owner-only files outside the repository:

- a PostgreSQL owner password for `PUNARO_POSTGRES_OWNER_PASSWORD_FILE`; and
- a PostgreSQL application-role password for `PUNARO_POSTGRES_APP_PASSWORD_FILE`; and
- an application-role PostgreSQL DSN for `PUNARO_POSTGRES_APP_DSN_FILE`.

Compose file secrets preserve their host ownership. The application DSN file
must therefore be a regular, non-symlink `0400` file owned by the non-root
runtime UID supplied to Compose. Set the runtime identity from the deployment
account, then use it to own the DSN file:

```sh
export PUNARO_RUNTIME_UID="$(id -u)"
export PUNARO_RUNTIME_GID="$(id -g)"
chown "$PUNARO_RUNTIME_UID:$PUNARO_RUNTIME_GID" APP_DSN_FILE
chmod 0400 APP_DSN_FILE
```

Do not make it group- or world-readable: the daemon rejects broad DSN-file
permissions. The PostgreSQL owner-password file remains an operator-owned
secret consumed only by the PostgreSQL entrypoint. The app-password secret is
used only during fresh PostgreSQL-volume initialization to create the
least-privilege `punaro_app` role; its value must match the password embedded
in the application DSN. The root-started PostgreSQL entrypoint copies that
single secret into a private in-memory directory, changes it to the PostgreSQL
user, and then invokes the upstream entrypoint; this allows the initialization
script to read it after privilege drop without making the host file broader or
persisting a second copy on disk.

Set `PUNARO_IMAGE` to a release digest and `PUNARO_PUBLIC_URL` to the canonical
HTTPS ingress URL for an authenticated local tunnel or reverse proxy. Always
invoke the bundle through `scripts/production-compose`: it refuses a non-digest
image reference and a root runtime identity. Start only the private database, then use the host-local
`punaro bootstrap` command to initialize/migrate the protected owner and
application DSNs. Bootstrap is intentionally migration-only: it does not
publish the host-local operator stack, so it cannot compete for ports or create
a second lifecycle authority for this reference bundle. Ordinary Compose
startup never migrates an existing schema.
After successful initialization, start the default services:

```sh
scripts/production-compose up -d postgres-bootstrap
punaro bootstrap --owner-dsn-file OWNER_DSN_FILE --app-dsn-file APP_DSN_FILE --owner-name 'Production operator'
scripts/production-compose up -d
```

The application and PostgreSQL bind only to `127.0.0.1` for a separately
configured local tunnel or reverse proxy. The bundle defines no published ports;
do not publish PostgreSQL, the blob volume, or the daemon's unauthenticated
health listener. Optional worker, gateway, ingress, and backup roles are
intentionally deferred to later M23 slices.
