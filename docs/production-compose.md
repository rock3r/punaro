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
- an application-role PostgreSQL DSN for `PUNARO_POSTGRES_APP_DSN_FILE`.

Set `PUNARO_IMAGE` to a release digest and `PUNARO_PUBLIC_URL` to the canonical
HTTPS ingress URL for an authenticated local tunnel or reverse proxy. Start only the private database, then use the host-local
operator workflow to initialize/migrate it with the protected owner and
application DSNs. Ordinary Compose startup never migrates an existing schema.
After successful initialization, start the default services:

```sh
docker compose -f deploy/compose/production.yaml up -d postgres
# Run the documented host-local `punaro init` workflow here.
docker compose -f deploy/compose/production.yaml up -d
```

The application and PostgreSQL bind only to `127.0.0.1` for a separately
configured local tunnel or reverse proxy. The bundle defines no published ports;
do not publish PostgreSQL, the blob volume, or the daemon's unauthenticated
health listener. Optional worker, gateway, ingress, and backup roles are
intentionally deferred to later M23 slices.
