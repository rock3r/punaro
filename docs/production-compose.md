# Reference production Compose bundle

`deploy/compose/production.yaml` is the reference single-node bundle. It is
not a development shortcut and deliberately refuses to choose an image,
database password, application DSN, or public URL on the operator's behalf.

The default services are `postgres` and its one-shot role bootstrap. PostgreSQL
is pinned to the reviewed pgvector 18 digest and is forced to same-host
loopback. The bundled `punarod` definition is an explicit
`reference-daemon` profile, not a default service: the supported installation
uses the host-local lifecycle created by `punaro init`, `punaro up`, and
`punaro update`. This prevents two daemons from claiming the same loopback
ports or different blob state. Database credentials are mounted as read-only
Compose secrets; neither credential is an environment variable or image layer.

## First installation

Prepare owner-only files outside the repository:

- a PostgreSQL owner password for `PUNARO_POSTGRES_OWNER_PASSWORD_FILE`; and
- a PostgreSQL application-role password for `PUNARO_POSTGRES_APP_PASSWORD_FILE`; and
- an owner PostgreSQL DSN file for `punaro_owner`; and
- an application-role PostgreSQL DSN for `PUNARO_POSTGRES_APP_DSN_FILE`.

Compose file secrets preserve their host ownership. The application DSN file
must therefore be a regular, non-symlink `0400` file owned by the non-root
runtime UID supplied to Compose. Set the runtime identity from the deployment
account, then use it to own the DSN file:

```sh
export PUNARO_RUNTIME_UID="$(id -u)"
export PUNARO_RUNTIME_GID="$(id -g)"
export PUNARO_COMPOSE_PROJECT_NAME='punaro-prod-a1b2c3'
chown "$PUNARO_RUNTIME_UID:$PUNARO_RUNTIME_GID" APP_DSN_FILE
chmod 0400 APP_DSN_FILE
```

Do not make it group- or world-readable: the daemon rejects broad DSN-file
permissions. The PostgreSQL owner-password file remains an operator-owned
secret consumed only by PostgreSQL and its bootstrap service. The app-password secret is
used by the idempotent role bootstrap service to create the
least-privilege `punaro_app` role; its value must match the password embedded
in the application DSN. Use a non-empty URL-safe application password
(`A-Z`, `a-z`, `0-9`, `.`, `_`, `~`, `-`) and the exact DSN form
`postgres://punaro_app:APP_PASSWORD@127.0.0.1:5432/punaro?sslmode=disable`.

The owner DSN is a regular non-symlink `0400` file owned by the deployment
account, for example `postgres://punaro_owner:OWNER_PASSWORD@127.0.0.1:5432/punaro?sslmode=disable`.

Export the absolute paths to the credential files before invoking the wrapper:

```sh
export PUNARO_POSTGRES_OWNER_PASSWORD_FILE=OWNER_PASSWORD_FILE
export PUNARO_POSTGRES_OWNER_DSN_FILE=OWNER_DSN_FILE
export PUNARO_POSTGRES_APP_PASSWORD_FILE=APP_PASSWORD_FILE
export PUNARO_POSTGRES_APP_DSN_FILE=APP_DSN_FILE
```

Set `PUNARO_IMAGE` to a release digest and `PUNARO_PUBLIC_URL` to the canonical
HTTPS ingress URL for an authenticated local tunnel or reverse proxy. Always
invoke the database bundle through `scripts/production-compose`: it refuses a
non-digest image reference and a root runtime identity. Start the private
database and its idempotent role bootstrap, then initialize the host-local
Punaro lifecycle. The initial `punaro init` owns the daemon Compose artifact
and writes the installation record required by `punaro update`; do not enable
the `reference-daemon` profile or start the reference bundle's `punarod`
service separately.

Set `PUNARO_COMPOSE_PROJECT_NAME` once to a unique, lowercase installation ID
(for example `punaro-prod-a1b2c3`). Every wrapper invocation passes it
explicitly to Docker Compose, preventing another checkout or an ambient
`COMPOSE_PROJECT_NAME` from sharing or deleting this installation's volumes.

Create private, non-overlapping daemon data, backup, attachment-blob, and
installation directories outside the repository. Collect the public relay
machine records into one owner-only JSON file. This file is declarative input,
not a secret: it contains public keys and exclusive endpoint prefixes only.
The initial `punaro init` is the one supported server configuration boundary;
do not hand-edit the generated environment or Compose files.

To enable every currently supported surface on a fresh installation, initialize
and start the daemon with the explicit opt-ins below. Omit both memory flags to
keep native memory dark, or omit the trusted-attachment flag and blob directory
to keep trusted attachments dark. The attachment blob directory must already exist,
be private, and be beneath `DATA_DIR`; credentials and operator state must
remain outside `DATA_DIR`.

```sh
scripts/production-compose up -d postgres-bootstrap
scripts/production-compose wait postgres-bootstrap
punaro init \
  --directory INSTALLATION_DIR \
  --data-dir DATA_DIR \
  --backup-dir BACKUP_DIR \
  --image "$PUNARO_IMAGE" \
  --owner-dsn-file OWNER_DSN_FILE \
  --app-dsn-file APP_DSN_FILE \
  --owner-name 'Production operator' \
  --mode proxy \
  --public-url "$PUNARO_PUBLIC_URL" \
  --memory-api \
  --memory-mutations \
  --relay-machines-file RELAY_MACHINES_FILE \
  --trusted-attachments \
  --trusted-attachment-blob-dir DATA_DIR/attachments
punaro up --directory INSTALLATION_DIR
```

`--relay-machines-file` is read only after protected-file checks and is
canonicalized before any database mutation. `--trusted-attachments` requires
its blob-directory argument; a stray blob-directory argument, unsafe path, or
contradictory opt-in fails before listeners start. The generated runtime uses
PostgreSQL relay authority and device authentication, while its daemon,
database, health endpoint, and Compose credentials remain host-local.

## Add or revoke a mailbox client

First prove that the tunnel's device route and health route terminate at this
installation. Health may be routed to a dedicated loopback listener while
signed device requests go elsewhere; `/readyz` alone is therefore not daemon
identity. Record the Compose project, exact image, process/listener ownership,
and one harmless signed-request outcome. If an older systemd relay or LAN test
stack shares the host, keep it out of the evidence unless the tunnel route is
explicitly switched to it.

After initialization and before mail cutover, replace the complete public
enrollment set through the same host-local lifecycle rather than editing
generated files. Keep the JSON file owner-only and include every client that
should remain authorized:

```sh
punaro relay configure \
  --directory INSTALLATION_DIR \
  --relay-machines-file RELAY_MACHINES_FILE \
  --yes
punaro up --directory INSTALLATION_DIR
```

The command validates the exact non-secret set, atomically publishes the
daemon environment and Compose inputs, and preserves an interrupted update for
an exact retry. It is valid both before and after mail cutover; the cutover
marker itself cannot change. Removing a machine from the complete set prevents
new signed requests after the next `punaro up`; use `[]` to revoke the final
client. After mail cutover, additions with a new public key are rejected because
the active transition authority cannot authenticate them until the owner
registers that one key explicitly. For a new machine, keep its adapter disabled
and use the single protected JSON object printed by its installer:

```sh
punaro relay register \
  --directory INSTALLATION_DIR \
  --machine-enrollment-file /absolute/private/new-machine.json \
  --yes
punaro up --directory INSTALLATION_DIR
```

The registration transaction is owner-only and commits before marker-last
runtime publication. An interruption can leave a registered key absent from
the runtime, never the reverse; rerun the exact command to recover. Changed
retries and overlapping IDs, keys, endpoints, or prefixes fail closed. To
revoke a client, remove it with `relay configure`, stop its local adapter, and
revoke its distinct Access token. Never edit `punarod.env`, the Compose
override, `installation.json`, or PostgreSQL authority rows directly.

Relay authority requires a loopback device listener. For a legacy tunnel whose
origin is a private-LAN address, stage this installation on a free loopback
port, change the tunnel origin, verify signed traffic and readiness, and retain
the old origin as the rollback target until all adapters pass. Do not publish
the device listener on the LAN or preserve an old manual environment overlay;
`punaro up` and current daemon configuration fail closed for that state.

For every later release, use `punaro update --directory INSTALLATION_DIR` with
the protected release metadata distributed for that release. This preserves the
same durable update journal and recovery path as the initial installation; do
not replace `PUNARO_IMAGE` and restart the reference bundle directly.

Existing installations retain their published configuration through upgrade and
recovery. Re-run `punaro init --resume --directory INSTALLATION_DIR` only after
an interrupted first initialization; it never reinterprets new optional inputs
or opens a listener before the durable marker is complete. Backup and restore
continue to use their explicit lifecycle commands and a new target staging
directory rather than overwriting a live installation.

The application and PostgreSQL bind only to `127.0.0.1` for a separately
configured local tunnel or reverse proxy. The bundle defines no published ports;
do not publish PostgreSQL, the blob volume, or the daemon's unauthenticated
health listener. Optional worker, gateway, ingress, and backup roles are
intentionally deferred to later M23 slices.
