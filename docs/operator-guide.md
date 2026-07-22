# Operator guide

Punaro currently provides a loopback alpha text relay for enrolled adapters, a
separately deployable Telegram bridge, and a separately gated authenticated
trusted-attachment surface. The v2/v3 attachment runtime is retired from
production: all of its settings are rejected, its routes are unmounted, and
its binaries are not shipped. Its remaining material is historical evidence.

For the supported server/client installation sequence, see the
[installation guide](installation.md). The server installer creates only the
loopback systemd relay and its owner-controlled configuration; Cloudflare
Tunnel, Access, machine enrollment, and attachment release gates remain
explicit operator actions.

## Run locally

Use Go for the current local smoke test:

```sh
go run ./cmd/punarod
curl --fail http://127.0.0.1:8081/healthz
```

The legacy/application listener is deliberately restricted to a **literal**
loopback IP unless the isolated M-5 device policy is enabled.
`PUNARO_LISTEN_ADDR` must use `127.0.0.1:8080` or `[::1]:8080`; hostnames such
as `localhost` are rejected until the daemon can verify their resolved address.
Health and readiness use the distinct loopback-only
`PUNARO_HEALTH_LISTEN_ADDR` (`127.0.0.1:8081` by default).

Set `PUNARO_RELAY_ENABLED=true` plus a public
`PUNARO_RELAY_MACHINES_JSON` enrollment set to enable the alpha relay; see the
[onboarding guide](alpha-text-relay.md). `PUNARO_DATA_DIR` holds its SQLite
WAL state. `PUNARO_LOG_LEVEL` is validated as `debug`, `info`, `warn`, or
`error`, but does not yet filter the standard logger. An explicitly
named dotenv file is for local development only:

```sh
go run ./cmd/punarod --env-file .env
```

Process environment values override dotenv values.  Never commit, log, or
share a dotenv file, database, backup, private key, token, or message body.

### Retired v2/v3 evidence

The v2/v3 directory, permit, transfer, and controller implementations are not
production runtime surfaces. Their Go packages, CLI test harnesses, vectors,
RFCs, and focused tests remain available for source-level research and
regression evidence. Do not set their former environment variables or run
their provisioning helpers on a deployed relay: `punarod` rejects the
settings and mounts none of those routes.

Supported file operations use the separately gated trusted-relay surface and
the `punaro-trusted-attachment` native client. Build it with
`make trusted-attachment-client`; provide only an operator-configured fixed
HTTPS origin, absolute protected device-credential file, project UUID, stable
operation UUID, and existing safe download root. See the M-12 trusted-relay
section below and the [attachment skill](../skills/punaro-attachment/SKILL.md).

## Cloudflare Access under systemd

`punarod.service` denies non-loopback network access. Do not weaken that rule
just to fetch Access keys. Configure `PUNARO_ACCESS_ISSUER` and
`PUNARO_ACCESS_AUDIENCE` plus **exactly one** JWKS source:

- `PUNARO_ACCESS_JWKS_URL` is suitable only for a separately reviewed runtime
  that permits the daemon's narrowly understood HTTPS egress.
- `PUNARO_ACCESS_JWKS_FILE` is the systemd profile. The verifier accepts only a
  fresh, regular, non-symlinked file beneath a non-writable parent; its file
  mode must not allow group or world writes. A stale snapshot is a hard Access
  verification failure.

For a new Linux relay, `install-server.sh --machines-file ... --access-issuer
... --access-audience ... --access-jwks-url ... --enable` installs
`deploy/systemd/punaro-jwks-refresh.service`, `punaro-jwks-refresh.timer`, and
`refresh-jwks` for you. It creates `/etc/punaro/jwks` as `root:punaro` mode
`2750` (setgid), writes a root-owned mode-`0600`
`/etc/punaro/jwks-refresh.env` with the public HTTPS JWKS URL and
`PUNARO_ACCESS_JWKS_FILE=/etc/punaro/jwks/current.json`, refreshes it once, and
enables the timer before it restarts the relay to apply the rendered
configuration. The setgid directory gives an
atomic snapshot the non-writable `punaro` group without granting the refresh
unit `CAP_CHOWN`; the script writes it mode-`0640` and refuses redirects, an
empty response, oversized content, non-HTTPS URLs, or an output path outside
that directory.

For an existing manually managed relay, install the same three assets and
create the directory and environment file with those exact ownership and mode
requirements before enabling the timer. Do not put an Access service-token
secret in `punaro.env`; the relay validates end-user Access JWTs, while clients
keep their distinct service-token pairs in their own `adapter.env` files.

`/readyz` is deliberately unavailable until the configured JWKS source has
been parsed into at least one valid RS256 signing key. It rechecks that source
on every readiness probe, so a stale, missing, or malformed snapshot is a
service-unready condition rather than a deferred first-request failure.

Verify both `systemctl status punaro-jwks-refresh.service` and the timestamp
of the snapshot on every deployment and rotation. If the refresh fails or the
snapshot ages past the verifier cache interval, Access-protected requests are
denied rather than being served with an indefinitely stale key.

## Containers and systemd

The Compose file is a hardened build/run baseline, not a public deployment.
It intentionally publishes no port and does not import `.env`; provide only
the specific non-secret configuration a service needs.  The read-only root
filesystem leaves `/var/lib/punaro` as the only persistent writable location.

The supplied systemd units are a baseline. `cloudflared.service` and
`run-cloudflared` accept the tunnel credential only through systemd's
`LoadCredential`; keep the source file root-owned `0600` under
`/etc/punaro/credentials`, inject it directly from a secret manager, and never
place it in an environment file, command line, repository, or shell history.
The supplied units describe the current alpha SQLite path, not the accepted
PostgreSQL/OCI production shape. Before using them on Linux, run a smoke test
under the target distribution, verify SQLite WAL behavior, and record
`systemd-analyze security` with the exact systemd version. Keep the listener on
loopback and use a separately reviewed ingress only after the applicable
public-runtime release gate is complete.

### PostgreSQL substrate and relay qualification

PostgreSQL remains disabled unless both `PUNARO_POSTGRES_ENABLED=true` and an
absolute `PUNARO_POSTGRES_DSN_FILE` are supplied. The DSN file must be a private
regular file (`0600` on Unix) for the normal `punaro_app` role. Do not place a
DSN in an environment value, command line, checked-in dotenv file, or log.

Ordinary `punarod` startup and `/readyz` only inspect the database. They never
create or repair schema objects. A pristine, dirty, upgrade-required, newer, or
incompatible schema makes startup fail with a content-free classification. Do
not grant DDL to `punaro_app` to bypass that refusal.

Existing-schema migration is available only through `punaro update`. The
`punaro-migrate` image role requires the exact active update ID, verified backup
marker, target release/image/schema, exported snapshot, and manifest digest.
The host wrapper supplies those values to a hardened one-shot container and
mounts the owner DSN read-only; invoking the role without that durable evidence
fails closed. Pristine initialization remains part of `punaro init`.

The role contract uses the exact roles `punaro_owner` and
`punaro_app`. Provision `punaro_app` first as a login with no superuser,
database-create, role-create, public-schema-create, or `punaro_owner` membership;
the migrator refuses to bootstrap otherwise. The owner DSN must authenticate
directly as `punaro_owner` (not through `SET ROLE`), remain separately protected,
and be unavailable to `punarod`. The `--user` selection above lets the container
read the caller-owned `0600` bind mount without weakening it; use an equivalent
read-only secret mechanism in an orchestrator.
Concurrent migrators serialize on a PostgreSQL advisory lock. A migration left
in `applying` state is a dirty fence and is not silently repaired; preserve the
database and investigate. The digest-pinned `make test-postgres` stack is ephemeral
test infrastructure, publishes no database port, and deletes its volume on
exit.

The current binary requires schema version 8. Versions 1 through 7 are reported
as `upgrade_required`; damaged older objects remain `incompatible`. Migration 3 is
additive and creates the host-local ownership, pending enrollment, device
credential, cache/session generation, and Ed25519 migration-inventory records.
Migration 6 adds the durable update coordinator, exact recovery evidence, and
the mutation fence. Migration 7 adds the PostgreSQL mail store, durable
recipient cursors, replay protection, and relay-table mutation guards.
Migration 8 adds the M-9 cutover substrate: owner-only migration epochs,
bounded staging rows and checkpoints, and an application-role mail-write fence
for an importing or verified epoch. The host wrapper's one-shot executor is the
only supported authority transition. It always reads `relay.db` from Punaro's
validated private service data directory; there is no caller-selected source
path.
PostgreSQL mail work uses a reserved four-connection application-role pool;
each operation and lock wait is bounded to five seconds so platform work cannot
consume the mail budget indefinitely.

SQLite remains the default active relay. Maintainers may explicitly select an
empty PostgreSQL relay with `PUNARO_RELAY_STORE=postgres` only after completing
the supported update through schema v9. This selector does not import the SQLite file,
does not dual-write, and is incompatible with the superseded directory and
attachment routes. Do not point an established installation at an empty
PostgreSQL relay as a migration shortcut; the verified one-shot mail cutover is
a separate release gate. Before that cutover, rollback is selecting `sqlite`
again while retaining both stores unchanged.

### One-shot mail cutover

First complete the supported update through the exact current schema v9; the
preview and execution both fail closed on runtime-compatible schema v8 before
inspecting or preparing SQLite. Then stop ordinary operator changes, confirm every intended legacy machine is
`migrated` or explicitly `retired`, and run the read-only preview:

```sh
punaro mail cutover --directory /absolute/private/punaro --dry-run
```

Record the printed `source_fingerprint` and `target_identity`. Prepare one
protected JSON file containing the complete public static relay enrollment;
private keys and device bearer credentials must never appear in it. Choose one
UUID for the durable epoch, then execute exactly that binding:

```sh
punaro mail cutover --directory /absolute/private/punaro \
  --relay-machines-file /absolute/private/relay-machines.json \
  --epoch-id 019f7f07-8b88-7c12-a394-b663274a6555 \
  --expected-source-fingerprint SOURCE_SHA256 --yes
```

Punaro validates and durably publishes that public authority before preparing
the SQLite source. Exact retries may omit `--relay-machines-file` after this
publication; a different enrollment is rejected. The same command is the
crash-recovery command. It resumes the exact prepared source, checkpointed
staging, verified destination, retired source, active database, or marker-last
publication. Before source retirement only, abort the same epoch explicitly:

```sh
punaro mail cutover --directory /absolute/private/punaro \
  --abort --epoch-id 019f7f07-8b88-7c12-a394-b663274a6555 --yes
```

Abort is itself crash-safe. If PostgreSQL rejected the begin before creating
the epoch, Punaro first records an exact terminal abort reservation; a delayed
begin can then only observe that tombstone and cannot recreate an import fence.

After success, run `punaro up --directory /absolute/private/punaro` to recreate
the daemon from the published PostgreSQL and credential-transition settings.
Never reopen or replace the retired SQLite file. Once PostgreSQL accepts new
mail, recovery uses a PostgreSQL backup or forward repair.

Do not
hand edit ownership, enrollment, credential, idempotency, capacity, lease,
migration, update, restore, or audit rows to bypass a failure.

### Host-local device enrollment

`punaro-admin` is a one-shot image role and never opens a listener. Its owner
DSN must be protected exactly like the migrator DSN and must never be mounted
into `punarod`. Bootstrap is single-winner:

```sh
punaro-admin init -owner-dsn-file /absolute/private/owner.dsn -name "local owner"
```

Preview a bounded `trusted-agent` grant expansion before creating state. Use
repeatable `--project UUID` or the explicit dynamic `--all-projects`, never
both. The command exits with status 3 after printing the preview until `--yes`
is supplied:

```sh
punaro-admin client add -owner-dsn-file /absolute/private/owner.dsn \
  -actor-principal-id OWNER_UUID -name laptop -client-binding CLIENT_UUID \
  -project PROJECT_UUID
```

The confirmed run returns one enrollment ID and code. M-5 mounts bounded
redemption and device-session authentication under the transport policy below;
ownership and issuance remain host-local. Redemption binds the code to the
opaque client value, generates the 256-bit
credential secret by domain-separated derivation from the internally generated
256-bit code, and stores only an indexed SHA-256 digest. An exact retry with the
same code, client binding, and idempotency UUID returns the same result without
retaining plaintext while the original short enrollment lifetime remains
unexpired; any changed, expired, or ordinary replay fails. Never put an
enrollment code or device secret in
logs, shell history, audit fields, or an environment variable.

List credential metadata with `credential list`. Rotation requires the current
generation and two host-local steps. First run `credential rotate` with an
absolute new `--code-output` path; the command stages a short-lived random code
without invalidating the current credential and creates that file exclusively
as `0600`. Then rerun with the same generation and `--code-file`; exact retries
within that code's short lifetime derive and return the same internally
generated credential without storing it in plaintext. Symlinks, non-regular
files, permissive modes, and malformed
codes are rejected. `credential revoke` is immediate locally,
and other processes/sessions force reauthentication within the documented
two-second bound. Existing Ed25519 relay authentication remains active in this
slice; its PostgreSQL inventory and disable gate stage the later explicit
cutover and do not silently change current SQLite routing.

Migration 4 adds project identities, aliases, generation-bound merge previews,
and bounded reconciliation records. Migration 5 adds the backup GC-fence,
READY-blob manifest, restore-history, and timeline-rotation substrate. It does
not change relay authority. Migration 10 adds dark trusted-attachment
reservation, quota, claim, READY publication, and reconciliation state. It
does not mount an attachment route and is not authorization to expose the blob
volume. The private blob root is `$PUNARO_DATA_DIR/blobs`; it and its `staging`,
`ready`, and cross-process `locks` children must remain private, with staging
and ready on one filesystem, owned by the daemon account, and mode `0700`.
Blob and lock files are mode `0600`. Backup copies only database-READY
manifest entries; staging files, filesystem-only orphan finals, and known
`CORRUPT` artifacts are excluded.
The later route-mounting milestone must run the bounded reconciler after restore
and before accepting uploads so abandoned-timeline reservations are removed
before their quota is released; schema v10 exposes no operator upload command.

Migration 11 adds dark stable-principal recipient snapshots and bounded
download authorization. Device-bearer endpoint advertisement records its
principal with the lease; legacy-signed advertisement clears that binding and
keeps the endpoint mail-only. Project-bound conversations and attachment-bearing
messages recheck current capability and credential generation, and the message
transaction creates recipient grants from its exact delivery snapshot. The
application role has execute-only routines and cannot inspect the grant tables.
The server-side service verifies the complete exact private blob before any
download bytes are emitted, limits downloads to 16 concurrent streams and ten
minutes, and makes artifact-lock waits cancellation-aware. Project-bound
conversations fence project merge. Migration 11 still mounts no reservation, upload,
download, or delete route, so it creates no new operator command or public
surface.

Migration 12 adds the dark destructive lifecycle. Authorized deletion first
withdraws recipient visibility and the READY backup projection, while retaining
the immutable blob and charged quota for a 24-hour restore window. Physical GC
is blocked by an active backup fence and holds shared backup exclusion across
the expiring generation/token claim, durable unlink, and conditional
finalization; quota is released only after that unlink. Backup fence acquisition
waits for every such holder.
Corrupt artifacts follow the same delayed path. The bounded restore-skew scan
requires old filesystem namespaces, authoritative database absence, the
artifact lock, and the same backup exclusion held through unlink. A
state-changing scan restarts from the beginning. Restoring older data can
resurrect a deletion made after that snapshot.

M-12 adds a separately gated trusted-relay surface without enabling it in the
generated operator configuration. To exercise a reviewed self-hosted build,
set both `PUNARO_TRUSTED_ATTACHMENTS_ENABLED=true` and
`PUNARO_TRUSTED_ATTACHMENT_BLOB_DIR=/var/lib/punaro/blobs` alongside the
existing PostgreSQL device-auth and ingress settings. The blob root must
already be an absolute clean directory owned by the daemon account with mode
`0700`. Startup requires the exact current schema v13; merely compatible
v10-v12 mail schemas cannot mount this opt-in surface. Startup fails before binding if the schema, root, authority, ingress
policy, or bounded database/filesystem reconciliation is unavailable. A
periodic fail-closed sweep continues abandoned, corrupt, tombstoned, and orphan
cleanup; `/readyz` fails while that maintenance cannot complete.

Build the native client with `make trusted-attachment-client`. It reads
the bearer value only from an absolute protected regular file and never accepts
it on the command line or prints it. The supported commands are:

```sh
punaro-trusted-attachment send \
  --origin https://punaro.example \
  --credential-file /run/credentials/punaro-device \
  --project 00000000-0000-4000-8000-000000000001 \
  --idempotency-key 00000000-0000-4000-8000-000000000002 \
  --file /absolute/source/report.pdf \
  --name report.pdf \
  --media-type application/pdf

punaro-trusted-attachment receive \
  --origin https://punaro.example \
  --credential-file /run/credentials/punaro-device \
  --artifact 00000000-0000-4000-8000-000000000003 \
  --download-root /absolute/private/downloads
```

Retry `send` with the same idempotency key and unchanged inputs after a lost
response; an authoritative READY reservation skips the upload. `receive`
restarts an interrupted bounded stream, verifies exact size and SHA-256 in a
private stage, and creates the final root-relative name without replacement.
Unsafe, traversal-like, or portable reserved display names fall back to
`attachment-<artifact-id>`. An existing destination is never overwritten.
Deletion uses `delete` with a fresh stable `--idempotency-key`; it returns after
the tombstone, before backup-window physical GC.

The v2/v3 production switches are retired. Their packages, vectors, RFCs, and
tests remain experimental evidence only and cannot authorize deployment.

### Operator wrapper and device ingress

`punaro init` is the supported first-install path for the staged PostgreSQL
platform. Create separate private data and backup directories and separate
`0600` DSN files for `punaro_owner` and `punaro_app`. Build the host wrapper
with `make operator-binary`; do not run it inside the daemon container. Supply
only the reviewed release image by immutable registry digest. Run init as the
non-root Unix account that owns the private paths; root is rejected and the
same numeric identity runs the container. Data and backup must resolve to
non-overlapping locations. Supply every path in its already-clean absolute
form: `.`/`..` components, duplicate separators, and trailing separators are
rejected. Neither DSN nor the installation directory may
resolve beneath the daemon-writable data directory, including through a
symlinked ancestor. Each private directory and DSN file must be owned by that
account. Every path ancestor must be owned by root or that account and may not
be group/world writable unless sticky; only root-owned system symlinks with a
separately trusted resolved chain are accepted:

```sh
punaro init \
  --directory /absolute/private/punaro-installation \
  --data-dir /absolute/private/punaro-data \
  --backup-dir /absolute/private/punaro-backups \
  --image registry.example/punaro@sha256:REVIEWED_DIGEST \
  --owner-dsn-file /absolute/private/owner.dsn \
  --app-dsn-file /absolute/private/app.dsn \
  --owner-name "local owner" \
  --mode internet \
  --public-url https://punaro.example
```

Proxy mode has the same HTTPS and loopback-origin requirements. Trusted-LAN
plaintext is deliberately noisy and must name both a concrete private or
link-local bind and the containing CIDR:

```sh
punaro init ... --mode lan --listen-addr 192.168.50.4:8080 \
  --trusted-lan-cidr 192.168.50.0/24 --allow-lan-http
```

A non-loopback trusted-LAN listener is valid only for the two bounded device
routes added by M-5. Configuration fails closed if legacy relay, directory,
permit, or attachment routes are enabled on that process. Those surfaces stay
loopback-only until their separately reviewed public runtime milestone. Health
and readiness are mounted on the separate `127.0.0.1:8081` listener by default;
override it only with `--health-listen-addr` naming another distinct concrete
loopback address.

Fresh initialization requires the application-role view to be pristine,
migrates through the owner role, then reopens both roles and proves their
installation and timeline IDs match before creating the owner. It publishes
the generated configuration last. If the process reports
an uncertain owner outcome or publication failure, preserve the staging
directory and run only:

```sh
punaro init --resume --directory /absolute/private/punaro-installation
```

Resume verifies the staged files and exact owner label, adopts the singleton
owner if it committed, or finishes bootstrap if it did not. Do not delete the
staging directory or run a second bootstrap elsewhere while recovering.

`punaro up --directory ...` rechecks the generated Compose file, protected
paths (including ownership and ancestor permissions), exact
singleton-owner identity, and schema before invoking Compose. Status
and doctor enforce the same owner binding. The generated file
has no build context and accepts only the pinned image. The wrapper supplies a
stable Compose project name from the verified owner UUID, so equal installation
directory basenames cannot share containers. It also removes inherited
`PUNARO_*` and `COMPOSE_*` variables from the Compose subprocess, making the
validated generated environment authoritative while retaining Docker connection
settings. The operator-controlled Docker executable, CLI plugins, configuration,
and selected daemon/context remain trusted dependencies; use a local daemon for
this host-local wrapper because bind-path validation does not extend to a remote
Docker host. It starts only a compatible schema and refuses while an update
transaction owns the maintenance fence;
a pristine database after initialization is treated as data loss, an old schema
refuses startup and directs the operator to use the supported update or previous
compatible release. Dirty/newer/incompatible state
requires recovery. It waits up to 30 seconds for readiness and then runs the
same checks as doctor. Raw `docker compose up` and `punarod` never migrate.

Use `punaro status --directory ...` for a non-mutating report and `punaro doctor
--directory ...` for a failing health gate. Reports contain only capability and
content-free path/schema/health states. The generated M-5 server Compose file
still uses an externally provisioned PostgreSQL service; the bundled production
PostgreSQL/profile shape arrives in M-23.

Create a client in two exact steps. The first prints the effective grants and
preview hash without touching the database. The confirmed invocation must
repeat the same grant flags and bind the prior hash:

```sh
punaro client add --directory /absolute/private/punaro-installation \
  --name laptop --project PROJECT_UUID
punaro client add --directory /absolute/private/punaro-installation \
  --name laptop --project PROJECT_UUID --yes \
  --confirm-preview-hash HASH_FROM_THE_PRIOR_OUTPUT
```

The second response contains the generated client binding, enrollment ID, and
single-use code. Send the exact four-field JSON object to
`POST /v1/enrollments/redeem`; retain the returned bearer credential only in
protected client storage. `GET /v1/device/session` is the bounded authentication
check. Forwarded headers never qualify a direct request for TLS or trusted-LAN
admission.

### Consistent backup and clean-stack restore

M-6 supports local, verified recovery points for the staged PostgreSQL
platform. `pg_dump` and `pg_restore` must be installed on the operator host.
Database DSN files must use canonical single-host TCP `postgresql://` or
`postgres://` URI form. Unix sockets, multi-host URIs, URI fragments, service
files, host overrides, and encrypted client-key password parameters are not
supported;
the wrapper removes the password from process arguments, rejects inherited
`PG*` overrides, and supplies it through a temporary owner-only pgpass file.

Create and immediately verify a backup:

```sh
punaro backup --directory /absolute/private/punaro-installation
punaro backup list --directory /absolute/private/punaro-installation
punaro backup verify --backup /absolute/private/punaro-backups/BACKUP_DIRECTORY
```

The command commits a database GC fence before exporting one repeatable-read
snapshot. The schema-owner `pg_dump` and application-role READY-blob query use
that same snapshot. The exporter and renewable GC fence remain live until every
selected immutable blob has been copied, length/digest checked, synchronized,
and the complete hidden stage verifies. Only then is the backup renamed into
view. Failures before rename leave no published backup; a parent-directory sync
failure reports the published path as durability-uncertain so the operator can
verify it explicitly. A backup contains the custom
database dump, generated Punaro configuration, both Punaro database credential
files, and verified READY blobs. Its manifest lists host TLS, proxy/tunnel,
Telegram, and OAuth state as external dependencies rather than copying them.
Keep the backup directory private; optional storage encryption and an off-host
copy are recommended operational controls.

Restore only into a stopped, separately provisioned pristine database and new
filesystem paths. The target must already have the safe `punaro_owner` and
`punaro_app` roles plus distinct protected target DSN files; both DSNs are
proved to reach the same pristine database before `pg_restore` starts:

```sh
punaro restore \
  --backup /absolute/private/punaro-backups/BACKUP_DIRECTORY \
  --into-new-stack /absolute/private/restored-installation \
  --data-dir /absolute/private/restored-data \
  --backup-dir /absolute/private/restored-backups \
  --owner-dsn-file /absolute/private/restored-owner.dsn \
  --app-dsn-file /absolute/private/restored-app.dsn
```

For an update-bound recovery backup, the exact command must also name the
independent receipt written by the failed update before migration:

```text
  --update-receipt /absolute/private/old-installation/.update/recovery.json
```

Keep that receipt until the update is committed, recovered, or aborted. It is
deliberately outside the backup; a v2 update backup cannot authorize its own
restore.

Restore re-verifies the complete backup before mutation, stages and verifies
all blobs, restores the database in one `pg_restore` transaction, preserves the
installation ID, rotates the timeline, and publishes the new data and generated
configuration only at the end. Each boundary is recorded in a private durable
journal beside the new data path. If any post-mutation step fails, stop the old
stack and retry the exact same command: it resumes the bound journal without
repeating completed database or timeline mutation. Do not delete or edit the
journal or target paths. Existing targets on a new request, overlaps,
symlinks, permissive paths, non-pristine databases, identity drift, and an
unrotated timeline fail closed. Clients observing the new timeline must discard later
cursors/caches and re-enumerate authoritative state. Optional gateways remain
not ready until their external dependencies are supplied or re-enrolled.

Update-created version 2 backups additionally bind the exact update ID, source
schema and state coordinates, target release/image digest, exported snapshot,
and raw manifest digest. Before the database accepts that backup marker, the
host writes a protected receipt outside the backup. Restore requires both and
binds the receipt path and digest into its resume journal before mutation.
Restoring one automatically reconstructs the same fenced update transaction on
the rotated timeline; it does not reopen writes.
Run restore drills and retain a verified off-host copy before admitting
irreplaceable data.

### Supported update and rollback

`punaro update` is the only supported existing-schema migration path. It manages
the one generated `punarod` writer and the externally provisioned PostgreSQL
database. Any additional writer using the same database is outside this
generated-stack contract and must be stopped separately before adoption. The
bundled production PostgreSQL/profile shape remains M-23.

Run the host-side `punaro` wrapper shipped by the target release; its embedded
migration manifest and generated Compose template are part of the target
boundary and a source-release wrapper is intentionally rejected. Use the
target release's published, protected metadata whose `image` is digest-pinned,
`release_sha256` equals that image digest without the `sha256:` prefix,
`compose_sha256` matches the generated Compose artifact, and migration-manifest,
schema-range, rollback-floor, and PostgreSQL-major values match the target
release. The file must be an absolute private regular file. On the first update
from an installation without a release-name lock, supply the current release:

```sh
punaro update \
  --directory /absolute/private/punaro-installation \
  --release-metadata /absolute/private/releases/v0.7.0.json \
  --source-release v0.6.0
```

Before maintenance, the wrapper checks private paths, current health and owner
identity, disk capacity, PostgreSQL major, target compatibility, the exact
pulled image digest, and the Compose hash. It then acquires the transactional
database fence, drains earlier mutations, stops the configured writer, proves
it stopped, creates and verifies the bound backup, and records that marker. The
exact target image runs the one-shot migrator with a read-only owner DSN mount;
the normal daemon never receives that credential. The target starts while the
fence still rejects business writes and must pass readiness and doctor before
configuration is published and the database commit reopens writes.

Rerun the exact command after a crash or uncertain external command. It resumes
the durable PostgreSQL phase and private host journal without repeating completed
work or requiring another registry pull. Do not edit `.update`, the release
metadata, database update rows, or the verified backup. A pre-migration failure
may be abandoned only with the same arguments plus `--abort`; the previous
digest must start and pass doctor before the fence is released:

```sh
punaro update \
  --directory /absolute/private/punaro-installation \
  --release-metadata /absolute/private/releases/v0.7.0.json \
  --source-release v0.6.0 \
  --abort
```

After migration starts, `--abort` is refused. Explicitly select `--recover
compatible` only when the recorded previous image actually starts and passes
readiness plus the recovery doctor against the migrated schema while still
fenced. Otherwise restore the exact update-bound backup into a stopped,
pristine database and new paths using the normal `punaro restore` command above
with its `--update-receipt`. Then
resume the reconstructed transaction from the restored installation:

```sh
punaro update \
  --directory /absolute/private/restored-installation \
  --release-metadata /absolute/private/releases/v0.7.0.json \
  --recover restore
```

The restored source image, source schema, owner, installation/timeline state,
backup marker, readiness, and doctor must all match before recovery commits and
writes reopen. Keep the abandoned stack stopped. Raw `docker compose up`, raw
`punarod`, and direct `punaro-migrate` invocation never clear or bypass a live
fence.

### Dark native memory read API

M-17A adds an opt-in server read surface without enabling a native client or
memory mutations. New installations persist the supported choice with
`punaro init --memory-api`; without that flag the generated environment records
`PUNARO_MEMORY_API_ENABLED=false`. The generated Compose override passes the
persisted setting, so later `up`, update, resume, and restore operations do not
depend on ambient shell state. Startup fails before binding if the enabled
platform database does not provide the complete memory read authority. Existing
installations remain dark until a later supported configuration command is
delivered; do not hand-edit their generated environment or installation marker.

The mounted v1 surface provides strict authenticated project resolution,
authorized memory/proposal get, bounded lexical search and prompt brief, and a
timeline-aware content-free change feed. Every response is `Cache-Control:
no-store`; the server never accepts a principal ID from the caller. A first
change request uses `"cursor": null`; clients must retain the returned
installation/timeline/sequence cursor and discard it on the typed restore or
future-cursor conflict. There is intentionally no offline writable brain,
mutation route, CLI/MCP binary, semantic retrieval, or Compose Pi integration
in this slice.

### Dark native memory mutations

M-17B keeps every existing read-API installation read-only on upgrade. A new
installation must explicitly pass both `punaro init --memory-api` and
`--memory-mutations`; the persisted environment then records
`PUNARO_MEMORY_MUTATIONS_ENABLED=true`. The mutation flag cannot be enabled
without the read flag. Resume, update, and restore preserve the choice, while
historical installation files that predate the mutation setting are accepted
only as mutation-disabled generations. Do not hand-edit generated files.

The enabled surface adds canonical create/update/archive/restore/purge and
proposal create/approve/reject. Every operation needs a fresh canonical UUID
`Idempotency-Key`; updates, state changes, purge, and proposal decisions also
need the exact strong ETag returned by the preceding read or mutation in
`If-Match`. Retired project aliases are readable compatibility coordinates but
are deliberately rejected for every mutation. Purge requires its distinct
capability and is irreversible. Secret-shaped documents are rejected without
echoing the value or fingerprint. There is still no native client, MCP adapter,
semantic retrieval, offline queue, or Compose Pi integration.

## Operations and incident response

If a credential or machine is suspected compromised, stop the local service,
preserve relevant logs without copying secrets or message bodies, then follow
the alpha machine-revocation sequence in
[the onboarding guide](alpha-text-relay.md#onboard-and-revoke-a-machine): remove
the attachment-group memberships, remove the relay enrollment, revoke the
machine-scoped Access token and policy, restart the relay, and securely erase
the private key. Verify rejection of both the revoked Access credential and a
request signed by the removed machine before any replacement is enrolled.

This is an alpha text-relay procedure, not a substitute for the still-required
production restore and revocation exercise. Do not re-enable the compromised
machine or reuse its machine ID or endpoint namespace.
