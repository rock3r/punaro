# Operator guide

Punaro currently provides a loopback alpha text relay for enrolled adapters, a
separately deployable Telegram bridge, and a controlled v3 attachment-runtime
validation surface. It is not a released public service or production file
transfer system. Do not use it to carry sensitive production work yet.

For the supported server/client installation sequence, see the
[installation guide](installation.md). The server installer creates only the
loopback systemd relay and its owner-controlled configuration; Cloudflare
Tunnel, Access, machine enrollment, and attachment release gates remain
explicit operator actions.

## Run locally

Use Go for the current local smoke test:

```sh
go run ./cmd/punarod
curl --fail http://127.0.0.1:8080/healthz
```

The listener is deliberately restricted to a **literal** loopback IP.
`PUNARO_LISTEN_ADDR` must use `127.0.0.1:8080` or `[::1]:8080`; hostnames such
as `localhost` are rejected until the daemon can verify their resolved address.
A non-loopback address is a configuration error, even for health checks.

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

### Signed attachment-directory distribution and permit issuance

The v2 file-transfer API is disabled. A deployment may, however, exercise
the prerequisite signed directory distribution independently by setting
`PUNARO_DIRECTORY_ENABLED=true` and an absolute
`PUNARO_DIRECTORY_SNAPSHOT_FILE`. The relay must also be enabled with its
normal machine enrollment set. For a separately privileged publisher, make the
snapshot parent `root:punaro` mode `2750` and the published regular,
non-symlinked file `root:punaro` mode `0640`: the relay needs only group read
access, never write access to either path. Keep that service group limited to
the relay; issuer keys in the same parent remain owner-only `0600` files. The
daemon validates the complete canonical CBOR snapshot on every request and
returns no cached fallback.
Publish an updated snapshot by atomically replacing the configured file. The
only endpoint is authenticated `GET /v2/directory`; it requires both
the enrolled machine's signed request and, when configured, Cloudflare Access.

The directory endpoint is a validation aid for enrollment, directory
publishing, and revocation drills. It does not itself enable file transfer.

### Receiver egress preflight

Every attachment receiver must be permitted by its local outbound policy to
make authenticated HTTPS requests to the Access-protected relay. An adapter
that happens to have a working persistent connection, or a successful `curl`
health probe, does not prove that a newly started attachment receiver can
complete its own TLS handshake and signed `GET /v2/directory` request.

Every directory publisher, relay, sender, and receiver also needs working NTP
time synchronization. A directory head may be valid for up to five minutes
and accepts at most 60 seconds of future clock skew; per-operation permits
remain valid for at most 30 seconds. This margin handles normal scheduling and
NTP convergence, but never extends expiry or replaces NTP. Do not disable
freshness checks: repair a materially drifting host, then run the receiver
preflight again.

Before enabling controlled attachment delivery on each machine, and after an
Access, firewall, certificate, network, or directory-publisher change, run
the locally provisioned receiver command:

```sh
punaro-attachment check
```

`check` makes one fresh authenticated directory request and verifies its pinned
root trust and durable anti-rollback checkpoint. It does **not** read an offer,
issue a permit, create a transfer, or write an output file. Treat any failure
as a deployment blocker: authorize the receiver executable's required HTTPS
egress or repair the configured relay/Access path, then run the same check
again. Do not bypass it with a public link, mailbox payload, Telegram upload,
or a direct peer channel.

An operator may additionally exercise only the permit-issuance prerequisite by
setting `PUNARO_PERMIT_ISSUANCE_ENABLED=true`. This requires the directory
service above and all of the following explicit inputs:

- `PUNARO_DIRECTORY_AUDIENCE`, `PUNARO_DIRECTORY_ROOT_KEY_ID`, and
  `PUNARO_DIRECTORY_ROOT_PUBLIC_KEY`: canonical raw-base64url 32-byte root
  trust material.
- `PUNARO_PERMIT_ISSUER_KEY_ID`: canonical raw-base64url 32-byte key ID, and
  `PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE`: an absolute private (`0700` parent,
  `0600` non-symlink regular file) containing exactly one canonical
  raw-base64url 64-byte Ed25519 private key.
- `PUNARO_PERMIT_MAX_LIFETIME_SECONDS` (1–60; 1–30 for v3),
  `PUNARO_PERMIT_MAX_BYTES` (1–67108864), `PUNARO_PERMIT_MAX_CHUNKS`
  (1–4096), `PUNARO_PERMIT_MAX_OPERATIONS` (1–4096), and
  `PUNARO_PERMIT_MAX_ACTIVE` (1–4096). There are no defaults. For v2 it is a
  global capacity limit for concurrently live permits; expiry cleanup is
  transactional and removes the permit plus its issuance and redemption rows.
  For v3 it bounds retained issuance identities per holder (including
  short-lived retry tombstones), while the source store separately enforces
  aggregate transfer capacity. An exact retry does not consume another slot.
  Size this for the whole attachment lifecycle, not just one permit: a
  maximum-size v3 transfer can require a few hundred per-device issuance
  identities across upload and receipt download. `512` is the practical
  minimum for a single 64 MiB transfer with ordinary retries; increase it
  deliberately for concurrent large transfers while retaining the configured
  per-holder bound.
- At least one `PUNARO_RELAY_MACHINES_JSON` record with an
  `attachment_device_id`, encoded as canonical raw-base64url 16-byte data.
  Each device ID may be bound to only one machine. The permit route rejects a
  request unless its replay-protected machine signature matches the configured
  holder device binding; a holder signature by itself is not network admission.

`POST /v2/permits` is protected by the same optional Access middleware as the
relay, then machine signature/replay protection, then the holder/device binding
and a newly read, root-verified directory snapshot. A missing, stale, rolled
back, or equivocated snapshot rejects issuance. It persists both the directory
anti-rollback checkpoint and issuance idempotency under
`$PUNARO_DATA_DIR/attachment-v2` with private SQLite permissions.

The attachment operation routes are not mounted. Both
`PUNARO_ATTACHMENT_RELAY_ENABLED=true` and the legacy
`PUNARO_ATTACHMENTS_ENABLED=true` fail closed until the complete attachment v2
release gates, including capacity/reaping and source-ready evidence, are met.
Permit issuance is not a transfer release and does not relax any attachment
release gate.

### Controlled v3 attachment runtime

V3 is a separate protocol and route namespace; it does not turn on v2. For a
controlled validation deployment, set `PUNARO_ATTACHMENT_V3_ENABLED=true` and
leave both `PUNARO_ATTACHMENTS_ENABLED` and
`PUNARO_PERMIT_ISSUANCE_ENABLED` unset/false. In addition to the relay,
directory, root trust, issuer key, permit limits, and enrolled
`attachment_device_id` records listed above, provide:

Use the reviewed provisioning helpers in
[the installation guide](installation.md#4-provision-and-enable-controlled-attachment-v3)
to create these files and enable the relay. They intentionally separate the
offline root authority, relay issuer, and per-client device keys; they never
copy a root key to the relay or accept a wrapping key/token as a command-line
value. Manual configuration must preserve the same separation and private file
permissions.

- `PUNARO_ATTACHMENT_V3_SOURCE_STORE_FILE`: an absolute path beneath an
  existing private, non-symlinked `0700` directory. The daemon creates a
  `0600` SQLite file there; do not put it on NFS, a shared filesystem, or a
  synchronized folder.
- A current root-signed directory snapshot that names the sender, recipient,
  membership, and active permit issuer. A missing, expired, rolled-back, or
  revoked snapshot makes `/readyz`, issuance, and attachment operations fail
  closed.
- For remote use, Cloudflare Access plus machine request signatures. Access is
  an admission layer, not a substitute for the enrolled machine-to-directory
  device binding enforced by both `/v3/permits` and `/v3/attachments/...`.

The v3 daemon mounts only `POST /v3/permits` and the exact routes in
[`attachments-v3-rfc.md`](attachments-v3-rfc.md). A source-init permit is
accepted only if the exact holder-signed issuance request is present in the
same private journal; subsequent permits are registered in the source ledger
before a response is sent. Request identities and exact operation retries have
bounded tombstone retention, so do not delete or restore the source database
piecemeal.

The daemon runs a bounded reaper batch once a minute and waits for that worker
to stop before it closes SQLite. It only reclaims already expired retry,
receipt, source, and issuance-journal state; it never authorizes a request or
uses a cached directory decision. A fresh directory revocation or membership
change fences the next permit or attachment operation immediately. Treat a
denied transfer as terminal for the old credentials: rotate/re-enroll as
needed and start a new transfer rather than trying to restore old permits.

After the sender receives the successful `offer` operation result, it must
durably enqueue the offer in its local `OfferNoticeOutbox` before treating
recipient discovery as handed off. `punaro-adapter attachment-notify` does
this and then attempts immediate delivery; the long-running adapter drains the
same private SQLite outbox on every cycle. Use a stable transfer-scoped
idempotency key. The notice carries the canonical offer record only; it is
bounded to the relay's ordinary message limit and contains no plaintext or
public URL. A crash after relay acceptance but before the local delete is safe
because the exact append is retried. Do not re-wrap or mutate the offer.
Recipients parse the notice locally, then independently fresh-verify and use
recipient permits. The outbox uses a private, single-connection SQLite file in
the adapter data directory and admits at most 64 pending notices (2 MiB total,
including bounded route and idempotency fields) without evicting an
undelivered record. If it fills, restore relay connectivity and let the adapter
drain it; do not delete pending rows to make space.

### Local v3 receipt controller

`punaro-attachment` is the local-only control surface for v3 offer discovery.
It owns an immutable controller journal and must run with a recipient identity
already assigned to this machine. Set these non-repository environment values
through the normal service-secret mechanism (for example a service-manager
environment file or `op run`):

- `PUNARO_ATTACHMENT_CONTROLLER_JOURNAL`: absolute private SQLite path.
- `PUNARO_ATTACHMENT_RECIPIENT_ID`: canonical raw-base64url 16-byte local
  attachment device ID.
- `PUNARO_ATTACHMENT_RECIPIENT_GENERATION`: its non-zero directory generation.

An operator first provisions the directory-to-relay relationship with
`punaro-attachment map`. A delivered typed mailbox offer is then recorded with
`punaro-attachment record`, and only a deliberate
`punaro-attachment approve --message-id …` can mark that exact canonical offer
for a future receipt worker. Approval is not acceptance, download, or
decryption. The controller never accepts arbitrary permit records, URLs,
Access headers, or device keys on its command line.

### Local v3 sender controller

A source machine uses a distinct sender journal; it must not share the
recipient controller journal. Provision these private, absolute paths and
identities through the service-secret mechanism, never through mailbox text or
command-line key flags:

- `PUNARO_ATTACHMENT_SENDER_JOURNAL`: private sender SQLite journal.
- `PUNARO_ATTACHMENT_ARTIFACT_STORE`: separate private SQLite reservation
  store for file-key/salt/nonce uniqueness.
- `PUNARO_ATTACHMENT_OFFER_OUTBOX`: the same private
  `attachment-offers.db` path used by the local `punaro-adapter` data
  directory, so its normal sync loop can recover an undelivered offer notice.
- `PUNARO_ATTACHMENT_SENDER_ID` and
  `PUNARO_ATTACHMENT_SENDER_GENERATION`: this machine's directory attachment
  device and non-zero generation.
- `PUNARO_ATTACHMENT_SENDER_SIGNING_PRIVATE_KEY_FILE`: absolute private
  sender signing key path.
- macOS: `PUNARO_ATTACHMENT_HOST_KEY_SERVICE` and
  `PUNARO_ATTACHMENT_HOST_KEY_ACCOUNT`, naming a Keychain generic-password
  whose value is a 32-byte base64 key. Linux/systemd:
  `PUNARO_ATTACHMENT_HOST_CREDENTIAL_DIRECTORY` and
  `PUNARO_ATTACHMENT_HOST_CREDENTIAL_NAME`, naming a private LoadCredential
  file. This host-bound key wraps the per-file key; it is not an environment
  value or journal field.

The sender additionally needs the same machine credential, relay URL,
directory root/checkpoint, and optional paired Cloudflare Access service-token
variables as `receive`. First pin the exact relationship locally with
`punaro-attachment map-sender` using the same mapping flags as `map`; the
command rejects a mapping whose source device is not the configured local
sender. Then send only a local absolute regular input path:

```sh
punaro-attachment send \
  --input /absolute/private/source-file \
  --relay-conversation RELAY_CONVERSATION_ID \
  --from agent/local-machine/attached-session \
  --stage-id STABLE_CANONICAL_16_BYTE_BASE64URL_ID
```

Keep the stage ID until the recipient has confirmed the transfer. Re-running
the exact command after a crash resumes the already sealed immutable source;
once an expired source is reaped its ID becomes a non-reusable tombstone, so
start a new transfer with a new ID rather than retrying it. Never reuse an ID
for another file or conversation. The command validates its sender endpoint
and reserves the exact offer outbox capacity before staging; the row becomes
relay-flushable only after the offer operation succeeds. A crash-held row is
ignored by the adapter and is never age-reaped. While the signed manifest and
outcome capability remain valid, rerun the same stage so durable recovery can
decide whether to activate it. After that lifetime it is deliberately
fail-closed quarantine: do not delete or hand-edit it; follow the audited
operator incident procedure, because neither a stale manifest nor a stale
outcome capability can prove safe delivery. If an immediate relay attempt
fails, the command returns an error but leaves ambiguous delivery rows for
`punaro-adapter` to flush. A proven pre-append authorization rejection releases
only that exact row, allowing an operator to correct the endpoint and retry.

#### Expired held-offer incident procedure

There is intentionally no in-product command that deletes or activates an
expired inactive offer: its signed manifest and outcome capability can no
longer establish which remote mutation occurred. Treat this as a local
availability incident, not a reason to edit SQLite. Stop the sender command
and adapter, preserve private copies of the sender journal and offer outbox
with their ownership and permissions intact, and record the stage ID, transfer
ID, relay conversation, and relevant relay audit window. An authorized
operator must determine whether the old, now-expired transfer can be ignored.
After that audit, keep the preserved copies as incident evidence and provision
new private sender-journal, artifact-store, and offer-outbox paths; create a
new stage ID and transfer. Do not reuse the quarantined stage ID, do not alter
the old databases in place, and do not recover by changing the old offer route.

V3 uses the conservative finite source limits compiled into the current
runtime (64 MiB artifact, 4096 chunks, 256 KiB plaintext chunk; finite sender,
recipient, conversation, and relay reservations). It is a singleton SQLite
deployment shape. Do not run more than one writer against the source database.
For a generic deployment, use one `punarod` process in a container or LXC,
bind it to loopback, and let a Cloudflare Tunnel reach that loopback listener;
the repository intentionally contains no hostname, tunnel, account, token, or
deployment-specific example.

This is a controlled validation feature, not a production-release declaration.
Before allowing sensitive files, complete the v3 vector/fuzz, restore,
revocation, independent-review, and release-evidence gates below.

### Create v3 directory material

`punaro-directory` avoids hand-encoding signed CBOR. Run it only from a
private `0700` directory; it never prints a private key and refuses to create
an output over an existing file. Generate root/issuer/device signing keys with
`keygen --algorithm ed25519`, device HPKE keys with `keygen --algorithm
x25519`, and public 16- or 32-byte identifiers with `id --bytes 16|32`.
Each command prints a small JSON object containing only public base64url data.
The manifest has only `audience`, `root_key_id`, `sequence`,
`revocation_epoch`, and an ordered `entries` array; each entry has exactly one
of `device`, `membership`, or `issuer`. Unknown or
duplicate fields are rejected. Build a short-lived snapshot from that
non-secret JSON manifest using `build --config ... --root-private-key-file ...
--output ... --ttl 2m`, then atomically publish that new file at
`PUNARO_DIRECTORY_SNAPSHOT_FILE`. Keep the root and issuer private keys
separate from the relay runtime; only the issuer key belongs in the relay's
private credential directory. Never place device private keys, root keys, or
issuer keys in the manifest, an environment file, or source control.

For a Proxmox-contained relay, use
[`scripts/publish-directory-snapshot.sh`](../scripts/publish-directory-snapshot.sh)
from the separate root-key host. It builds one fresh two-minute snapshot and
copies only that signed snapshot through the Proxmox host, then changes mode
and atomically renames it inside the target container. Put its environment in
an owner-only service configuration and schedule the next publication only
after the prior two-minute snapshot and every permit it could have issued have
expired (for example, a 121-second interval). Do not rotate a still-valid head:
permits bind to that exact signed head. Do not run it on the relay or copy the
root key into the container. This deliberately creates a brief unready
rollover boundary; callers must retry a fresh operation after it. If a publish
fails, that unready state continues rather than extending an old snapshot's
lifetime. Serialize publisher invocations and use a unique private staging
filename for every attempt; an older invocation must never overwrite a newer
snapshot. The supplied publisher uses a local advisory lock (via the standard
`python3` `fcntl` module) that is released by the kernel after a crash or
reboot; its persistent lockfile is not itself a failure condition.

Directory history is append-only. For an update, retain every existing entry
in the same order, append new/revocation entries, increment `sequence`, and
keep `revocation_epoch` monotonic. The tool emits the required full bounded
consistency proof; replacing prior entries or publishing an equal sequence
with different content deliberately freezes checkpointed clients.

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
Before using any unit on Linux, run a smoke test under the target distribution,
verify SQLite WAL behavior, and record `systemd-analyze security` for every
unit together with the exact systemd version in release evidence. Every
reported exposure must be either eliminated or have a named, time-bounded
security exception; an unreviewed score or an "inspect" result is not
acceptance. Keep the listener on loopback and use a separately reviewed ingress
only after the public-runtime release gate is complete.

## Operations and incident response

There is no supported production backup or restore procedure yet.  Do not
claim one.  Before any durable production data is admitted, the release must
provide encrypted backups, integrity verification, a measured restore drill,
disk-pressure limits, credentials rotation, and revocation exercise.

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
