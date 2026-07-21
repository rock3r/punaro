# Punaro — the chicken coop relay

Punaro is a central, self-hosted collaboration service for conversations,
trusted attachment exchange, and shared memory among coding agents on several
computers and a human operator through Telegram. It does **not** expose or
share a machine's local `agent_mailbox` state. Each computer retains its local
mailbox; a native local client translates between that mailbox and Punaro.

The accepted production direction is a versioned OCI application image with
Docker Compose as the reference single-node deployment. The service is written
in Go. Go matches the existing `agent-mailbox` toolchain, produces small
auditable binaries, and supports native clients on the existing platforms.

## Architectural authority

[`docs/big-brain-plan.md`](docs/big-brain-plan.md) is the accepted direction
for the platform, threat model, migration, Big Brain, trusted attachments, and
operations. [`docs/platform-contracts.md`](docs/platform-contracts.md) fixes
the Phase A compatibility contracts that implementation slices must preserve.

This document records both the accepted target and the current alpha. Where a
current SQLite, Ed25519, systemd, or attachment-v2/v3 description differs from
the accepted target, it describes preserved implementation evidence or a
migration source, not the future production direction. Compose Pi integration
remains in the accepted plan but is outside the currently authorized Punaro
delivery scope.

## Implementation status

The accepted target is not yet a released service. The current `punarod`
binary provides a loopback-only alpha text relay: explicit
machine enrollment, signed requests, durable append/lease/ack, attached-endpoint
advertising, and payload-free WebSocket wake hints. A local adapter bridges
this to `agent-mailbox`. The separately deployable `punaro-telegram` bridge
adds explicit Telegram topic routing and a restricted Bot API client.
Authenticated attachments use the separately gated trusted-relay surface and
native client. V2/v3 production settings are rejected, their routes are
unmounted, and their binaries are absent from production packaging. Their
code, tests, RFCs, and vectors remain historical experimental evidence. The current
executable release conditions are in
[`docs/security-release-gates.md`](docs/security-release-gates.md).

## Goals

- Durable, ordered delivery to an enrolled machine, even when it sleeps.
- Best-effort low-latency wake-ups while it is online.
- Explicit, revocable identity and authorization for machines, agents, and
  conversations.
- Telegram topics as first-class user-facing conversations.
- Local agent sessions are visible only while their local adapter advertises
  them as attached.
- No message payload in WebSocket wake-up frames.
- Bounded trusted-relay attachment upload and safe native download.
- Shared revisioned memory with lexical and optional semantic retrieval.
- Operator-friendly backup, restore, upgrade, recovery, and revocation.
- Proportionate authorization and resource controls for a trusted self-hosted
  installation.

## Non-goals

- Hostile public multi-tenant SaaS operation or compliance-grade isolation.
- End-to-end confidentiality from the Punaro operator, host root, database
  administrator, or trusted LAN.
- Application-managed encryption at rest, zero-knowledge storage, or a secrets
  manager.
- Multi-node high availability, federation, or remote filesystem access.
- Treating model-visible content as routing, authorization, URL-fetch, secret
  resolution, or execution authority.

## Accepted deployment direction

```text
native client ---- authenticated HTTPS ----+
Telegram gateway ---------------------------+--> punarod
remote MCP gateway -- scoped OAuth ---------+      |-- PostgreSQL authority
                                                    |-- private blob volume
                                                    `-- optional brain workers
```

The reference deployment runs `punarod` and PostgreSQL by default. Optional
Compose profiles run the brain worker, Telegram gateway, remote MCP gateway,
Cloudflare ingress, and scheduled backup command. One versioned application
image supplies role subcommands. Containers run non-root with a read-only root,
dropped capabilities, `no-new-privileges`, bounded temporary storage, and no
Docker socket. PostgreSQL and blob storage are never host-published.

PostgreSQL is the only authoritative server database. SQLite remains a native
client recovery store and a server migration/parity source until cutover. The
current SQLite/systemd deployment remains an alpha compatibility path while
the staged migration is implemented; it is not the target production shape.
Internet ingress always uses TLS. An explicitly enabled trusted-LAN HTTP mode
may accept only validated private or link-local bind and source addresses.

## Identities and authorization

The accepted target uses host-local first ownership, short-lived single-use
enrollment codes, and one revocable high-entropy device credential per
installation. PostgreSQL stores only an indexed SHA-256 digest. Capabilities
are explicit across project, conversation, memory, and attachment scopes, and
the server applies authorized-scope predicates before any data-dependent
ranking or lookup. The current Ed25519 machine enrollment below remains a
staged migration source and is disabled only after intended clients exchange
credentials or are explicitly retired.

Punaro separates three principals:

| Principal | Example | Purpose |
| --- | --- | --- |
| Machine | `workstation-a` | A single enrolled adapter installation. |
| Endpoint | `agent/build-review` | A locally attached agent session advertised by one machine. |
| Conversation | `conv_01…` | The durable room/thread which has members and messages. |

An endpoint belongs to exactly one currently connected machine lease. A machine
can only advertise endpoints in its configured namespace (for example,
`agent/`) and only after local attachment is confirmed. A machine may instead
be enrolled for a named exact legacy endpoint; exact enrollment is equality
only, never an implicit client-wide namespace.

Each conversation has an explicit membership table with `send`, `receive`,
and `admin` capabilities. The Telegram gateway is a distinct principal; only
the configured Telegram user ID may control it. Neither a friendly endpoint
name nor a client-provided `from` field is proof of identity.

Provision each machine with a distinct Cloudflare Access service token and a
distinct Punaro machine credential. Service-token revocation stops ingress at
Cloudflare; revoking the machine credential stops it at Punaro. Store both in
the OS keychain or a root-readable service secret file, never in an agent
prompt, repository, or mailbox body.

Some Cloudflare Access deployments establish a service-token session through
an initial redirect. Before a signed adapter operation, the client may perform
a payload-free session preflight that carries only the two Access headers. It
may follow at most one HTTPS hop to a `*.cloudflareaccess.com` host and then
only back to the exact relay origin; it requires an origin-scoped
`CF_Authorization` cookie before proceeding. Signed request bodies, machine
signatures, nonces, and idempotency keys are never replayed through this flow.
All signed relay operations still reject redirects.

`punarod` validates Cloudflare Access JWTs itself (audience, issuer, expiry,
not-before, and signature via cached JWKS) in addition to accepting traffic
only through the tunnel. Both the issuer and JWKS endpoint must be
unambiguous HTTPS URLs (no credentials, query, or fragment), and the bounded
JWKS fetcher rejects redirects so configuration validation cannot be bypassed
by a later hop. A systemd deployment instead consumes a fresh, root-managed
local JWKS snapshot; this keeps the daemon's egress deny-list intact while a
separate, constrained refresh unit is the only component permitted to fetch
the configured HTTPS URL. The daemon warms and revalidates that source for
startup and `/readyz`, so it cannot advertise readiness with a missing, stale,
or unparsable Access boundary. It requires a valid machine credential for every
adapter request. Use an enrolled Ed25519 device key with request signatures
(method, path, body hash, timestamp, and nonce), or mTLS client certificates;
the exact choice is an implementation decision, not an optional security
layer.
This avoids treating a network location or Cloudflare header as application
authorization.

## Delivery model

Conversation creation and messages use separate idempotency records, each
scoped to the signed machine and bound to the normalized request. Retrying a
create returns the original conversation; changing the request under the same
key is a conflict. Messages are immutable rows. A relay-assigned UUID is the
message identity; the sender supplies a separate idempotency key scoped to its
machine. Each conversation has a monotonically increasing `sequence` assigned
transactionally at acceptance. The guarantee is **at-least-once delivery**: a crash after a
local mailbox injection but before the relay receives the acknowledgement can
produce a redelivery.

An adapter does not receive a message merely because it has opened a WebSocket.
It fetches durable deliveries, injects them into its local `agent_mailbox`, and
acknowledges each only after local acceptance succeeds.

```text
sender adapter  POST /v1/conversations/{id}/messages (Idempotency-Key)
punarod         transaction: authorize, append message, create deliveries
punarod         best-effort WebSocket hint: {type:"wake", topic_id, sequence}
recipient       POST /v1/deliveries/lease {endpoint, consumer_id, conversation_id?, limit?}
recipient       inject into local agent_mailbox
recipient       POST /v1/deliveries/{id}/ack
```

The lease response is the source of truth. It contains bounded durable
deliveries plus a map of conversation IDs to the recipient's highest contiguous
acknowledged sequence. Every recipient has an independent
delivery stream; a delivery has a short server-enforced lease, lease generation,
and lease token. A lease that expires without an acknowledgement becomes
available again. The recipient must tolerate duplicate delivery by durably
recording the Punaro message UUID before local injection, or by using it as the
local mailbox idempotency key.

`ack` is idempotent. It is conditional on the current recipient, lease token,
and lease generation. Acks from the wrong machine, stale lease holders, expired
credentials, or a machine no longer owning the endpoint are rejected. The relay
advances its per-recipient cursor only across contiguous acknowledged sequences;
it never skips a gap. Only one consumer holds an endpoint's renewable fencing
lease at a time, preventing a stale adapter process from injecting alongside a
replacement. `consumer_id` is a fresh opaque identity generated once per
adapter process; repeated polls from that process renew its endpoint fence,
while another process must wait for expiry before it can increment the fence
and take over.

## WebSocket wake-up channel

`GET /v1/notifications` upgrades to WebSocket after normal Access and machine
authentication. The server derives subscribed topics from authorization; it
does not trust a client-provided topic list.

The only application payload is:

```json
{"type":"wake","topic_id":"conv_01...","sequence":42}
```

No message title, sender, size, or content appears in a hint. Hints are
coalesced per `(machine, topic)` and may be dropped at any time. A successful
hint causes a normal HTTPS fetch. Heartbeat pings detect dead connections, but
do not affect delivery correctness.

The adapter runs this state machine:

```text
connected WS: wake -> fetch and ack
disconnected: periodic authenticated poll -> fetch and ack
poll finds work: immediately make one WS reconnect attempt
WS failure: exponential backoff with full jitter; polling continues
```

The opportunistic reconnect is rate-limited (for example, once per 30 seconds),
single-flight per adapter, and allowed to bypass backoff only once while work
remains. This prevents a large backlog from creating a reconnect storm.
WebSocket reconnect never alters delivery cursors.

## Minimal HTTP surface

All remote requests use HTTPS and require Punaro machine authentication.
Cloudflare Access JWT validation is additionally enabled when all three Access
verifier configuration values are set. The Telegram process is an outbound Bot
API client and reaches the relay using its own enrolled machine credential.

| Method | Route | Purpose |
| --- | --- | --- |
| `PUT` | `/v1/machines/me/endpoints` | Atomically advertise active local attachments. |
| `POST` | `/v1/conversations` | Create a conversation with explicit members; idempotent per signed machine and key. |
| `GET` | `/v1/conversations` | List conversations the caller may discover. |
| `POST` | `/v1/conversations/{id}/messages` | Append an authorized message. |
| `POST` | `/v1/deliveries/lease` | Lease bounded durable deliveries for one endpoint. |
| `POST` | `/v1/deliveries/{id}/ack` | Acknowledge after local injection. |
| `GET` | `/v1/notifications` | Best-effort WebSocket wake-up stream. |

Use opaque UUID/ULID identifiers. Endpoint names are labels, not URL
authorization handles. Bound every list/fetch page and message size. All
mutations require `Idempotency-Key`; retain idempotency records long enough to
cover client retry windows.

## Telegram integration

The Telegram gateway converts one explicitly configured topic into one Punaro
conversation. It verifies the configured allowed Telegram user ID on every
update. It persists `update_id` only after the relay append succeeds; retrying
an unrecorded update uses the same relay idempotency key, so crashes or
transient relay failures do not silently lose user input.

For outbound messages, it leases a durable gateway delivery and posts it using
the exact stored `message_thread_id`. One durable unique route prevents a
conversation from fanning out to multiple topics. There is no topic picker,
callback data, or main-chat fallback. The Bot API does not expose a send
idempotency key, so a crash after an accepted Telegram send and before relay
acknowledgement is deliberately at-least-once. Agent text is rendered as
escaped rich HTML with entity detection disabled and content protection set.

An optional major-update adapter action resolves the registered
conversation/topic and submits a concise milestone or blocker message. It must
fail closed if there is no explicit thread route.

## Local adapter boundary

The Go adapter runs on each agent machine. It owns the local `agent-mailbox`
CLI/MCP integration and no remote actor may invoke the CLI directly. It:

1. Watches or periodically reads the locally configured attachment group.
2. Advertises only currently attached sessions to Punaro with a renewable lease.
3. Converts inbound Punaro messages to local mailbox messages, preserving
   `punaro_message_id`, conversation ID, and Telegram thread metadata.
4. Watches local replies and major-update events, then submits them to Punaro.
5. Keeps a local encrypted-or-permission-restricted SQLite journal of received
   message UUIDs and pending acknowledgements.

## Superseded attachment-transfer v2 foundation

Attachment v2 is preserved experimental evidence, not the accepted production
direction. It uses a separate encrypted data plane; it never puts file
bytes, file keys, or recipient redemption material in a normal Punaro message
or WebSocket hint. The preserved package includes strict HTTP handlers, but
`punarod` neither imports nor mounts them and rejects their former
configuration. Its historical RFC and release checklist
remain useful validation evidence but cannot authorize production exposure
under the new direction.

`internal/attachment/v2` preserves a strict canonical
CBOR record core: verified signed manifests, manifest commitments,
recipient-bound HPKE envelopes, a fresh root-signed device/membership snapshot
resolver with a durable anti-rollback checkpoint, and a source-artifact helper
that reserves file-key/content-salt/nonce uniqueness before encryption. The
experimental directory snapshot was group-readable by its relay harness but
lived below a root-owned configuration hierarchy; its prototype installers
and publishers did not write snapshot paths below service-owned state. It has
canonical permits whose issuer, sender/recipient membership, device
generations, directory head, epoch, and expiry are all checked against the
same fresh directory snapshot, plus a private SQLite serial and
operation-redemption ledger. The historical permit issuer starts with a separately
holder-signed, retry-stable request; the issuer verifies that holder and its
own public key against the same fresh directory, derives the head/epoch rather
than accepting caller values, clamps every requested limit, and atomically
persists the request-to-permit mapping. The ledger accepts only a fully verified exact
operation and runs its SQL state mutation in the same transaction as recording
the idempotent result. Its handler accepts only the versioned routes and exact
canonical permit/operation headers, resolves fresh directory authority for
every request, and derives all commitments from the request. A separately
gated `/v2/directory` handler was designed to serve only complete canonical snapshots to
an enrolled, replay-protected machine request; it reads and validates a fresh
private snapshot file for every request and is covered by the same optional
Access middleware as the text relay. A separately gated `POST /v2/permits`
uses the same fresh provider, but only after an enrolled machine's
replay-protected request is explicitly bound to the request holder's 16-byte
directory device ID; a directory device cannot be bound to multiple machine
credentials. Its issuer key comes only from a private, non-symlinked,
canonical-key file and its lifetime and quotas are explicit configuration,
with an explicit global live-permit ceiling. The ledger transactionally reaps
expired permits together with their issuance and redemption rows before
admitting a new permit, while an exact live request retry remains idempotent at
that ceiling.
The authority provider fetches a complete
signed snapshot for every attachment request and never falls back to a stale
accepted view; root pinning and the private checkpoint store remain the only
sources of directory trust. `punarod` no longer imports or mounts these
handlers, irrespective of the historical gates.
Where the experimental privileged publisher supplied that snapshot, the publication
directory is root-owned and non-writable by the relay (`root:service-group`,
mode `2750`), and the atomically replaced snapshot is group-readable but
non-writable (`root:service-group`, mode `0640`). The relay may only belong to
that narrowly reserved service group. The publisher creates each staging file
inside a root-only container directory, verifies it is a regular non-symlink,
then uses a same-filesystem rename; the relay cannot redirect the privileged
copy or replace a newer head. A kernel-released advisory lock serializes
publisher instances, so a crash cannot leave a stale lock that blocks
republication. Issuer private keys under that parent stay
owner-only (`0600`).
The v2 core also has a strict, non-secret
transfer lifecycle model with one fenced attempt and no transition out of a
terminal state, plus a private SQLite store that writes its permitted
transitions in the same transaction as durable permit redemption and refuses
obsolete table layouts rather than attempting a lossy migration. It is not
imported or mounted by `punarod`. Its strict route parser derives operation bindings only from the
fixed versioned HTTP schema and prevents a permit from crossing into another
transfer route; sender-only actions are offer/upload/begin, recipient-only
actions are accept/download/complete, and no current client route accepts a
relay-holder permit. Offers contain a one-time recipient acceptance nonce that is
consumed with the accepted transition, rather than treating a state change
alone as acceptance evidence. The v2 core
also has an immutable source-ready store which atomically persists a freshly
verified manifest, recipient envelope, and all ciphertext chunks before an
offer can reference it. Its withheld relay store independently refuses to
make an offer recipient-visible unless it already contains every exact-sized,
commitment-verified ciphertext chunk for that Manifest; a partial source is a
hard failure, not a pending offer. In
particular, it does **not** make
attachments usable, or satisfy the vector/fuzz/review release gates. Callers
in the preserved tests construct its verified-manifest input only after fresh
directory verification. This evidence is not a dormant production roadmap.

## Superseded attachment-transfer v3 controlled runtime

V3 is preserved experimental evidence, not the accepted production direction.
It is a distinct record, signature, and route namespace that solves the v2
source-staging bootstrap cycle. It does not reinterpret any v2 manifest,
permit, operation, or envelope. Its historical runtime required
all of these are present: a private shared source store, a fresh root-verified
directory adapter, an authorized issuer key, an independently authenticated
machine-to-directory-device binding for permit issuance, and the equivalent
binding for every attachment operation. Its package-level harness mounts
`/v3/permits` and the strict `/v3/attachments/...` routes together; the runtime owns one SQLite source
store, so issuance and redemption cannot accidentally use different ledgers.

All behavior described below belongs to the preserved package and CLI test
harnesses. It is not linked into `punarod`, shipped by production installers,
or available for operator activation.

The source-init exception is deliberate and narrow. A sender must first obtain
a holder-signed v3 source-init permit. The issuer journals the exact request
and permit; source init verifies that journal entry, verifies the fresh signed
Manifest body, records both the source and issued permit, and records the
operation result in one transaction. Later permits are registered against the
current lifecycle before they are returned. Exact issuance retries remain
available after lifecycle advance only after fresh issuer/revocation
validation; retained request identities are bounded per holder and expire only
after tombstone retention. This prevents bootstrap by an arbitrary valid
issuer signature, request-ID replacement after short permit expiry, and
retry failure after normal source cleanup.

The historical local sender command opens a sender-only journal and requires its pinned
source identity to match the pre-approved relationship before staging. It
creates encrypted artifacts only after a local private artifact store has
reserved file-key, salt, and nonce tuples; the file key is wrapped by the
machine Keychain, Windows DPAPI CurrentUser boundary, or a private systemd
credential and is never placed in that journal. The prototype Windows harness uses an
exclusive current-user ACL and an interactive per-user Scheduled Task; it does
not expose the wrapping key through an environment variable or task argument.
On Unix, attachment journals, keys, snapshots, and durable stores additionally
require owner-only permission bits. On Windows, those same paths must remain
regular, non-reparse files below the installer-managed ACL: Go's `FileMode`
cannot represent NTFS ACL ownership, so treating POSIX mode bits as an ACL
would reject secure Windows state or create a false security boundary.
Completed receipt files are flushed before their no-replace publication. Unix
also flushes the containing directory; Windows cannot apply that Unix directory
fsync contract, so it relies on the flushed file plus the atomic NTFS metadata
operation while preserving the installer-managed ACL and no-reparse checks.
It issues holder-signed v3 permits and submits permit/operation-bound
bytes through the same replay-protected machine transport as text. Every send
requires a caller-retained stage ID: retries reuse only the exact immutable
staged transfer, never newly generated source material. Once an expired stage
is reaped, its ID is retained as a bounded tombstone and is rejected forever;
the local caller must use a new ID rather than silently creating a second
transfer. Before the source is allowed to reach `offer`, the sender reserves
bounded durable capacity for the exact canonical offer in the adapter-owned
`OfferNoticeOutbox`; held rows are not visible to the relay sync loop. Only
after the successful `offer` result is durable does it activate that row for
delivery. An inactive row is never age-reaped: an offer may have been accepted
immediately before a sender crash, so only sender recovery within the signed
manifest and outcome-capability lifetime may activate it. Once those records
expire, the hold is a deliberate fail-closed quarantine rather than a
recoverable transfer; it remains bounded local capacity until an audited
operator incident procedure resolves it. A crash after relay acceptance but
before local deletion merely retries the stable
relay idempotency key. The notice is discovery data only: it is neither
a download URL nor an authorization grant; the recipient must fresh-verify its
manifest/envelope, use its local HPKE key, and obtain recipient-held permits
before it can accept or download. A bounded reaper runs in the daemon and is
stopped before its SQLite stores close.

The implementation does not expose a mailbox database, accept public links,
move file bytes through Telegram, or decrypt at the relay. Recipient-side
orchestration, recovery drills, vectors/fuzzing, and release evidence remain
required; the runtime is a controlled validation surface, not a production
attachment release.

The local v3 controller binds each text-relay conversation to one exact,
operator-approved directory conversation, sender generation, recipient
generation, and membership commitment. It persists the canonical inbound offer
under its relay message ID, deduplicates only byte-identical retries, and
requires a separate explicit local receipt approval. Before any future
recipient permit, acceptance, download, or decrypt action, the controller
must re-fetch and root-verify that exact directory relationship; a notice
cannot discover a new member or override the binding. The recipient validates
that the requested output destination is a new regular path before acceptance,
then uses an atomic no-replace finalization after decryption. Merely receiving
a typed mailbox offer therefore never starts a data-plane action or writes an
output.

The legacy `internal/attachment` foundation tests local encrypted-frame,
replay, fencing, and bounded-store helpers.  Those helpers are intentionally
**non-normative**: they do not specify cipher parameters, nonce/AAD
construction, quotas, or a transport limit for a released protocol.  The
complete implementation-to-RFC divergence is maintained in
[`docs/attachment-foundation-gap-matrix.md`](docs/attachment-foundation-gap-matrix.md).

Direct/TURN primitives are isolated adapter test helpers and are intentionally
not wired into `punarod`.  The encrypted relay-blob transfer has no reachable
daemon route.  Only the RFC may define the released record formats, algorithms,
and bounds.

If the adapter stops, its endpoint lease expires and the central target picker
no longer lists it. Existing conversations remain, but new sends are queued
only where the policy permits offline delivery; the Telegram UI clearly labels
that state.

## Safety controls and operations

The accepted target operating model is specified by the Big Brain plan and
platform contracts. Current executable safeguards are limited
to loopback binding, fail-closed attachments, a restricted container context,
and static/container configuration checks.  The operator guide explicitly
lists what is not yet a supported production operation.

- Internet ingress is TLS-only. Trusted-LAN HTTP requires explicit enablement
  plus validated private or link-local bind and source addresses; public
  addresses never qualify.
  Access issuer/JWKS metadata is HTTPS-only and its JWKS client must not follow
  redirects. The daemon must either prove safe direct JWKS egress or, for the
  systemd profile, consume a fresh root-managed local snapshot refreshed by a
  separately constrained unit before reporting ready.
- For the optional Cloudflare profile, firewall the host so only `cloudflared`
  reaches the relay listener. Strip incoming `CF-*` and forwarding headers
  before any reverse-proxy boundary; never treat a client-supplied identity
  header as authenticated.
- Rate limits per machine, conversation, and Telegram user; bounded queues and
  explicit backpressure/expiry policies.
- Maximum message body and metadata sizes; reject unknown JSON fields where
  practical and validate schemas strictly.
- Structured audit log for auth decisions, membership changes, sends, leases,
  acknowledgements, and Telegram actions. Do not log bodies or credentials.
- Encrypt database backups; rotate service tokens and machine credentials;
  support immediate machine disable and conversation membership revocation.
- Separate Cloudflare service tokens by machine, with finite expirations and
  narrow Access policies. Do not use an account-wide "any service token" rule.
- Health endpoints are local-only or require admin credentials and disclose no
  agent/session inventory.
- Restore testing, database integrity checks, metrics for queue age, lease
  expiry, reconnect rate, and failed authorization attempts.
- Treat every Telegram/agent body as opaque untrusted content. It cannot create
  routes, change membership, trigger a URL fetch, execute a command, or modify
  adapter registration. The adapter labels remote content clearly at the local
  mailbox boundary.
- Use SQLite-aware online backups or checkpoint/quiesce before snapshots; do
  not assume a live Proxmox snapshot is a consistent database backup. Monitor
  NTP/clock skew because leases and credentials are time-bound. Attachment
  directory heads permit at most 60 seconds of future skew and remain valid
  for at most five minutes; permits and operation records remain bounded to
  30 seconds and never receive an expiry extension for skew.

## Implementation plan

Implementation follows the independently mergeable migration phases in
[`docs/big-brain-plan.md`](docs/big-brain-plan.md): compatibility contracts,
PostgreSQL foundation, mail migration, trusted attachments, lexical Big Brain,
semantic retrieval, and independently optional dreaming and remote MCP. Compose
Pi integration remains a future plan phase but is excluded from the currently
authorized Punaro delivery scope. Every slice retains a safe rollback boundary,
passes the full quality gate, and ships through a separately reviewed PR.

The first PostgreSQL foundation slice is additive and dark. It embeds an
advisory-locked, checksum-validated schema migrator behind the explicit
`punaro-migrate` command, records installation/timeline identity and a monotonic
change sequence, and makes opt-in `punarod` startup/readiness reject pristine,
dirty, old, newer, or incompatible schemas without performing DDL. The normal
application role is distinct from the schema owner. SQLite remains the active
and default relay authority until the later fenced mail cutover.

The first mail-cutover slice was dark and stopped before authority transfer.
SQLite can be inspected read-only into a deterministic logical manifest; its
prepare barrier expires endpoint ownership, clears consumers and delivery
leases, advances their generations, and installs a durable write fence that
also stops already-open older daemons. PostgreSQL schema v8 can durably record
one owner-authorized import epoch plus bounded staging/checkpoint state and
fences application-role mail writes while that epoch is importing or verified.
Schema v9 expands only the staging payload bound to cover worst-case JSON
escaping for every valid 32 KiB message body while retaining the same ACLs.
The one-shot executor now consumes that substrate. It exports canonical rows in
bounded order-preserving pages, durably checkpoints exact idempotent staging,
streams every table back through the source-manifest hash, and materializes all
canonical PostgreSQL tables in one verified transaction. Before source
retirement an explicit abort deletes any materialized destination rows, reopens
SQLite first, and marks the destination epoch aborted. If PostgreSQL rejected
before recording the epoch, abort first records an exact terminal tombstone so
a delayed begin cannot resurrect the import fence, then reopens SQLite.
Retirement is permanent.
Only after it succeeds may one owner transaction prove that no intended legacy
machine remains pending, close the legacy gate, and mark PostgreSQL active.
The generated environment, Compose input, and installation marker are then
published locally with `installation.json` last. A crash can therefore resume
at prepare, staging, verification, retirement, activation, or publication
without dual writes or rollback across the seal.

Schema v10 adds the first trusted-relay attachment slice as a dark server-side
publication authority. An upload is an operation-bound, authorized `RESERVED`
record with global, project, and principal quota held in one lock order. A
fresh fenced claim permits one bounded stream into an owner-only staging file;
exact bytes are hashed, fsynced, published to an opaque no-replace name, and
directory-synced before a short transaction reauthorizes the principal and
commits an unshared `READY` projection. Equal digests remain separate artifacts.
Reconciliation verifies every READY blob and withdraws missing or changed bytes
from the backup-visible READY projection as `CORRUPT`. Expired or restored-
timeline reservations first enter a durable `REAPING` publication fence; only
then are all claim-specific stages and hidden finals removed, and only after
that deletion commits is held quota released. The application role has only
narrow function execute authority, active attachment records fence project
merge, and backup continues
to select the READY manifest in the exported database snapshot. No upload,
download, recipient, sharing, or deletion HTTP route is mounted by this slice;
those remain later independently reviewed milestones.

Schema v11 adds the next dark slice without mounting a file route. Bearer
transition sessions carry the authenticated stable principal and credential
generation into PostgreSQL relay transactions. Endpoint advertisement records
that principal atomically with the mail lease; legacy-signed advertisement
clears any prior principal binding and remains mail-only. A project-bound
conversation requires current `conversation.send` authority. Its message
append may contain at most 16 ordered opaque artifact IDs and, in the same
transaction as the immutable message and deliveries, locks and verifies the
sender's READY artifacts and snapshots the delivered endpoints' stable
recipient principals. Initial artifacts may be referenced by one message only.
Endpoint reassignment cannot transfer a historical grant, while credential
rotation preserves it. An immutable conversation-project binding fences project
merge so a conversation cannot be stranded on a retired source project.

Download authorization is the conjunction of a current generation-fenced
device credential, current project-scoped `attachment.download`, the immutable
recipient snapshot, READY metadata, and the exact manifest. The service holds
the artifact lock, opens only the server-derived no-follow `0600` regular file,
verifies its full size and digest before emitting any byte, rewinds the same
descriptor, and streams exactly the recorded size under cancellation and a
16-stream concurrency ceiling plus a service-owned ten-minute maximum lifetime.
In-process and cross-process artifact-lock waits honor cancellation. Guessed
IDs, revoked authority, absent grants, and
hidden or corrupt artifacts do not expose which condition failed. There are no
ranges, public URLs, redirects, URL fetches, or display-name paths. Reservation,
upload, download, and delete HTTP routes remain unmounted until the native
client and final release surface receive their separate reviews.

Schema v12 adds tombstone-first deletion without mounting a route. An
operation-bound idempotency record, current device generation, current
`attachment.delete` capability, and the canonical project lock authorize the
visibility transition. The same artifact lock serializes deletion with active
downloads. Tombstoning withdraws recipient grants and the READY backup
projection but retains the exact private path, size, digest, and charged quota
through a database-time 24-hour restore window. Post-cutoff physical GC is
permitted only outside an active backup fence, uses a generation/token/lease
claim, durably removes the final and private stages, then conditionally marks
the tombstone deleted and releases quota exactly once. Corrupt artifacts use
the same delayed path. A bounded deterministic filesystem scan removes only
old UUID namespaces whose database absence and backup permission are rechecked
under the artifact lock; any state change restarts its cursor. Restoring an
older snapshot may therefore resurrect data that was deleted later.

The M-12 native-client slice exposes those lifecycle routines through schema
v13 only behind the separate `PUNARO_TRUSTED_ATTACHMENTS_ENABLED` release switch, PostgreSQL device
authentication, the selected ingress transport policy, and an absolute private
blob root. The strict `/v1/trusted-attachments` surface accepts bounded
reservation metadata, one exact streaming upload, authorized streaming
download, and operation-bound deletion; redirects, URLs, ranges, caller paths,
and unauthenticated access are absent. Startup completes bounded database and
restore-skew reconciliation before mounting the surface, and a fail-closed
periodic sweep keeps abandoned, corrupt, deleted, and orphan state moving
through the existing fenced lifecycle.
Schema v13 binds the exact device credential lookup and generation inside the
same transaction that authorizes and publishes READY, so revocation and
completion have one database serialization point.

The native client hashes a regular source before reservation, retries the same
idempotency identity, and skips re-upload when the authoritative reservation is
already READY. Downloads receive immutable size, digest, media type, and an
encoded display name in authenticated response headers. An already-open
`os.Root` contains a private same-filesystem stage across root renames, verifies
the exact stream, and creates the visible name with atomic no-replace linking.
Portable unsafe or reserved display names fall back to the opaque artifact ID.
The v2/v3 experimental code, RFCs, vectors, and tests remain evidence only.
Their production switches are rejected, their routes are unmounted, and their
binaries are absent from the production image.

The second dark foundation slice adds opaque principals/projects, explicit
selected-project and dynamic all-project capability grants, globally unique
operation-bound idempotency keys, closed content-free audit events, and a
capacity-bounded transactional work queue. Project creation proves that
authorization, immutable retry outcome, ordinary creator grants, audit, queued
work, and one change-sequence advance commit atomically. Worker publication is
accepted only for the exact unexpired lease token and generation. None of these
primitives is exposed through the alpha HTTP relay yet, and they do not change
SQLite routing or establish a production authority barrier.

The third foundation slice adds the host-local-only ownership and device
credential path. The schema owner creates exactly one installation owner and
prints the exact `trusted-agent` grant expansion before issuing a short-lived,
single-use enrollment. Redemption is bound to an opaque client value; the dark
store generates a fresh 256-bit secret
internally, stores only its indexed SHA-256 digest, and composes the device
principal, credential, grants, audit, and change sequence atomically. At the
M-3 boundary no public bootstrap, issuance, redemption, or device-auth route was
mounted; M-5 adds only bounded redemption and device session authentication
behind its explicit ingress transport policy. Credential caches
and long-lived sessions revalidate within two seconds. The existing Ed25519
relay remains active while its intended machines are durably inventoried as
pending, migrated, or retired; the global legacy gate cannot close while any
machine is pending. PostgreSQL remains dark for mail and SQLite routing is
unchanged.

The dormant M-9 credential-transition bridge does not duplicate relay
authority in PostgreSQL. A successful proof-bound exchange already records the
replacement credential lookup against the exact registered legacy public key.
When the explicit transition switch is enabled, a current, unrevoked device
credential follows that relationship back to the public key and selects the
one matching static machine enrollment. The returned machine ID therefore has
exactly the existing endpoint prefixes, exact endpoints, and attachment-device
binding. Duplicate configured public keys fail startup. Ordinary device
credentials, stale generations, retired mappings, and unavailable database
state fail authentication without revealing which check failed. In the same
mode every Ed25519 relay request consults the durable legacy gate after
signature verification and before consuming its nonce; closing the gate blocks
new legacy requests while migrated credentials remain usable. The switch is
off by default and requires device auth plus the PostgreSQL relay, so this
slice does not activate PostgreSQL mail authority or change the SQLite default.
Long-lived notification sockets retain only a non-secret generation/gate fence,
not the bearer credential. A check starts every second with a one-second
deadline in a dedicated loop; wake writes cannot delay it, and fence failure
cancels any blocked write. This bounds authority after the last successful check to two seconds. Gate
closure, key retirement, credential rotation/revocation, principal disablement,
mapping removal, timeout, or database failure closes the socket.

The supported cutover action is `punaro mail cutover`. Its dry-run reads the
service-owned `relay.db` from the installation data directory and prints the
source fingerprint, exact counts, and PostgreSQL target identity without a
mutation. Execution accepts no arbitrary source path and requires a caller
chosen epoch UUID, the dry-run fingerprint, `--yes`, and a complete validated
public static relay enrollment on first execution. That enrollment is published
marker-last before SQLite prepare, remains the canonical endpoint authority
after cutover, and cannot be changed by a recovery retry. SQLite prepare fences
old daemons and clears every lease holder while advancing fences. Staging is
bounded to 128 rows per page and resumes from durable PostgreSQL checkpoints.
Verification rejects any missing, extra, reordered, malformed, or changed row.
`--abort` is available only before SQLite retirement; after activation the old
file is forensic evidence and recovery is PostgreSQL backup or forward repair.

The fourth dark foundation slice gives projects durable, credential-free
identity claims. Conservative Git normalization strips credentials and only
collapses well-known equivalent syntax; ambiguous locators fail closed.
Unclaimed identities require both project write and explicit attach authority.
A claimed identity can only be reconciled through an expiring, generation-bound
preview followed by one bounded transaction that reauthorizes the same actor,
locks both active project rows in deterministic order, and identifies every
principal with any capability-level content-access expansion. Memberships are
not unioned. Unredeemed enrollments targeting the retired project are included,
with all of their collateral grants, in the preview impact and receive an
explicit irreversible invalidation marker rather than silent retargeting.
Nonterminal jobs are bounded merge records: queued jobs are rehomed, running
leases are fenced and requeued, and the known typed payload is canonicalized in
the same transaction. The retired project IDs and any older aliases are
flattened directly to the active canonical project, but an alias supplies no
authority by itself. Per-project
identity, grant, alias-rewrite, preview, and pruning limits are hard bounds.
Application-role mutation privileges are column-exact, and readiness verifies
the new catalog objects, indexes, constraints, and grants. These primitives
remain internal: no public identity or merge route is mounted, PostgreSQL mail
authority remains dark, and SQLite routing is unchanged.

The fifth foundation slice adds the host-local `punaro` operator wrapper and
the first device-credential ingress. `init` validates private data and backup
directories, distinct owner/application DSN files, and a digest-pinned release
image. Canonical-path checks keep both credentials and operator state outside
the daemon-writable data tree, including across symlinked ancestors. It durably
stages a private daemon environment and immutable-image-only Compose file,
creates the first owner, then publishes one `installation.json` marker by
rename. An uncertain owner outcome is recoverable with `punaro init --resume`;
the staging directory is synchronized before the database mutation. `up`
starts only an already-compatible owned database, refuses pristine/reset,
upgrade-required, newer, dirty, and incompatible states before service start,
waits boundedly for readiness, then runs doctor. Initial pristine migration is
part of `init`; raw daemon and Compose startup remain non-migrating.

Internet and existing-proxy profiles require a canonical HTTPS public URL and
a loopback origin. Trusted-LAN plaintext is an explicit exception requiring a
concrete private or link-local bind, a containing private/link-local CIDR, and
an observed peer in that CIDR. Wildcard/public binds and peers fail closed;
forwarded headers never establish TLS or source trust. The public surface added
here is limited to strict, bounded enrollment redemption and a
bearer-authenticated session check. PostgreSQL remains dark for mail and
project identity APIs. A non-loopback device listener cannot be combined with
legacy relay, directory, permit, or attachment routes; those remain loopback-only.
Health and readiness use a distinct concrete loopback-only listener and are
never mounted on the device/legacy listener.

The sixth foundation slice adds consistent backup, verification, and
clean-stack restore without changing mail authority. One committed GC fence is
held while an application-role repeatable-read transaction exports the exact
snapshot used by the schema-owner `pg_dump` and READY-blob manifest query. The
fence renews until immutable blobs are copied and verified; only a synchronized,
strictly verified hidden stage is published. Backups include Punaro-generated
configuration and database credentials while only declaring host TLS,
proxy/tunnel, Telegram, and OAuth dependencies. Restore proves both target roles
reach the same pristine database, restores in one transaction, verifies blobs,
preserves installation identity, rotates the timeline, durably journals each
phase, and publishes only new data/operator paths. Exact-command retries resume
without repeating completed mutation. Abandoned-timeline and future cursors fail closed. This is
not the later update fence and does not let ordinary startup migrate.

The seventh foundation slice adds the single-node supported update transaction.
Every PostgreSQL business mutation takes the shared side of one transactional
maintenance gate; the owner-side update fence drains prior writers, rejects
later writes before acknowledgement, and remains durable through crashes. The
host wrapper verifies protected release metadata, the exact pulled image digest,
the generated Compose artifact, PostgreSQL major, installation identity, disk
capacity, and current health before fencing. It then stops the generated writer,
creates an update-bound M-6 backup, and runs the exact target image as a hardened
one-shot owner migrator. The target starts under the still-active fence and must
pass readiness and a non-mutating doctor before marker-last configuration
publication and database commit reopen writes.

Update phases and the previous image lock are durable. Exact retries resume;
pre-migration abort restarts and doctors the previous image before releasing the
fence. After migration starts, an explicit compatible-image recovery is allowed
only when the previous image actually starts and passes its recovery doctor against
the migrated schema. Otherwise the exact bound backup plus its independently
durable host receipt must be restored into a pristine stopped/new stack; restore rotates the timeline,
reconstructs the same fenced update transaction, and requires the restored source
image to pass readiness and doctor before recovery commits. Raw daemon/Compose
startup and the ordinary migrator cannot cross an existing-schema migration.
This generated-stack contract covers the single configured `punarod` writer and
externally provisioned PostgreSQL; the production PostgreSQL/profile bundle is
still M-23.

## Required adversarial acceptance tests

The implementation is not internet-exposure-ready until these cases pass:

1. Duplicate every send and WebSocket hint; drop the acknowledgement response;
   crash at send, fetch, local-forward, and ack boundaries. Verify no loss and
   expected deduplication.
2. Attempt stale-lease acknowledgement, two adapters for one endpoint, and
   detach/reattach during delivery. Verify fencing and no cursor gap.
3. Attempt direct origin access with forged Cloudflare/forwarded headers,
   expired/revoked service or device credentials, and guessed/revoked topic
   IDs. Verify rejection without existence disclosure.
4. Replay a signed request, claim another machine's endpoint, or fetch/subscribe
   to an unauthorized topic. Verify server-side authorization on every path.
5. Replay Telegram updates/callbacks and send text that attempts to change
   registration, invoke URLs, or execute commands. Verify it remains inert
   content.
6. Induce disk pressure, lease expiry, WebSocket reconnect storms, backup
   restore, and database recovery. Verify bounded resource use and a tested
   recovery path.

## Explicit decisions

- Go, not Rust, for v1.
- Versioned OCI images and Docker Compose are the reference production path;
  a dedicated Linux LXC remains a valid OCI host.
- PostgreSQL is the sole authoritative server database after cutover; SQLite is
  retained for client recovery, migration evidence, and parity tests only.
- HTTP fetch/ack is authoritative; WebSocket carries topic ID and sequence only.
- Remote MCP is an optional OAuth-scoped adapter over the Punaro service, never
  a remotely exposed `agent_mailbox` database.
- Default authorization is deny; explicit conversation membership grants reach.
