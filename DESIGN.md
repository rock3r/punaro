# Punaro — the chicken coop relay

Punaro is a small, central, self-hosted relay for conversations among coding
agents on several computers and a human operator through Telegram. It does **not** expose
or share a machine's local `agent_mailbox` state. Each computer retains its
local mailbox; a local adapter translates between that mailbox and Punaro.

The first production target is a dedicated unprivileged Linux LXC. The relay is
written in Go. Go matches the existing `agent-mailbox` toolchain, produces a
single static-ish service binary, and keeps the runtime small and auditable.

## Implementation status

This document describes the target architecture, not a released service. The
current `punarod` binary provides a loopback-only alpha text relay: explicit
machine enrollment, signed requests, durable append/lease/ack, attached-endpoint
advertising, and payload-free WebSocket wake hints. A local adapter bridges
this to `agent-mailbox`. The separately deployable `punaro-telegram` bridge
adds explicit Telegram topic routing and a restricted Bot API client. V3
attachments are a separately provisioned, controlled runtime: the offline
root key, relay issuer key, and per-client device keys are distinct, and the
relay starts v3 only with a current signed directory plus explicit
machine-to-device bindings. Legacy v2 switches still fail closed. The
authoritative release conditions are in
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

## Non-goals for v1

- Federating arbitrary third-party relays.
- A generic remote MCP endpoint or remote filesystem access.
- End-to-end encryption against the relay operator. The NUC relay is trusted
  to route message bodies and encrypts data at rest.
- Multi-node high availability. Backups and restore are preferred first.

## Deployment

```text
Telegram Bot API                         workstation A
      |                                      agent-mailbox
      v                                           ^
Telegram gateway <-> Punaro relay <----> local adapter
                       ^    ^                  (outbound HTTPS + WS)
                       |    |
                 SQLite WAL  Cloudflare Tunnel + Access
                       |              ^
                     backups           |
                                   workstation B
```

The intended production deployment will run the following as separate,
unprivileged systemd services in a dedicated
Debian LXC:

1. `punarod`: the Go HTTP API, WebSocket notifier, queue, and registry.
2. `punaro-telegram`: the Telegram long-polling gateway. It is the only
   component that reads the Telegram bot token.
3. `cloudflared`: a named outbound tunnel which exposes only `punarod`'s TLS
   HTTP listener through an Access-protected hostname.

Bind `punarod` to loopback or the private LXC interface; do not publish its
port from Proxmox. The Cloudflare tunnel is the sole internet ingress. A
separate private LAN listener is optional for emergency administration, but is
not part of v1.

Use SQLite in WAL mode on a persistent LXC volume for v1. Back up the database
and the configuration/secrets manifests with encryption. Do not put the SQLite
database on NFS. Migrate to PostgreSQL only for a multi-relay deployment.

## Identities and authorization

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
recipient       GET /v1/deliveries?topic_id=...&after=...
recipient       inject into local agent_mailbox
recipient       POST /v1/deliveries/{id}/ack
```

The fetch response is the source of truth. Every recipient has an independent
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
replacement.

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

## Attachment-transfer v2 foundation

Attachment transfer uses a separate encrypted data plane; it never puts file
bytes, file keys, or recipient redemption material in a normal Punaro message
or WebSocket hint. The current code includes an unmounted strict HTTP handler;
`punarod` deliberately refuses to mount it even when attachment configuration
is present. It will remain fail-closed until all gates in the
[attachment RFC](docs/attachments-v2-rfc.md) and
[security release checklist](docs/security-release-gates.md) are complete.

`internal/attachment/v2` currently provides a strict canonical
CBOR record core: verified signed manifests, manifest commitments,
recipient-bound HPKE envelopes, a fresh root-signed device/membership snapshot
resolver with a durable anti-rollback checkpoint, and a source-artifact helper
that reserves file-key/content-salt/nonce uniqueness before encryption. The
published directory snapshot is group-readable by the relay but lives below a
root-owned configuration hierarchy; privileged installers and publishers never
create, repair, or write snapshot paths below service-owned state. It has
canonical permits whose issuer, sender/recipient membership, device
generations, directory head, epoch, and expiry are all checked against the
same fresh directory snapshot, plus a private SQLite serial and
operation-redemption ledger. Permit issuance now starts with a separately
holder-signed, retry-stable request; the issuer verifies that holder and its
own public key against the same fresh directory, derives the head/epoch rather
than accepting caller values, clamps every requested limit, and atomically
persists the request-to-permit mapping. The ledger accepts only a fully verified exact
operation and runs its SQL state mutation in the same transaction as recording
the idempotent result. Its handler accepts only the versioned routes and exact
canonical permit/operation headers, resolves fresh directory authority for
every request, and derives all commitments from the request. A separately
gated `/v2/directory` endpoint now serves only complete canonical snapshots to
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
sources of directory trust. Attachment operation routes remain unmounted
because runtime capacity quotas and reaper scheduling, adapter transport
integration, end-to-end transfer drills, and release evidence are incomplete.
Where a separately privileged publisher supplies that snapshot, the publication
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
mounted yet. Its strict route parser derives operation bindings only from the
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
must only construct its verified-manifest input after fresh directory
verification; the directory-distribution prerequisite now exists, but the
remaining attachment runtime does not.

## Attachment-transfer v3 controlled runtime

V3 is a distinct record, signature, and route namespace that solves the v2
source-staging bootstrap cycle. It does not reinterpret any v2 manifest,
permit, operation, or envelope. Its explicit runtime is constructed only when
all of these are present: a private shared source store, a fresh root-verified
directory adapter, an authorized issuer key, an independently authenticated
machine-to-directory-device binding for permit issuance, and the equivalent
binding for every attachment operation. It mounts `/v3/permits` and the strict
`/v3/attachments/...` routes together; the runtime owns one SQLite source
store, so issuance and redemption cannot accidentally use different ledgers.

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

The local sender command opens a sender-only journal and requires its pinned
source identity to match the pre-approved relationship before staging. It
creates encrypted artifacts only after a local private artifact store has
reserved file-key, salt, and nonce tuples; the file key is wrapped by the
machine Keychain, Windows DPAPI CurrentUser boundary, or a private systemd
credential and is never placed in that journal. Windows deployment uses an
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

This is a target operating model.  Current executable safeguards are limited
to loopback binding, fail-closed attachments, a restricted container context,
and static/container configuration checks.  The operator guide explicitly
lists what is not yet a supported production operation.

- TLS only; no HTTP listener exposed outside loopback/private LXC network.
  Access issuer/JWKS metadata is HTTPS-only and its JWKS client must not follow
  redirects. The daemon must either prove safe direct JWKS egress or, for the
  systemd profile, consume a fresh root-managed local snapshot refreshed by a
  separately constrained unit before reporting ready.
- Firewall the LXC so only `cloudflared` reaches the relay listener. Strip
  incoming `CF-*` and forwarding headers before any reverse-proxy boundary;
  never treat a client-supplied identity header as authenticated.
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

1. Build `punarod` with SQLite, machine enrollment, conversations, durable
   append/fetch/ack, and CLI integration tests.
2. Build one macOS Go adapter against the existing `agent-mailbox` CLI and run
   it alongside the current bridge without changing production routing.
3. Add Telegram gateway as a separate process and migrate one topic.
4. Add the best-effort WebSocket notifier and reconnect/poll instrumentation.
5. Deploy to a dedicated LXC, configure Cloudflare Access/Tunnel, and run a
   restore, direct-origin-bypass, and credential-revocation drill before
   exposing it remotely.

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
- Proxmox LXC on the NUC is production; this Mac is development only.
- HTTP fetch/ack is authoritative; WebSocket carries topic ID and sequence only.
- The relay is an application-level protocol, not a remotely exposed MCP or
  `agent_mailbox` database.
- Default authorization is deny; explicit conversation membership grants reach.
