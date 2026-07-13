# Punaro — the chicken coop relay

Punaro is a small, central, self-hosted relay for conversations among coding
agents on several computers and a human operator through Telegram. It does **not** expose
or share a machine's local `agent_mailbox` state. Each computer retains its
local mailbox; a local adapter translates between that mailbox and Punaro.

The first production target is a dedicated Proxmox LXC on the NUC. The relay is
written in Go. Go matches the existing `agent-mailbox` toolchain, produces a
single static-ish service binary, and keeps the runtime small and auditable.

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

Run the following as separate, unprivileged systemd services in a dedicated
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
`agent/`) and only after local attachment is confirmed.

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
only through the tunnel. It requires a valid machine credential for every
adapter request. Use an enrolled Ed25519 device key with request signatures
(method, path, body hash, timestamp, and nonce), or mTLS client certificates;
the exact choice is an implementation decision, not an optional security
layer.
This avoids treating a network location or Cloudflare header as application
authorization.

## Delivery model

Messages are immutable rows. A relay-assigned UUID is the message identity;
the sender supplies a separate idempotency key scoped to its machine. Each
conversation has a monotonically increasing `sequence` assigned transactionally
at acceptance. The guarantee is **at-least-once delivery**: a crash after a
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

All requests use HTTPS and require both Cloudflare Access validation and Punaro
machine authentication, except the Telegram gateway's loopback-only endpoint.

| Method | Route | Purpose |
| --- | --- | --- |
| `POST` | `/v1/machines/heartbeat` | Renew machine and endpoint leases. |
| `PUT` | `/v1/machines/me/endpoints` | Atomically advertise active local attachments. |
| `POST` | `/v1/conversations` | Create a conversation with explicit members. |
| `GET` | `/v1/conversations` | List conversations the caller may discover. |
| `POST` | `/v1/conversations/{id}/messages` | Append an authorized message. |
| `GET` | `/v1/deliveries` | Lease durable deliveries, optionally for one topic. |
| `POST` | `/v1/deliveries/{id}/ack` | Acknowledge after local injection. |
| `GET` | `/v1/notifications` | Best-effort WebSocket wake-up stream. |

Use opaque UUID/ULID identifiers. Endpoint names are labels, not URL
authorization handles. Bound every list/fetch page and message size. All
mutations require `Idempotency-Key`; retain idempotency records long enough to
cover client retry windows.

## Telegram integration

The Telegram gateway converts an explicitly selected allowed private-chat topic
into one Punaro conversation. It verifies every configured allowed Telegram
user ID on each update, records `update_id` idempotently, prevents concurrent pollers, and
stores short-lived opaque callback references server-side rather than exposing
endpoint addresses in callback data. A topic's target picker lists only active,
authorized endpoints. Selecting a target creates or updates explicit
conversation membership rather than a hidden global route.

For inbound Telegram messages, the gateway appends a normal Punaro message to
the selected conversation. For outbound messages, it consumes a durable gateway
delivery and posts using Telegram's `message_thread_id`. Store the Telegram
chat ID, topic ID, and reply-to message ID as gateway metadata; do not infer a
topic and never silently fall back to the main chat.

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
or WebSocket hint. The current code is a testable protocol foundation only;
`punarod` deliberately refuses to mount its HTTP surface even when attachment
configuration is present. It will remain fail-closed until recipient envelopes,
fresh authority directories, revocation, and permit renewal are implemented.
The foundation's relay model persists offers, fencing sessions, ciphertext
frames, and verified completions in SQLite WAL; it never falls back to an
unauthenticated or in-memory-only runtime mode.

Each logical attachment has a CSPRNG 32-byte content salt and a BLAKE3 content
commitment over that salt and the domain-separated full-plaintext hash. A
recipient-specific artifact uses a CSPRNG file key and artifact ID. XChaCha20-
Poly1305 frames bind the transfer, artifact, chunk index, and plaintext length
as AAD; deterministic nonces are safe only because `(transfer ID, artifact ID,
chunk index)` is unique and durable. The relay blob store contains ciphertext
only, accepts an identical retry, and rejects a replacement at an existing
artifact/index.

Recipient offers use fencing generations: accepting or resuming creates a new
opaque session token and invalidates every prior token. Tokens have a bounded
ten-minute relay lease. Offer creation requires a signed `Idempotency-Key`; the
offer, sender/conversation context, and deduplication record commit atomically.
Signed request nonces are also consumed in the same SQLite database so a daemon
restart cannot replay a still-valid mutation. Authorization failures do not
disclose whether an offer exists.

The foundation fallback requires a sender-signed source declaration:
one safe opaque artifact ID, chunk count, ciphertext byte ceiling, and expected
plaintext hash. It accepts only the declared artifact and contiguous declared
indexes, caps each frame at 256 KiB, caps each artifact at 64 MiB, caps the
relay at 1 GiB of ciphertext, and does not mark completion until every declared
frame exists and the recipient submits the declared plaintext hash. Opaque
signaling is separately capped to 32 records/512 KiB per offer and 128 MiB
relay-wide. These are fail-closed reservation limits, not a substitute for the
future operator-configured quotas and retention reaper.

Direct/TURN transport primitives are tested only in an isolated adapter-side
package and are intentionally not wired into `punarod`. They remain disabled
until the directory freshness, permit renewal, transcript binding, candidate
authorization, and 1 MiB in-flight bound in the normative attachment issue are
implemented. The relay accepts only bounded opaque signaling from the original
sender or a recipient holding the current fenced session; it does not parse
SDP/ICE, log candidates, or carry them through normal messages. The encrypted
relay-blob transfer has no currently reachable daemon route.

If the adapter stops, its endpoint lease expires and the central target picker
no longer lists it. Existing conversations remain, but new sends are queued
only where the policy permits offline delivery; the Telegram UI clearly labels
that state.

## Safety controls and operations

- TLS only; no HTTP listener exposed outside loopback/private LXC network.
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
  NTP/clock skew because leases and credentials are time-bound.

## Implementation plan

1. Build `punarod` with SQLite, machine enrollment, conversations, durable
   append/fetch/ack, and CLI integration tests.
2. Build one macOS Go adapter against the existing `agent-mailbox` CLI and run
   it alongside the current bridge without changing production routing.
3. Add Telegram gateway as a separate process and migrate one topic.
4. Add the best-effort WebSocket notifier and reconnect/poll instrumentation.
5. Deploy to the NUC LXC, configure Cloudflare Access/Tunnel, and run a
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
