# Punaro — the chicken coop relay

Punaro is a central, self-hosted collaboration service for conversations,
trusted attachment exchange, and shared memory among coding agents on several
computers and a human operator through Telegram. It does **not** expose or
share a machine's local `agent_mailbox` state. Each computer retains its local
mailbox; a native local client translates between that mailbox and Punaro.

The accepted production direction is a versioned OCI application image with
Docker Compose as the reference single-node deployment. The service is written
in Go. Go matches the existing Waypost toolchain, produces small
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
this to Waypost, retaining a bounded legacy `agent-mailbox` compatibility path
during migration. The separately deployable `punaro-telegram` bridge
adds explicit Telegram topic routing and a restricted Bot API client.
Authenticated attachments use the separately gated trusted-relay surface and
native client. V2/v3 production settings are rejected, their routes are
unmounted, and their binaries are absent from production packaging. Their
code, tests, RFCs, and vectors remain historical experimental evidence. The current
executable release conditions are in
[`docs/security-release-gates.md`](docs/security-release-gates.md).
PostgreSQL schema 22 also contains the dark canonical Big Brain store and its
operator-approved proposal authority. A writer can stage one immutable,
bounded create, update, archive, merge, or split proposal; an administrator
can approve or reject its exact pending ETag. Approval locks every referenced
item deterministically, revalidates exact target and evidence revisions,
rescans proposed documents for secrets, and applies all primitive mutations in
one transaction. The pending ETag binds the complete ordered payload, database
guards reject later child-row appends, and immutable result rows retain the
proposal-to-canonical-revision provenance after approval. Rejection changes no
canonical memory. The store has no
production route or client switch yet. Schema 19 adds a synchronous derived
lexical vector and a two-connection search pool. `memory.search` is checked
before a current-revision-only query; archived and quarantined items are
excluded, exact key/title matches precede weighted title/summary/keywords/body
rank, and only bounded title/summary metadata is returned under a two-second
SQL deadline. Full documents still require `memory.read`. Existing databases
above either 100,000 revisions or 256 MiB of stored canonical documents refuse
the blocking migration. They remain upgrade-blocked pending a later explicit,
backed-up, bounded-backfill slice. The dark `BuildMemoryPromptBrief` read uses
the same authorization, pool, snapshot, deadline, and bounded title/summary
projection. It places up to four curated boolean-pinned records, the newest
curated `project_brief`, and six curated lexical results into deterministic
JSON framed as untrusted memory data. Pin and kind are retrieval hints, never
authority or truth. The response is fixed to versioned section budgets and a
16,384-rune/64-KiB rendered ceiling, reports lexical-only semantic status, and
binds future client caches to the same-snapshot installation, timeline, change,
project-content, and project-ACL generations. It never returns bodies, source
coordinates, or control-plane arguments. The dark native read API is separately
gated by `PUNARO_MEMORY_API_ENABLED`. It authenticates one device bearer under
the existing ingress policy and exposes project resolution, full authorized
get, proposal get, bounded search/brief, and timeline-aware change fetch on
project-scoped v1 routes. The server binds the principal, uses strict bounded
inputs and content-free failures, and keeps unauthorized resources
indistinguishable from missing. An explicit null change cursor starts at the
current installation/timeline origin; subsequent cursors fail on restore or
future coordinates. Remote MCP metadata is separately dark behind
`PUNARO_REMOTE_MCP_METADATA_ENABLED`. It serves the OAuth protected-resource
metadata document for the canonical `PUNARO_PUBLIC_URL/mcp` resource, with
configured HTTPS authorization-server origins, and returns a 401
`WWW-Authenticate` discovery challenge at `/mcp`. That challenge names only
the default `memory.search`, `memory.read`, and `memory.propose` scopes; it
does not parse or accept a token, mount an MCP transport, or expose tools. Thus
enabling it cannot grant remote access before the later OAuth resource-server
and strict transport slices. The OAuth metadata and challenge remain reachable
for standards-required discovery even when optional Access admission is
configured; Access is not application authorization.
The next opt-in resource-server boundary validates only RS256 JWTs from an
advertised issuer through its HTTPS JWKS endpoint. It requires an expiry and
the exact canonical MCP resource as audience, and never forwards the bearer
token. A successful validation additionally requires an operator-configured,
bounded one-to-one OAuth-subject binding to an existing enabled opaque Punaro
principal; an unbound subject is forbidden. The binding is identity plumbing,
not a project grant and not a client-provided authority claim. A successfully
validated and bound request returns only the deliberate no-transport response
when it carries at least one of the advertised default scopes. A token without
those scopes receives an OAuth insufficient-scope response. A later slice must
still check the operation-specific verified scope and Punaro's authoritative
project capability grant for that bound principal before exposing transport or
tools.
The next transport-dark foundation defines a bounded, strict JSON-RPC 2.0
single-request parser. It rejects batches, ambiguous duplicate object members,
unknown envelope members, invalid request IDs, non-object params, excessive
nesting, and trailing data. It is intentionally not mounted on `/mcp` and
cannot dispatch a method; a later adapter must apply operation-specific OAuth
scope and authoritative project capability checks before using the parsed
request.
The mutation slice is separately dark behind
`PUNARO_MEMORY_MUTATIONS_ENABLED`, which requires the read API opt-in. It adds
strict canonical create/update/archive/restore/purge and staged-proposal
create/approve/reject routes without changing the schema. Mutations accept
only canonical active project IDs, bind the authenticated principal, require a
canonical UUID idempotency key, and require a strong revision ETag for every
CAS operation. PostgreSQL remains authoritative for capability checks,
idempotency, atomic proposal application, secret rejection, and permanent
read-only project aliases. The native local memory client now exists as an
independently reviewed slice. `punaro-memory` binds each command to a fixed
origin and protected device credential file. The default remains HTTPS; an
HTTP origin is accepted only when it is a literal private or link-local IP and
the operator supplies both an explicit LAN acknowledgement and a containing
CIDR. Operators may create an
explicit local profile, but it is only a non-secret convenience contract:
versioned JSON containing origin, credential-file path, and optional project
UUID. A version-2 LAN profile additionally records the acknowledgement and
CIDR; HTTPS profiles remain version 1. The profile never stores the bearer
credential value. Profile files are
atomically replaced, owner-only regular files under trusted non-writable,
non-symlink parent directories. Loading revalidates the path, owner-only file
state, strict schema, origin transport policy, absolute credential path, and
optional project UUID before any request can use the defaults. Explicit CLI
flags override profile defaults for the current invocation. The same binary
also has a local stdio MCP mode, `punaro-memory mcp`, that loads the protected
credential and profile once at startup and exposes only bounded memory tools
over JSON-RPC. MCP tool arguments cannot set or override origin, credential
path, profile path, or credential value. Profiles and MCP mode do not add
retry, queue, cache, Git discovery, project registry, fallback local brain,
enrollment recovery, semantic retrieval, remote MCP/OAuth, or Compose Pi
behavior.

Schema 20 adds optional expiry only for explicit evidence. A bounded
`memory.administer` maintenance transaction archives due active evidence,
copies its exact revision-bound provenance, and covers historical scopes behind
permanent project lookup aliases. Ordinary evidence reads require active state;
expiry is reversible archive, not content deletion. Exact duplicate detection
adds no schema: it is a
read-only, repeatable-read administrator report over active current revisions,
excluding active quarantine and including permanent-alias scopes. It verifies
JSONB equality in addition to the hash grouping, returns only hashes, opaque
item IDs, revisions, and layers, and caps each report at 64 duplicate
candidates. The deterministic oldest item is a reporting anchor only:
detection never merges, archives, proposes, or rewrites content. A two-second
SQL deadline and the isolated two-connection brain pool bound its effect on the
rest of the service.

Schema 21 adds derived recall usage: a saturating count and monotonic
last-recalled time per memory item. Successful authorized canonical gets,
evidence gets, returned lexical results, and final prompt-brief entries attempt
one deduplicated enqueue into a bounded 64-batch in-process queue without
waiting for SQL. One worker uses the isolated brain pool and a 150-millisecond
write deadline. Accounting is deliberately optional: queue saturation, a
maintenance fence, usage-table failure, or a hard-deleted race never delays or
fails a successful read. Hard delete cascades usage; ordinary application SQL
cannot directly insert, update, or delete usage rows. A `memory.administer` archive-candidate
report applies an explicit 24-hour-to-ten-year inactivity policy and recall
ceiling to one repeatable-read snapshot. It includes permanent-alias scopes,
excludes pinned, archived, and quarantined records, returns no document, and
caps output at 64 stable CAS candidates. The report never archives or proposes
anything; usage is derived metadata and may be rebuilt from future recalls.

Schema 22 adds bounded canonical reference reconciliation. A direct active
project's `memory.administer` caller may repair only permanent lookup aliases
whose retired project already names that canonical project in `merged_into`,
then remove only soft evidence edges whose exact target revision no longer
exists. One owner-controlled, mutation-fenced batch performs at most 64 changes
in stable alias-then-edge order, advances identity/content generations and the
global change sequence once per non-empty batch, and emits one content-free
audit event. The result contains counts, a `more` bit, and the changed sequence;
converged retries are no-ops. Live source coordinates and proposal
evidence/result coordinates intentionally remain durable provenance and are
never reconciliation targets. The operation does not discover or merge
projects, rewrite memory, or repair derived indexes.

The schema-neutral canonical consistency verifier completes deterministic
memory maintenance. A direct active canonical project's `memory.administer`
caller scans at most 64 current revisions per stable item-ID page across the
canonical project and authoritative retired projects merged into it. One
read-only repeatable-read snapshot compares the canonical document with its
stored SHA-256 digest and synchronous generated lexical title/vector, and
reports whether the exact lexical columns and access paths still satisfy
readiness. Results contain only opaque item/revision coordinates and closed
issue classes; they never return content, hashes, titles, vectors, snippets, or
cross-project counts. The verifier does not repair, reindex, write audit, or
advance generations. Embedding/chunk cleanup and side-by-side generation
rebuilds remain later derived-index work.

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
- Universal turn injection into a receiving model.
- Universal runtime resume of an idle agent process.
- Permission brokering for a receiving host's tool consent.
- Read/action receipts for ordinary message delivery.

## Accepted deployment direction

```text
native client ---- authenticated HTTPS ----+
Telegram gateway ---------------------------+--> punarod
remote MCP gateway -- scoped OAuth ---------+      |-- PostgreSQL authority
                                                    |-- private blob volume
                                                    `-- optional brain workers
```

The reference deployment runs PostgreSQL and its one-shot role bootstrap by
default. `punarod` is a non-default reference profile because the supported
daemon lifecycle is the host-local `punaro` workflow; optional Compose profiles
run the brain worker, Telegram gateway, remote MCP gateway, Cloudflare ingress,
and scheduled backup command. One versioned application image supplies role
subcommands. Containers run non-root with a read-only root, dropped
capabilities, `no-new-privileges`, bounded temporary storage, and no Docker
socket. PostgreSQL and blob storage are never host-published.

The first executable reference bundle is
`deploy/compose/production.yaml`. It pins PostgreSQL/pgvector 18, requires a
digest-pinned application image and canonical HTTPS public URL, mounts owner
and application database credentials only as read-only Compose secrets, and
uses the same-host loopback boundary already required by proxy/Internet ingress:
PostgreSQL is forced to loopback and the bundle defines no host-published
ports. A separately configured local ingress reaches `punarod` on loopback.
The default Compose services start PostgreSQL and its role bootstrap only; a
host-local operator publishes and controls the daemon lifecycle after database
initialization, so raw Compose startup cannot migrate a schema or start a
competing daemon.

PostgreSQL is the only authoritative server database. SQLite remains a native
client recovery store and a server migration/parity source until cutover. The
current SQLite/systemd deployment remains an alpha compatibility path while
the staged migration is implemented; it is not the target production shape.
Internet ingress always uses TLS. An explicitly enabled trusted-LAN HTTP mode
may accept only validated private or link-local bind and source addresses. A
native client independently opts into that plaintext boundary with the same
kind of containing CIDR; the origin must use a literal address, and client
transports disable ambient proxies and redirects.

## Identities and authorization

The accepted target uses host-local first ownership, short-lived single-use
enrollment codes, and one revocable high-entropy device credential per
installation. PostgreSQL stores only an indexed SHA-256 digest. Capabilities
are explicit across project, conversation, memory, and attachment scopes, and
the server applies authorized-scope predicates before any data-dependent
ranking or lookup. The current Ed25519 machine enrollment below remains a
staged migration source and is disabled only after intended clients exchange
credentials or are explicitly retired.

Punaro separates four principals:

| Principal | Example | Purpose |
| --- | --- | --- |
| Machine | `workstation-a` | A single enrolled adapter installation. |
| Endpoint | `agent/build-review` | A locally attached agent session advertised by one machine. |
| Role | `role/plan-reviewer` or `role/<machine>/<slug>` | A durable conversation identity owned by one enrolled machine and bound to one live endpoint at a time. Canonical `role/<machine>/<slug>` handles are opt-in public addresses; legacy names remain valid conversation members until explicitly registered. |
| Conversation | `conv_01…` | The durable room/thread which has members and messages. |

Enrollment templates are server-owned authorization choices, not client
labels. A `trusted-agent` template expands only the exact confirmed project or
all-project capability grants. A `service` template expands to an exactly empty
grant set and creates a revocable device principal that can authenticate only
routes requiring no capability grant, such as server doctor probes. Template,
scope, and grants are bound into the owner-confirmed preview hash and pending
enrollment; `service` cannot be combined with project scope, all-project scope,
or any capability grant. It may carry one exact owner-selected legacy principal
only for a proof-bound exchange, allowing an existing server doctor to replace
its Ed25519 key with a zero-grant device credential without widening authority.

An endpoint belongs to exactly one currently connected machine lease. A machine
can only advertise endpoints in its configured namespace (for example,
`agent/`) and only after local attachment is confirmed. A machine may instead
be enrolled for a named exact legacy endpoint; exact enrollment is equality
only, never an implicit client-wide namespace.

An endpoint member remains the compatible, session-address membership model.
A role member is a separate durable subject with an immutable owning machine,
not an alias or prefix rule for an endpoint. Conversation creation may name a
role with `role_machine_id`; the server rejects an unknown machine and rejects
any later attempt to reuse that role for another machine. A role may be a member
of many conversations, but it has one active session binding at a time.

Canonical public addresses use `role/<machine>/<slug>`, where `<machine>` is the
authenticated owner and `<slug>` is lowercase ASCII matching
`[a-z0-9][a-z0-9-]{0,62}`. The handle is immutable and unique in the
installation. An optional display name is portable UTF-8, trimmed, and at most
128 bytes; it is never authorization. `direct_addressable` defaults to false.
Owning machines register or update that profile with `POST /v1/roles/register`
and a required `Idempotency-Key`. The first call may create the durable role;
later calls may change only display name and addressability. Exact retries
return the first result. Legacy roles such as `role/plan-reviewer` stay valid
conversation members and are not silently renamed; they remain hidden from
addressable identity until explicitly registered under a canonical handle.
Registration never returns bindings, endpoints, credentials, or membership.
Authenticated machines list opted-in addresses with `POST /v1/roles/list` and
resolve a name with `POST /v1/roles/resolve`. Listing is cursor-stable, bounded
to 1–100 rows (default 50), ordered by canonical role, and includes only
`direct_addressable` profiles plus a server-computed `online` flag from the
current valid binding and endpoint ownership generation. Resolve accepts a
fully qualified handle such as `role/workstation-review/reviewer` or an
unqualified slug such as `reviewer`. Display names are never keys. Zero matches
are indistinguishable from hidden or legacy roles. Multiple slug matches return
a typed ambiguity result with at most 20 qualified roles and display names,
never sessions or conversation inventory. After resolve, an authenticated
machine sends with `POST /v1/direct-messages` and a required `Idempotency-Key`.
The request names canonical `from_role` and `to_role` handles plus a body. The
server proves `from_role` is owned by the signed machine and currently bound to
one of its live advertised sessions. `to_role` must exist and remain
`direct_addressable`; it may be offline. Self-send is rejected. One transaction
reuses the unique unordered-role conversation or creates it with exactly those
two role members, both send and receive, and no endpoint membership from
request text. The immutable message is targeted only to `to_role`. The envelope
sender is the source role, not the bound session. Exact retries of the same
machine, key, roles, and body return the original conversation, message, and
sequence. Changing target, body, or source with the same key conflicts.
Revoking addressability before commit creates nothing; revocation after
acceptance does not recall. Direct-role conversations are writable only
through this route; generic `POST /v1/conversations/{id}/messages` appends,
including targeted `target_role` sends, are refused. Delivery remains durable
while the target is offline and becomes leaseable when that role binds later.

The owning machine renews that binding with `POST /v1/roles/bindings`, supplying
the role and one of its currently advertised endpoints. The server verifies the
request signature, the machine's endpoint namespace, the durable role owner,
and the live endpoint ownership generation before recording it. The binding
expires no later than the endpoint lease. Later advertisements of that exact
still-owned session renew the binding together with its attachment lease; a
new session still needs an explicit binding. A detached, expired, or reclaimed
session cannot retain or revive a role. Binding a new session replaces the old
binding. Sending, leasing, acknowledging, room
listing, and wake routing authorize an active role binding as well as an
existing endpoint member, while legacy endpoint membership retains its current
behavior unchanged.

Message routing is explicit and server-authorized. Omitting `target_role`
preserves broadcast delivery to every receiving endpoint and role member other
than the sending endpoint. Supplying a non-empty `target_role` creates a
delivery only for that receiving role membership; endpoint members and other
roles receive nothing. The relay rejects an unknown or non-receiving role
before allocating a message sequence or idempotency row. The target role is
part of the sender's idempotency request hash, while an untargeted request keeps
the pre-targeting broadcast hash so retries remain valid across upgrades.
Every leased role delivery carries a server-derived `recipient_role`; the
adapter preserves it in the inert mailbox envelope so two roles bound to one
session remain distinguishable without interpreting the untrusted body.

Each conversation has an explicit membership table with `send`, `receive`,
and `admin` capabilities. Roles may use only those three capabilities;
`invoke` is endpoint-only because a role has no stable process target. The
Telegram gateway is a distinct principal; only the configured Telegram user ID
may control it. Neither a friendly endpoint name nor a client-provided `from`
field is proof of identity.

Provision each machine with a distinct Cloudflare Access service token and a
distinct Punaro machine credential. Service-token revocation stops ingress at
Cloudflare; revoking the machine credential stops it at Punaro. Store both in
the OS keychain or a root-readable service secret file, never in an agent
prompt, repository, or mailbox body.

Cloudflare Access Service Auth authenticates every protected request from that
machine's service-token headers. Adapter and enrollment clients therefore send
both headers on every protected request and never establish, retain, or replay
a browser `CF_Authorization` cookie alongside them. Mixing those two identity
mechanisms can be rejected by Access before the signed relay request reaches
Punaro. Signed request bodies, machine signatures, nonces, and idempotency keys
are never sent through an Access-session preflight. All signed relay operations
still reject redirects.

Every Ed25519-authenticated relay request carries a fresh signed
`X-Punaro-Nonce`; every device-bearer-authenticated relay request instead
carries a fresh random, non-secret `X-Punaro-Request-Correlation`. The origin
validates the correlation token's bounded canonical form and echoes the
applicable request token exactly once as `X-Punaro-Response-Nonce` before route
handling, including HTTP errors and WebSocket upgrades. Clients compare the
echo with the token they generated to distinguish a Punaro-origin response or
upgrade from an Access or reverse-proxy rejection. Bearer clients require
exactly one matching echo before accepting any allowed HTTP response; doctor
and WebSocket handshakes enforce the same exact match. The correlation token is
neither a credential nor authorization, replay protection, or idempotency;
bearer authorization remains independently mandatory, Ed25519 replay defense
continues to use the signed nonce, and redirects remain rejections.

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

Conversation creation, membership controls, and messages use separate
idempotency records, each
scoped to the signed machine and bound to the normalized request. Retrying a
create returns the original conversation; changing the request under the same
key is a conflict. Messages are immutable rows. A relay-assigned UUID is the
message identity; the sender supplies a separate idempotency key scoped to its
machine. Each conversation has a monotonically increasing `sequence` assigned
transactionally at acceptance. New-message creation is independently rate
limited per authenticated sender machine and per conversation with durable
token buckets. The limiter uses server time, not a client timestamp. An exact
retry of a committed idempotency key returns the original message without
charging. A new request consumes one token from each bucket in the same
transaction that accepts the message. Exhaustion returns HTTP `429` with a
bounded integer `Retry-After` and the stable error `rate limited`. After rate
limits pass, the same transaction reserves pending-delivery capacity for every
recipient identity before sequence allocation: count and body-byte ceilings per
recipient, plus installation-wide count and body-byte ceilings. Broadcast
reserves the complete fan-out or creates nothing. Acknowledgement, membership-
revocation retirement, and other terminal delivery transitions release that
reservation once. Lease and redelivery do not change charged capacity. Capacity
exhaustion returns HTTP `429` with a bounded integer `Retry-After` and the
stable error `capacity exceeded`. A rejected request creates no sequence,
message, delivery, idempotency, or audit row. Explicit counters are updated in
the append transaction; the send path does not scan pending deliveries.
Startup and readiness verify counter consistency or fail closed. The operator
`punaro relay reconcile-capacity` command uses a repair opener that preserves
that fail-closed path while rebuilding drifted counters. Bodies are
never hashed, compared, or parsed for loop detection.

Pending deliveries also have a startup-validated maximum age. Conservative
defaults expire work after seven days. Maintenance uses injected or database
time, never sleep-based tests, and processes expiry and terminal prune in
bounded pages with stable continuation. A delivery older than the inclusive
age boundary transitions atomically from pending to terminal `expired`,
releases pending capacity once, and advances only that recipient's contiguous
cursor through the expired sequence. Another recipient of the same message is
unchanged. An expired active lease cannot later acknowledge. Closed reasons
are `acked`, `expired`, and `revoked`. Terminal records keep opaque
message, conversation, and recipient identifiers, sequence, closed reason,
lease generation, and timestamps; they never duplicate bodies or credentials.
A separate terminal retention period, default thirty days, then prunes that
metadata in bounded pages. Host-local `punaro relay list-terminals` and
`punaro relay maintain-deliveries --yes` inspect and trigger that work.
Ordinary agent HTTP exposes neither dead-letter inventory nor delivery
receipts. Sender-facing append remains accepted/queued or rejected only.
The loopback health listener publishes unlabeled counters for pending count
and bytes, oldest pending age, terminal transitions by closed reason, retained
terminals, and lease redeliveries.

The guarantee is **at-least-once delivery**: a crash after a
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

### Server-authorized invocation

`notify` is still only the best-effort wake hint above: it can reach an
already-attached adapter but cannot create an agent process. `invoke` is a
separate, explicitly granted conversation capability. An attached member with
`invoke` may submit `POST /v1/conversations/{id}/invocations` with only its
endpoint, a receiving target endpoint, and an idempotency key. The server
authorizes the caller's live ownership plus `invoke`, derives the target
machine from the durable endpoint record, requires that target to have
`receive`, verifies unacknowledged work exists, and creates a handoff only if
the target is currently offline. An attached target produces the content-free
`already_running` result instead; it never causes a second start.

An invocation stores no message body. It has a durable ID, target machine,
stable random fence, retry state, lease generation/token, and body-free audit
events for request, lease, retry, acceptance, and terminal failure. The target
machine's always-on adapter leases those records and hands the fixed local
runtime command only `invocation_id`, conversation ID, target endpoint, and
fence. The runtime must durably make a fence idempotent before it reports
success and attaches the role; ordinary delivery then follows the existing
lease/inject/ack flow. A failed handoff retries after 2, 4, then 8 seconds and
becomes a visible terminal failure after three attempts. If the adapter crashes
after local acceptance but before its server outcome, its private journal and
the stable fence prevent a second start on the re-leased record. This is a
fenced at-least-once handoff acknowledgement, not an unsupported claim of
exactly-once process creation.

Terminal invocation records, their idempotency bindings, and their body-free
audit trail are retained for 24 hours from their terminal transition to serve
bounded client retries, then pruned atomically by later invoke traffic. Pending
handoffs and the short accepted-attachment fence are never pruned by this
retention path. A pending handoff that has neither been polled nor completed
for 24 hours is terminally failed before a later invoke can create a fresh
fence, bounding its coalesced idempotency and audit metadata.

The lease response is the source of truth. It contains bounded durable
deliveries plus a map of conversation IDs to the recipient's highest contiguous
acknowledged sequence. Every recipient has an independent
delivery stream; a delivery has a short server-enforced lease, lease generation,
and lease token. A lease that expires without an acknowledgement becomes
available again. The recipient must tolerate duplicate delivery by durably
recording the Punaro message UUID before local injection, or by using it as the
local mailbox idempotency key.

### Membership control plane

Running-fleet membership changes are explicit control operations, never message
bodies. `POST /v1/conversations/{id}/controls` accepts only the typed
`upsert_member` and `remove_member` operations, an attached `actor_endpoint`,
and a target member. The relay derives authority from the signed machine plus
the current endpoint lease, then requires that actor's durable `admin`
capability. It does not trust a client-supplied machine, sender, or endpoint
name as authority. A control retry uses a dedicated idempotency key and returns
the original content-free audit event; reuse with another mutation conflicts.

Every accepted operation appends a durable audit row containing only opaque
conversation/event IDs, actor and target endpoint labels, capability bits,
operation, and timestamp—never a message body, credential, routing secret, or
arbitrary instruction. Current admins may read the bounded history through
`POST /v1/conversations/{id}/controls/audit`. The relay refuses any mutation
that would remove the final admin, preserving a recoverable control path.

The actionable local interface is `punaro-adapter member set --conversation
... --actor ... --member endpoint:send,receive,admin --idempotency-key ...`
or `punaro-adapter member remove --conversation ... --actor ... --member
endpoint --idempotency-key ...`. These paths call the typed control endpoint;
they never interpret local or delivered text as a command.

Optional conversation display names are sanitized UTF-8 labels, not routing
authority. Create may leave a room unnamed. `POST
/v1/conversations/{id}/display-name` requires a live admin session and an
`Idempotency-Key`; repeating the same sanitized label is a no-op. Once a room
has a name it cannot be unnamed again. The adapter surfaces this as
`punaro-adapter create --name ...` and `punaro-adapter rename --conversation
... --actor ... --name ... --idempotency-key ...`.

An agent session may occupy at most one conversation that is named or claimed.
Occupancy is a direct membership or a live role binding to a role member of
such a room. Joining a second named or claimed room is a conflict. Several
sessions may share one topic. Unnamed, unclaimed rooms stay many-to-many.
Exactly `telegram/primary` is exempt so the gateway can occupy every claimed
topic. The fence is enforced on create, control upsert, role membership,
bind-role, the first rename that assigns a name, and Telegram claim reserve.
PostgreSQL serializes that first rename and claim reserve with
`BindRoleToSession` using conversation then endpoint row locks, including
still-unnamed rooms the role already occupies, so an uncommitted bind cannot
hide a second exclusive occupancy. Memberships stay
keyed by `(conversation, endpoint)` and are not unique on endpoint.

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

## Fleet-global agent configuration

Punaro can distribute a user-published coding-agent configuration as a
**data-only** v1 release. The contract lives in `internal/fleetconfig` and is
documented in
[`docs/fleet-global-agent-config.md`](docs/fleet-global-agent-config.md).

The source of truth is an explicitly published immutable Git commit from a
configured repository. Mutable branches, tags, `HEAD`, and abbreviated object
names are never desired state. Publication validates and materializes a
content-addressed archive **before** changing fleet desired revision; a failed
publish leaves the prior desired revision unchanged.

v1 source layout is `AGENTS.md`, optional global `skills/<name>/` trees rooted
by `SKILL.md`, optional `common/<name>/` trees defined once, and optional
`projects/<name>/` trees. A project opts into a common skill with a regular
`projects/<name>/skills/<skill>/COMMON` file whose body is empty or the skill
name. `COMMON` cannot sit next to a private skill tree; dangling `COMMON` is
rejected; a common skill with no members is valid. Common skills count once
toward the 64-skill cap and are never written to `~/.agents/skills`. Skill
`name` frontmatter must match the directory. Reserved live markers
(`<!-- punaro-managed -->`, `<!-- punaro-addendum -->` / `<!--/punaro-addendum-->`,
`<!-- user -->` / `<!--/user-->`, and the retired trailer markers) are illegal
in fleet source and are never archived. `scripts/` files may be present as
regular files; Punaro never executes them and records no destinations or
post-install commands.

Validation rejects absolute paths, traversal, links, special files, duplicate
or case-colliding paths, oversized files, excessive skill counts, malformed
skill metadata, dangling `COMMON`, and `COMMON` mixed with a private skill
tree. Identical input yields identical archive bytes and digest.
Product binary releases remain `internal/release`; this pipeline is a separate
trust domain.

Operators publish with `punaro fleet-config publish COMMIT` against an
explicitly configured repository. The command materializes the release before
changing the singleton desired row (schema 58). A failed publish leaves the
prior desired revision unchanged; an identical digest is idempotent; rollback
is the same command against a previously published commit.

Enrolled clients read desired metadata and exact archive bytes over signed HTTP
and may write only their own bounded status row (schema 59). There is no client
publish route. Desired-generation advances emit a payload-free WebSocket wake
with `topic_id=fleet-config` and `sequence` equal to the generation.

The client reconciler stages a complete tree, copies destinations as regular
files only (never dest symlinks, junctions, or `CLAUDE.md` aliases), matches
project names only as top-level directories under a configured base path (or an
explicit override), and keeps last-known-good on failed activation. A common
skill is copied into each present member-project dest; if that project is
absent on the machine, the skill is absent there. Concurrent reconcile is
serialized.

Apply rehydrates each managed dest from the published file, then matching
machine-local addendums under `~/punaro/addendums` (same layout as the
published tree; project addendum overrides global), then the live
`<!-- user -->` … `<!--/user-->` region (created empty if missing). Addendum
text lives in a marked `<!-- punaro-addendum -->` block that is not the user
block. `CLAUDE.md` is the composed `AGENTS.md` text plus Claude addendum(s),
written as a regular file. Addendums are never published, uploaded, or logged.
Skill bodies and addendums never appear in logs, status, or doctor output.

Harness projection installs only Punaro-managed `AGENTS.md`, `CLAUDE.md`, and
skills, each marked so a later apply can tell Punaro owns it. An unmarked
unmanaged dest is a collision: report drift and do not overwrite.
Activation is reported as immediate, next turn, next session, or restart
required. Unknown installed harnesses are `unsupported`.

`punaro fleet-config status` and content-free Canopi/doctor hooks expose
desired/applied generation, digest, and trailer/alias/project-match states
without file contents, host paths, or raw errors.

LAN qualification uses the owner-managed hosts in
[`docs/fleet-config-lan-e2e.md`](docs/fleet-config-lan-e2e.md). A personal
deployment-validation record is not official release evidence; the
fleet-config boxes in `docs/security-release-gates.md` stay unchecked.

## Canonical memory model

Canonical memory is project-scoped PostgreSQL authority. Each item has an
optional logical key unique only inside its opaque project scope, a bounded
kind and trust classification, reversible active/archive state, and one current
append-only JSONB revision. Reads expose an opaque ETag derived from the item
and revision. Update, archive, restore, and hard delete require an exact ETag;
a stale attempt commits no revision, audit row, change, or idempotency result.

Create and every mutation use the shared operation-bound idempotency contract.
Durable retry outcomes contain only opaque IDs, closed state, revision, ETag,
and change sequence—never memory content, a logical key, or a content hash.
An effective archive or restore state transition appends a revision even when
the document bytes are unchanged, so an older ETag cannot survive the
transition. Archive and restore use distinct closed audit actions. Requesting
the already-current state is a stable no-op that returns the item's current
timeline sequence rather than the installation watermark; that coordinate is
zero until the item changes on a newly restored timeline. Create denial for missing,
retired, and unauthorized projects is likewise non-disclosing.
Reads report only the current timeline's change sequence; abandoned-timeline
rows cannot become a live item cursor after restore.

Hard delete requires the separate `memory.purge` capability. One transaction
records a content-free change, audit event, and durable tombstone, then removes
the item and every canonical revision. The tombstone retains only opaque scope,
item, actor, timeline, sequence, and time fields. The application role has no
direct table privilege on tombstones; only the narrow owner routine writes
them. Change fetch is bounded,
timeline-aware, project-authorized before reading, and permits gaps in the
global sequence without exposing other projects. Until collision-aware scope
rehoming is implemented, a project with any canonical memory scope or retained
history fails closed at project-merge preview/approval rather than stranding or
widening access.
WebSocket reconnect never alters delivery cursors.

Schema version 23 introduces an inert semantic-work frontier. An immutable
owner-created active generation pins a bounded embedding model identity,
revision, and vector dimension. Every later canonical revision insert
coalesces a derived work coordinate containing only generation/item/revision
and canonical SHA-256; no document text, credential, provider request, or
semantic result is present in this slice. A newer revision supersedes queued
work and advances its fence. With no active generation—or with no worker—the
canonical, lexical, prompt-brief, authorization, and mail paths remain
available. A later worker must recheck the exact generation, revision, hash,
and lease before it may publish derived chunks.

Schema version 24 adds only the fenced worker control plane. Owner routines
first honor the global update/backup mutation fence, then claim bounded ready
or expired coordinates with database-time leases, fresh
opaque tokens, and monotonic generations; retry persists a bounded next-attempt
time and requires the exact revision/hash/token/generation fence. A new
canonical revision invalidates an outstanding lease, and the final permitted
attempt is terminal with a code-only diagnostic. No provider, chunk/vector
storage, success publication, semantic ranking, or client-facing semantic
surface is enabled yet.

Schema version 25 adds a bounded content-free chunk coordinate for one
generation and revision. The owner-only publication routine validates ordered
non-overlapping offsets and digests, then atomically stores those coordinates
and terminally completes the exact unexpired lease only while the revision is
current. It still stores no fragment text, provider credential, vector, index,
or semantic result.

Schema version 26 establishes the rebuild starting boundary without activating
semantic retrieval. A schema-owner-only routine takes the same
transaction-scoped advisory fence as revision enqueueing, then locks the
installation change-sequence row and records that sequence on one immutable
`building` generation. The revision enqueue trigger takes the shared form of
that advisory fence,
so every subsequent revision is atomically queued for both immutable active
and building generations. Start itself never scans an unbounded corpus.

Schema version 27 adds the owner-only, bounded rebuild scan. The start routine
also records the installation timeline and creates a private progress row. Each
batch advances that cursor through at most 128 current canonical revisions on
the captured timeline at or before the start watermark; historical revisions
that are no longer current do not create stale jobs. Conflict updates only move
jobs forward, so a revision dual-enqueued after start cannot be overwritten by
the historical scan. A v26 building generation lacks the durable timeline
identity needed for restore-safe scanning and is discarded as derived work
during upgrade. At most one building generation exists; the active generation
remains the sole serving generation.

Schema version 28 adds the owner-only activation transaction. It takes the
same exclusive advisory fence, accepts only completed rebuild progress with no
unfinished building job, removes the former active generation and its derived
jobs/chunks, and promotes the requested building generation atomically. A
revision on either side of that fence is therefore queued for a generation that
is either proved complete before promotion or active after promotion. The
application role cannot activate a generation, and replay fails after the
generation has ceased to be building. There is still no provider, vector
storage, semantic ranking, or client-facing semantic surface.

Schema version 29 records finite pgvector output for every bounded chunk only
when the worker's exact leased-generation, revision, digest, and lease fence
still holds. Each vector must exactly match the generation's pinned dimension.
Coordinate-only successes from older schemas are derived data, so upgrade
requeues them and clears their chunks; terminal failures remain diagnostics
rather than being erased. There is no provider credential or fragment text in
the database, and no vector index. An internal exact cosine-candidate read may
use only the active generation's succeeded chunks and the same project,
`memory.search`, current-revision, active, and quarantine boundaries as
lexical search. It accepts an already-derived, dimension-matched query vector;
it never invokes a provider, exposes a route, or changes core readiness. An
internal hybrid primitive reads both bounded candidate lists under one
repeatable-read authorization snapshot and deterministically applies
reciprocal-rank fusion with a fixed offset of 60. Its candidate primitive
returns only current item coordinates/ranks. The provider-free summary surface
then projects bounded canonical title/summary metadata for those coordinates
from the same authorization-filtered repeatable-read snapshot and records
recall only after that read commits. Both hybrid and lexical-only summary
surfaces re-check the project `memory.search` boundary; with no active
generation the lexical surface reports semantic `not_configured` so callers
keep retrieval available without exposing a provider route.

Before any provider may derive a query embedding, the server authorizes the
caller for `memory.search` and returns only the active generation's non-secret
identity. The provider result must carry that exact generation ID into hybrid
retrieval; if activation changed it meanwhile, retrieval rejects it rather than
comparing a vector against a different model's chunks.

The OpenAI-compatible query provider is a bounded HTTPS-only adapter. Its
endpoint has no userinfo, query, or fragment; redirects are never followed, and
the API credential is sent only as a bearer Authorization header. It posts one
strict JSON request with the pinned model, bounded query input, and float
encoding; the configured provider model identifier must embed the pinned
revision as a `:revision` suffix, and dimension selection is sent only for
`text-embedding-3-*` models.
Responses are limited to 1 MiB, must be one complete JSON value without
duplicate or noncanonical object members with exactly one finite
float32-representable vector
of the pinned dimension, must have bounded JSON nesting, and must
declare the exact pinned model. Provider failures are content-free and never
log credentials, query text, or raw response data. Credential-file loading,
provider selection, and daemon wiring remain separate deployment slices.
The same transport also accepts the worker's current one fenced canonical
document chunk for either validated active or building generation, preserving
its exact SHA-256 and byte-range boundary before a provider request. It
deliberately rejects multiple chunks: later chunking must add an explicitly
bounded request and response contract rather than silently widening provider
exposure.

Provider API-key files use canonical absolute paths only. On Unix, every
ancestor must be a non-symlinked directory owned by the daemon user or root
and not writable by group or others; the key file itself must be a single-link,
regular `0600`-or-stricter file owned by the daemon user and is opened with
`O_NOFOLLOW` before its identity and permissions are rechecked. Keys are one
bounded, non-empty header-safe line and are never included in diagnostics. On
Windows, loading fails closed until equivalent ACL and reparse-point checks
exist.

The bounded embedding executor is provider-agnostic. It claims only existing
fenced work, re-reads the exact live generation/item/revision/hash/lease before
passing a bounded canonical JSON document to an injected provider, validates
all source bounds, offsets, hashes, and generation metadata before the provider
call, binds the reconstructed source bytes and generation to the claimed lease,
then validates the returned chunk count and dimensions before using the existing
fenced publication routine. Active quarantines are excluded both at claim and
source-read time; a race into quarantine durably returns the exact lease to
queued state without spending an attempt only when the owner routine confirms
the active quarantine, so release makes its work claimable again. Stale source
or publication leases are no-ops; source,
provider, and publication outages become bounded code-only retries, and a
failed retry write is surfaced to the executor caller. Provider selection,
credentials, and network configuration remain separate deployment slices.
When an embedding provider is explicitly configured, `punarod` starts one
best-effort background worker with a fresh opaque holder ID. Each pass claims
at most one minute-leased item; the executor preserves that lease's own
deadline through durable retry/publication handling. Provider, database, or
publication failures are retained in the fenced job lifecycle and never fail
request serving or readiness. No provider configuration means no worker or
provider call.

The optional native hybrid-search surface is mounted only when the dark memory
API is enabled and daemon startup has successfully constructed the bounded
OpenAI-compatible query provider and hybrid retrieval executor. It is a
device-authenticated `POST /v1/projects/{project}/memories/hybrid-search`
route with the same strict `query` and 1--50 `limit` bounds as lexical search.
Authentication and project `memory.search` authorization occur before any
provider invocation; denied, missing, and revoked credentials therefore never
send a query to the provider. Its 15-second end-to-end request budget covers
the independently bounded preparation, embedding, and retrieval phases. The
response is the existing bounded title/summary hybrid surface and reports a
semantic status: retrieval remains available with lexical-only
`not_configured` degradation when no active generation exists. If the provider
endpoint is not configured, the route is unmounted; invalid provider
configuration prevents daemon startup rather than accepting a request or
exposing provider configuration.

Schema version 15 places one deterministic secret guard inside the authorized
create/update transaction before any scope, revision, change, audit,
idempotency result, or derived job can be written. Findings contain only the
compiled rule version, stable rule ID, escaped RFC 6901 JSON Pointer, and an exact SHA-256
fingerprint; public errors omit both the suspected value and fingerprint.
Private-key material, supported bearer-token families, credential assignments,
and resolved values in credential-named fields fail closed. `op://` locators,
environment names/references, and explicit placeholders remain inert accepted
text.

There is no request or model override. A principal with
`memory.administer` may approve or revoke only one exact
project/rule-version/rule/path/fingerprint tuple through an idempotent,
content-free operation. The database stores no rejected value and readiness
binds the stored rule version/digest to the exact compiled scanner. Future
proposal approval, import, consolidation, and attachment-text ingestion must
call this same guard before publication or enqueue.

Consolidation is proposal-only: a single pass may inspect at most 128 source
changes, produce at most eight staged proposals, bind at most sixteen exact
evidence revisions to each proposal, and run for at most 30 seconds. It has no
direct canonical-mutation path; every output remains subject to the existing
secret guard, proposal CAS, and explicit approval flow.

Each scope has one durable consolidation checkpoint. A worker claims it only
when unleased or expired and receives an opaque token plus monotonically
increasing generation, timeline, and sequence. Advancement must present that
exact live fence and may only move to the current server timeline and no later
than its current change sequence; it atomically releases the lease. After a
restore, an ancestral checkpoint instead drains each recorded restore edge up
to that edge's watermark, then the next claim rebases it onto the immediate
restored timeline at sequence zero. This repeats through the retained restore
lineage before ordinary current-timeline advancement resumes, so no pending
pre-restore changes are skipped. A crashed worker is reclaimed after expiry,
and a stale worker cannot advance or release the checkpoint. Reprocessing
after a crash or restore is allowed, but proposal creation remains idempotent
and approval remains separately fenced. Timeline rotation invalidates every
live consolidation lease and advances its generation, so a token resurrected
from a restored backup cannot act on the recovered checkpoint.

Schema version 35 materializes each selected consolidation source's canonical
JSON document in the same security-definer statement as the live lease fence
and exact `(item, revision)` coordinate. Fence and cursor rows carry no
document; a missing or malformed document invalidates the whole read. This
internal provider boundary remains read-only and has no proposal, approval, or
canonical-mutation authority.

Schema version 37 additionally materializes only each item's current active
revision as a consolidation source; superseded changes remain cursor gaps. A
stale or non-clear scan for a selected source is a failed provider read rather
than a cursor gap, so a worker cannot advance past a current revision until it
is clear under the current scanner and exception state. The read holds its
matching checkpoint lease fence through materialization, so a new generation
cannot reclaim the checkpoint while the old generation is still being returned
work. Restores rescan their copied revision and record current clear or
quarantined coverage, and the provider boundary rejects any document whose
stored content hash no longer matches its canonical bytes.

Schema version 38 records the source page of each staged consolidation proposal
as immutable `(timeline, item, revision, change-sequence)` bindings. Staging
rechecks the exact live checkpoint token and generation inside its proposal
transaction, requires ordinary `memory.propose` authority, and creates only a
pending proposal: it neither advances the checkpoint nor changes canonical
memory. Generic proposal evidence remains restricted to evidence-layer records;
consolidation provenance is a separate scope-bound relation so curated source
revisions remain auditable without weakening that invariant.

Schema version 39 adds one immutable, lease-fenced pass record for each exact
source page and authorized proposer/project. The bounded, provider-agnostic
executor first loads that record; only an absent record permits planner output,
which is fully validated and durably reserved before any proposal is staged.
Every retry consequently reuses the original proposal bodies and ordinal-based
idempotency keys even if a later planner response differs. It advances the
exact checkpoint and removes that pass atomically only after all staging
succeeds. Planner, validation, staging, or checkpoint failure leaves the page
unadvanced for fenced replay; the executor has no canonical mutation or
approval authority. Planner output cannot choose a principal, project, or
idempotency key: the trusted executor caller binds the authorized
principal/project. A source page that becomes stale, or immutable planner
output that is permanently rejected by item, evidence, or secret validation,
is fenced-retired and advanced without staging a replacement plan; transient
operational and capacity failures remain replayable.
Consolidation staging also proves that the requested project is the leased
scope's canonical project before expiry/retention maintenance can touch any
proposal rows, so a wrong-project request has no cross-project side effects.

Schema version 16 adds bounded, operator-driven rescan and retained quarantine.
Every current revision carries scan coverage bound to its revision, the compiled
rule identity, and a per-project exact-exception generation. Exception changes
advance that generation under the same project lock rather than rewriting an
unbounded corpus. Each rescan batch selects only stale coverage, is idempotent,
and commits scan, quarantine, content-free change, audit, and cursor state
atomically.

An active quarantine is item-level, so archive/restore cannot make a suspected
record visible. Ordinary retrieval treats it like a missing record; later
search, prompt, embedding, and consolidation queries must apply the same active
quarantine exclusion. `memory.administer` has a separate explicit review read
that returns the canonical document and exact content-free finding coordinates.
A clean guarded update or a rescan satisfied by narrow exact exceptions releases
the quarantine; there is no wildcard or model override. Quarantine history is
retained until the canonical item is explicitly purged.

Schema version 17 adds an explicit `evidence` layer beside curated memory.
Evidence creation is one bounded, idempotent transaction containing a guarded
document, one to eight provenance sources, and at most sixteen exact-revision
claims. Copied sources retain only a canonical SHA-256 reference digest. Live
message, attachment, and memory sources retain opaque project/resource
coordinates; memory sources also bind an exact revision. Creation locks the
target and every live-source project in UUID order, locks each required grant,
each mutable source authority record, and each claimed memory item in UUID
order, then rechecks quarantine and source-specific authority before
publication. Relay messages themselves are immutable.

Evidence content is immutable through ordinary update. Archive and restore
append identical content and copy the exact provenance graph to the new
revision. Purging the evidence item cascades its own provenance; purging a
claimed target retains the incoming opaque exact-revision claim so another
item's immutable provenance is not silently rewritten. Retrieval first authorizes the target and
then reauthorizes every live source independently in one repeatable-read
snapshot. A denied source is represented only by its evidence-local source ID,
ordinal, mode, and a redaction marker; its kind and source coordinates are not
revealed. Active quarantine suppresses the whole evidence item exactly as it
does curated memory. No search, embedding, proposal, ingestion worker, HTTP
route, or production client is enabled by this schema-only slice.

## Minimal HTTP surface

All remote requests use HTTPS and require Punaro machine authentication.
Cloudflare Access JWT validation is additionally enabled when all three Access
verifier configuration values are set. The Telegram process is an outbound Bot
API client and reaches the relay using its own enrolled machine credential.

| Method | Route | Purpose |
| --- | --- | --- |
| `PUT` | `/v1/machines/me/endpoints` | Atomically advertise active local attachments. |
| `POST` | `/v1/conversations` | Create a conversation with explicit members and an optional display name; idempotent per signed machine and key. |
| `POST` | `/v1/roles/register` | Register or update one machine-owned canonical role profile; idempotent per signed machine and key. |
| `POST` | `/v1/roles/list` | Bounded listing of opted-in addressable roles; no session inventory. |
| `POST` | `/v1/roles/resolve` | Deterministic name resolution; short names are unambiguous or typed-ambiguous. |
| `POST` | `/v1/direct-messages` | Create or reuse the unique direct-role conversation and send; idempotent per signed machine and key. |
| `POST` | `/v1/roles/bindings` | Renew one durable role onto a currently attached session of its owning machine. |
| `GET` | `/v1/conversations` | List conversations the caller may discover, including optional display names. |
| `POST` | `/v1/conversations/{id}/display-name` | Set a conversation display name from a live admin session; idempotent per signed machine and key bound to the original conversation, actor, and label. |
| `POST` | `/v1/conversations/{id}/messages` | Append an authorized broadcast, or set `target_role` for one durable receiving role. Distinct new messages are admitted only within the configured sender and conversation rate limits and pending-delivery capacity ceilings; committed idempotent retries do not consume tokens or reserve capacity again. |
| `POST` | `/v1/conversations/{id}/invocations` | Request a server-authorized, body-free offline-role handoff. |
| `POST` | `/v1/deliveries/lease` | Lease bounded durable deliveries for one endpoint. |
| `POST` | `/v1/deliveries/{id}/ack` | Acknowledge after local injection. |
| `POST` | `/v1/invocations/lease` | Lease content-free runtime handoffs for the authenticated machine. |
| `POST` | `/v1/invocations/{id}/outcome` | Record one fenced local-runtime outcome. |
| `GET` | `/v1/notifications` | Best-effort WebSocket wake-up stream. |

Use opaque UUID/ULID identifiers. Endpoint names are labels, not URL
authorization handles. Bound every list/fetch page and message size. All
mutations require `Idempotency-Key`; retain idempotency records long enough to
cover client retry windows.

## Telegram integration

A Punaro conversation is the topic. `user-telegram` is a conversation-scoped
built-in participant, not a durable `roles` row: creating or member-setting
that label is rejected. `POST /v1/conversations/{id}/telegram-claim` is a
singleton reservation (`request_hash` is SHA-256 of the conversation id).
Only a live `telegram/primary` advertisement may complete a claim, list
unclaimed named rooms, poll pending reservations, or submit
`telegram-inbound`. Complete inserts `telegram/primary` with send|receive
and materializes `user-telegram`. Targeted send `target_role=user-telegram`
requires a completed claim and creates one delivery to `telegram/primary`.
SQLite-to-PostgreSQL mail cutover exports `telegram_claims`,
`telegram_participants`, `telegram_claim_events`, and inbound `messages`
metadata (`from_participant`, `in_reply_to_*`, `telegram_thread_id`) so a
claimed installation keeps reservation authority and reply context.

The Telegram gateway converts one explicitly configured topic into one Punaro
conversation. It verifies the configured allowed Telegram user ID on every
update, including `callback_query`. It persists `update_id` only after the
relay append succeeds (or after an inert command/callback is finalized);
retrying an unrecorded update uses the same relay idempotency key, so crashes
or transient relay failures do not silently lose user input.

Operator `/list` is a private-chat topic picker: the gateway polls
`callback_query` and sends display-name buttons whose `callback_data` is a raw
256-bit token. Only SHA-256(token) is stored, with a 15-minute TTL and a cap
of 100 outstanding tokens. Conversation ids never appear in Telegram. A `/list`
tap persists `claim_executions` reserved, then consumes the token in the same
SQLite transaction, and `SyncOnce` resumes any incomplete execution. The
gateway persists a `creating` fence under the same SQLite `BEGIN IMMEDIATE`
write lock as `route`, rechecking `topic_routes` and adopting a concurrent
emergency route instead of creating a second topic, then calls
`createForumTopic` only when no route exists,
persists `message_thread_id` and the creation `chat_id` immediately, and
never calls `getForumTopic`. Resume of `topic_created` binds that stored
pair; a changed allowed user fails closed instead of attaching the old
thread to a new chat. A crash after Bot API success and before the thread
id is stored keeps the fence, so resume does not create a second
user-visible topic. An emergency `route` of a known thread is the supported
recovery: unthreaded `creating` may be remapped, and resume binds that route
without calling `createForumTopic`. A thread already bound to `creating`
still cannot be stolen. An ambiguous
createForumTopic error (timeout, lost response, or decode failure) also
keeps the fence instead of retrying create. A completed 4xx Bot API
rejection, including HTTP 429, returns the row to reserved so resume can
retry createForumTopic; the topic was not created. Agent-side pending reservations
are polled with `POST /v1/telegram/claims/pending`; those rows skip a second
reserve. A locally reserved execution whose relay claim is already complete
continues only when this gateway already has a recoverable topic route for
the configured chat; otherwise it fails closed and requires
`punaro-telegram adopt` instead of creating a second topic. Reusing a stored
route requires its `chat_id` to match the configured allowed user.
`punaro-telegram adopt` writes the local `claim_executions` fence from
`topic_routes` under one SQLite `BEGIN IMMEDIATE` as `adopting` before the
remote reserve, so an emergency `route` remap cannot leave a pending relay
claim without a protected local route. A crash after that fence and before
`ClaimConversation` resumes through the adopt reservation instead of
`CompleteTelegramClaim`. `route` refuses a conversation that is adopting, topic-created, routed, or
complete, or a `(chat,thread)` already bound to a `creating` or later claim.
Unthreaded `creating` may be bound to a known thread. Main-chat
ordinary text stays unbound. There is no main-chat fallback. Gateway startup
and `SendDelivery` fail closed when a completed route's `chat_id` is not the
configured allowed user. `/list` fails closed when two unclaimed rooms share
the same 64-rune button label: it sends a generic operator error, consumes
the update, and does not stall later Telegram polling or outbound leasing. One `SyncOnce` starts at most ten new pending
claims, retries at most ten incomplete local executions, and revalidates at
most ten completed routes so Bot API retries cannot starve inbound and
outbound mail; durable cursors continue later rows on the next cycle.
A machine's Telegram claim idempotency key maps to one conversation. Every
successful reserve or ensure records `(machine, key)` in
`telegram_claim_idempotency` bound to that conversation hash: exact replay
returns the existing claim, and reuse on another conversation fails closed.
PostgreSQL serializes reserve/ensure by `(machine, key)` with
`pg_advisory_xact_lock` before the mapping lookup. Claim and mapping
inserts use untargeted `ON CONFLICT DO NOTHING` and then read the winning
row, so a racing unique `(requested_by_machine, idempotency_key)` cannot
abort the transaction. Opening a pre-v8 SQLite database that already stored
the same machine key on two conversations never deletes a complete claim:
extra completes are rekeyed to a collision-free `legacy-dup-` token, extra
pending rows are dropped, then the unique index is created so inspect/migrate
can start.

Inbound topic text is submitted on `POST /v1/conversations/{id}/telegram-inbound`
with `from_participant=user-telegram`. A local `telegram_outbound` map, filled
from each successful `sendRichMessage` `message_id`, resolves `reply_to_message`
into inert `in_reply_to_*` metadata. A map miss delivers the text without that
metadata.

For outbound messages, it leases a durable gateway delivery and posts it using
the exact stored `message_thread_id`. One durable unique route prevents a
conversation from fanning out to multiple topics. `SendDelivery` stays
route-based (`topic_routes` only) and refuses a `chat_id` other than the
configured allowed user. A missing or foreign route fails closed and leaves
the delivery unacked. Requiring a
completed claim on that path is a post-adopt soak follow-up. The Bot API does
not expose a send idempotency key, so a crash after an accepted Telegram send
and before relay acknowledgement is deliberately at-least-once. Agent text is
rendered as escaped rich HTML with entity detection disabled and content
protection set.
Gateway health persists inbound poll-offset progress separately from outbound
delivery-head progress. Only a completed relay acknowledgement advances the
outbound clock during a failing cycle, so ongoing inbound traffic cannot mask a
repeatedly failing outbound head. The endpoint-specific read-only doctor probe
hashes the exact `X-Punaro-Doctor-Endpoint` value into the machine-signed
canonical request; a proxy cannot change the asserted endpoint without making
authentication fail.

Product pings and replies to the human use `punaro-adapter send --to
user-telegram`. The adapter resolves the session's sole claimed topic and
sets `target_role=user-telegram`. Pending quota for that send charges
`telegram/primary` only when the sender is not the gateway; a gateway
self-send creates no delivery and must not leave an un-ackable quota charge.
Agents never pass a Telegram thread or chat id.
`telegram-major-updates` / `send_major_update.py` is not a production
sender.

Adopt of the two live routes is fence-legal only in this order: rename the
keeper while the non-keeper is still unnamed; run `punaro-relay-adopt-prepare
--drop-role role/telegram-codex --yes` on the non-keeper; then
`punaro-telegram adopt` on `<KEEPER_CONVERSATION_ID>` (thread
`<KEEPER_THREAD_ID>`) and `<NON_KEEPER_CONVERSATION_ID>` (thread
`<NON_KEEPER_THREAD_ID>`). Resolve those operator-protected values from the
live gateway state; never record them in source. Adopt never calls
`createForumTopic`.

## Local adapter boundary

The Go adapter runs on each agent machine. It owns the local Waypost
CLI/MCP integration and no remote actor may invoke the CLI directly. It:

1. Watches or periodically reads the locally configured attachment group.
2. Advertises only currently attached sessions to Punaro with a renewable lease.
3. Converts inbound Punaro messages to local mailbox messages, preserving
   `punaro_message_id`, conversation ID, `from_participant`, `in_reply_to_*`,
   and `telegram_thread_id`. When `from_participant` is `user-telegram`, the
   envelope `from_endpoint` is rewritten to `user-telegram`. Agents cannot set
   those metadata fields on `POST /v1/conversations/{id}/messages`.
4. Watches local replies and submits them to Punaro. Pings use
   `punaro-adapter send --to user-telegram`, not a Bot API side channel.
5. Keeps a local encrypted-or-permission-restricted SQLite journal of received
   message UUIDs and pending acknowledgements.

## Agent runtime boundary

Punaro's portable contract stops at durable relay acceptance, local mailbox
injection, and optional fenced process start. Agent-runtime behavior—model
turns, tool permission, and whether an idle session continues—belongs to the
receiving agent host and is not a Punaro guarantee.

Punaro intentionally mediates both same-machine and cross-machine messages
through the Linux gateway: the Linux-hosted relay and, when configured, the
Linux Telegram process. Adapter and native clients are supported on macOS,
Linux, and Windows. Linux gateway hosting plus cross-platform clients is
intentional, not a parity gap.

`notify`, mailbox delivery, and `invoke` remain three distinct mechanisms:

- `notify` is a best-effort, payload-free WebSocket wake. It can accelerate an
  already-attached adapter's next poll. It cannot create a process, inject
  between tool calls, start a model turn, or resume an idle runtime.
- Mailbox delivery is the durable path: advertise attached sessions, lease
  deliveries, inject an inert typed envelope into the local `agent_mailbox`,
  then acknowledge. Relay append acceptance means durable `accepted/queued` for
  authorized recipients. It does not mean the recipient's mailbox has been
  acknowledged, that a model read the body, or that an agent acted.
- `invoke` is optional, operator-configured, fenced runtime start. It is granted
  as an endpoint capability, carries no message body, and is separate from
  ordinary delivery. Without a local invoker command, ordinary mail continues
  and invoke work is not leased. A possible future Pi or provider-specific
  extension that starts or resumes a runtime is non-normative and out of scope.

An active agent must monitor its local mailbox with bounded wait/receive/ack
behavior, repeating those waits during long-running work. Ordinary delivery does
not universally inject between tool calls, create a new turn, or resume an idle
runtime. This boundary excludes universal turn injection, universal runtime resume,
permission brokering, and read/action receipts.

Tool permission and consent belong to the receiving agent host. Punaro does not
broker, cache, or replay host permission decisions. Punaro's enforceable safety
invariant is narrower: message content is inert data and
cannot directly alter Punaro configuration, credentials, routing, membership,
or invoke authority.

There is no per-message accept/hold/refuse UI and no delivered, read, or action
receipt. Installation, role addressability, and conversation membership are the
authorization boundary.

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
exclusive current-user ACL and a hidden interactive per-user Scheduled Task; it
does not expose the wrapping key through an environment variable or task
argument.
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
machine is pending before cutover. After mail cutover is active, an
owner-registered new machine is deliberately pending but is admitted by that
active-cutover record rather than by reopening the migration-wide gate.
PostgreSQL remains dark for mail and SQLite routing is unchanged.

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
mode every Ed25519 relay request consults durable transition authority after
signature verification and before consuming its nonce. The open legacy gate
admits the pre-cutover migration inventory. Once mail cutover is active and
that gate is closed, only a pending key added by the owner-only post-cutover
registration transaction is admitted; migrated and retired legacy keys remain
blocked while migrated credentials remain usable. The switch is off by default
and requires device auth plus the PostgreSQL relay, so this slice does not
activate PostgreSQL mail authority or change the SQLite default.
Long-lived notification sockets retain only a non-secret generation/gate fence,
not the bearer credential. A check starts every second with a one-second
deadline in a dedicated loop; wake writes cannot delay it, and fence failure
cancels any blocked write. This bounds authority after the last successful check to two seconds. Gate
closure, key retirement, credential rotation/revocation, principal disablement,
mapping removal, timeout, or database failure closes the socket.

Every native client records its non-secret transition relationship in a
versioned private local sidecar: version, canonical fixed origin, its explicit
trusted-LAN plaintext policy when applicable, opaque client-generated
enrollment binding, and, only during a mailbox migration, the exact
legacy machine ID. Device credentials, enrollment codes, private keys, Access
tokens, project grants, endpoint aliases, and mailbox state are never fields in
that record. The adapter accepts the sidecar only when its matching protected
profile supplies the same origin, binding, and machine; malformed, stale,
cross-origin, cross-device, partial, or unknown-version state fails before a
transport action. The sidecar is intentionally optional for an unchanged
legacy profile and cannot select a grant, mint a credential, or activate the
M-9 bridge. Fresh enrollment, protected credential persistence, and
platform-specific sidecar creation belong to the client onboarding flow; the
owner-controlled server cutover remains the irreversible authority boundary.

The supported onboarding client is `punaro-enroll`. `prepare` creates a
private current-user state directory and records only the canonical origin,
an explicit containing CIDR for trusted-LAN plaintext when selected, and a
fresh opaque binding in the versioned non-secret sidecar. It
accepts literal loopback HTTP under the same zero-policy version-one identity
shape as HTTPS; non-loopback HTTP still requires the version-two explicit LAN
acknowledgement and containing CIDR. It
prints that public binding for the server owner to use in the exact
least-privilege `trusted-agent` grant preview. `redeem` reads the server's
short-lived enrollment JSON only from a protected local file, requires its
binding to equal the sidecar before any request, and posts only to that stored
origin. Before any network operation it creates a protected recovery journal
containing the code, fresh idempotency UUID, and, for a legacy exchange, the
non-secret public key proving the selected legacy private key. Recovery rejects
a changed proof locally without mutating that journal. Server retry with the
preserved UUID yields the same credential; successful persistence removes the journal. No
command-line argument, environment variable, sidecar, normal output, or
diagnostic includes the code or bearer credential. POSIX storage rejects
symlinks, non-regular files, non-owner files, and group/other-readable state.
Windows storage rejects reparse points and requires a protected DACL with the
current user as owner and sole FullControl ACE. Malformed, cross-device,
cross-origin, unavailable, expired, already-used, or revoked enrollment fails
closed; only the server owner can issue a replacement, rotate a credential, or
revoke it.

Schema version 44 adds the first server-side named-release lifecycle
foundation. Every newly redeemed bearer credential atomically owns one
immutable, unique machine ID, opaque client installation, and derived exclusive
`agent/<machine-id>/` endpoint namespace. First-release credentials are
non-expiring; rotation and either owner or targetless self-revocation advance
the credential, client, principal, and endpoint-authority fences together.
`punaro client list` exposes only bounded lifecycle metadata, while `punaro
client revoke` is host-local, permanent, and idempotent. The public self-revoke
route accepts no body or target and permits an already-revoked credential only
for the exact committed self-revocation key. Authentication and session checks
fail closed unless every lifecycle generation agrees. This sub-slice does not
yet replace static relay endpoint authority, import exact legacy enrollments,
or implement the new invitation, hello, updater, fleet, or recovery protocols.

Schema version 45 adds opt-in canonical `role/<machine>/<slug>` profiles. The
handle is immutable and unique; display name is never authorization.
`direct_addressable` defaults to false. Legacy role names remain valid
conversation members until explicitly registered.

Schema version 46 adds durable per-sender and per-conversation token buckets
for new relay messages. Token state survives daemon restart. Configuration
bounds are startup-validated. Exact committed retries do not consume tokens.
Current SQLite sources that contain `rate_buckets` are migration-source
version 5 and copy those rows into PostgreSQL during cutover so a depleted
sender cannot regain burst after authority transfer. A prepared parent source
without that table remains version 4 and exports an empty `mail_rate_buckets`
page, so crash-during-cutover plus an upgraded admin binary can still inspect
and resume.

Schema version 47 adds idempotent direct-role conversations. Schema version 48
adds explicit pending-delivery capacity counters per recipient identity and
installation-wide. Quota tables are derived operational
state, not cutover content: inspect and fingerprint ignore them, and activation
rebuilds them from pending deliveries. Capacity denial is distinct from rate
limiting. Schema version 49 adds content-free `mail_delivery_terminals` for
acked, expired, and revoked deliveries. Terminal tables are the same class of
derived operational state: inspect and fingerprint ignore them, abort still
deletes them, and they are not cutover content. Pending-age expiry and
terminal prune run in bounded host-local maintenance; they are not an agent
receipt API.

The supported cutover action is `punaro mail cutover`. Its dry-run reads the
service-owned `relay.db` from the installation data directory and prints the
source fingerprint, exact counts, and PostgreSQL target identity without a
mutation. Execution accepts no arbitrary source path and requires a caller
chosen epoch UUID, the dry-run fingerprint, `--yes`, and a complete validated
public static relay enrollment on first execution. That enrollment is published
marker-last before SQLite prepare, remains the canonical endpoint authority
after cutover, and cannot be changed by a recovery retry. The complete static
set can subsequently revoke any machine, including every machine via explicit
`[]`; that restart-safe revocation fails closed. A later replacement may restore
only a public key recorded in the durable cutover enrollment history, so a
temporary revocation does not strand a previously migrated machine. A new
post-cutover machine uses the separate owner-only `punaro relay register`
workflow. It accepts one protected installer-produced public enrollment object,
holds the installation's host-local authority lock across local-state loading,
active-cutover and legacy-gate registration, and marker-last publication, and
commits an idempotent content-free PostgreSQL legacy-machine registration
before extending the local known-key history and static relay enrollment. A
concurrent cutover, configure, or register command fails before mutation and
can retry exactly. A crash releases the lock and, because the database commit
precedes local publication, can leave only a registered but unauthenticated
key; the exact command safely
retries, while a changed label, key, endpoint authority, non-owner caller,
inactive cutover, or conflicting recovery fails closed. The transaction does
not reopen the migration-wide legacy gate: under an active cutover, only its
new pending key becomes eligible for Ed25519 request resolution. Migrated and
retired keys stay blocked. The new key remains pending for an eventual
proof-bound device-credential exchange. This workflow neither
copies another machine's authority nor treats the public record, machine name,
or device credential as authorization by itself. SQLite prepare fences
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

The unified fresh-server declaration includes public relay-machine authority,
device authentication, ingress, memory read/mutation opt-ins, and trusted
attachment storage. Relay authority is read only from a protected bounded file
and canonicalized before the owner bootstrap; trusted attachments require an
existing private blob directory beneath daemon data. A new declaration with
relay authority enables PostgreSQL relay storage immediately, while the
separate mail-cutover preparatory enrollment remains dark until its
owner-controlled cutover marker. Invalid, incomplete, or contradictory inputs
fail before any listener or database mutation. Older published templates remain
valid only as matched generations during explicit lifecycle recovery; the
operator never hand-edits generated runtime files to upgrade a server.

Internet and existing-proxy profiles require a canonical HTTPS public URL and
a loopback origin. Trusted-LAN plaintext is an explicit exception requiring a
concrete private or link-local bind, a containing private/link-local CIDR, and
an observed peer in that CIDR. Wildcard/public binds and peers fail closed;
forwarded headers never establish TLS or source trust. The public surface added
here is limited to strict, bounded enrollment redemption and a
bearer-authenticated session check. PostgreSQL remains dark for mail and
project identity APIs. The signed relay surface may share a trusted-LAN
listener only when its static machine authority is explicitly configured; it
uses the observed peer policy before signature authentication. Directory,
permit, and attachment routes remain loopback-only.
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
host wrapper accepts the exact public release manifest only with its detached
signature and an independently provisioned operator trust root. All three inputs
must be bounded owner-controlled regular files beneath trusted ancestors; linked,
foreign-owned, or group/world-writable trust material fails closed. Signature
verification covers the exact manifest bytes before the wrapper projects the
release name, digest-pinned image, schema range, PostgreSQL major, image digest,
Compose digest, or migration-manifest digest, so no unsigned server-update value
can enter that boundary. The wrapper also derives the source release from the
durable transaction or host stage (requiring an explicit source only for an old
installation without a release lock) and requires that source in the manifest's
signed `supported_from` allowlist before any preflight or fencing; an empty list
permits no server update. Before creating a new transaction, it also verifies a
fresh catalog under that same trust root and requires the exact target release,
sequence, and manifest digest to remain allowed. Catalog retirement blocks new
starts but is not re-applied to an exact durable resume, which must remain
recoverable. Before transaction creation, the wrapper durably advances an
installation-local accepted catalog high-water under a file lock. Catalogs
below either the release binary's embedded catalog sequence or that accepted
sequence are rejected; a synced pending advance is recovered after a crash so
replaying an older, still-fresh signed catalog cannot undo a retirement. The
same cross-process lock remains held through preflight until the database
transaction is durably created, so concurrent starts cannot authorize under
different catalog generations and publish in the opposite order. The one-time
schema-5 bridge also reconciles an uncertain commit against the exact durable
update ID; when none exists, the previous writer must regain readiness before
the unpublished host stage is removed. It
then verifies the exact pulled image digest,
generated Compose artifact, installation identity, disk capacity, and current
health before fencing. It then stops the generated writer,
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

## Canopi lifecycle dashboard boundary

Canopi is Punaro's independently deployable coding-agent status surface. Its
versioned protocol is intentionally outside the Punaro relay/mail contract:
provider adapters normalize lifecycle signals into strict events without
knowing whether direct HTTP, a local spool, or a future Punaro bridge transports
them. Punaro message content is never interpreted as Canopi control data.

The MVP collector uses a separate bearer-authenticated loopback HTTP or LAN TLS
listener, a bounded durable state snapshot, and at-least-once event IDs.
Duplicate IDs are harmless and an already-durable duplicate is acknowledged
before future-skew validation, preserving exact-retry idempotency across clock
corrections.
For one card, `activity_at` and then `event_id` fence delayed/out-of-order
updates. Admission durably expires stale records before rejecting new identities
at a configured live-record ceiling, and rejects activity timestamps beyond
configured future clock skew. A failed
state-file write never mutates the acknowledged in-memory revision, record, or
dedupe set, so an exact retry still attempts persistence. Non-terminal TTL
expiry archives/hides abandoned work and never converts it to success; done
retention is independent. Expiry commits transactionally; a failed state-file
write leaves the acknowledged record visible under the unchanged revision.
The configured aggregate serialized-state budget is checked transactionally
before an event is acknowledged; startup rejects a larger state file before
allocating or decoding its body, and snapshot JSON is bounded by the same
invariant. Admission evicts the oldest dedupe IDs until the candidate fits but
never evicts the newly acknowledged ID; record overflow still fails
transactionally. Serialized updates reclaim crash-left state
temporaries in per-target namespaces and bounded directory batches before
creating a replacement, without racing another state file in the same parent.
The state path is absolute and clean. Its parent must be current-user-owned and
is made owner-only; existing Unix state files must be stable, singly linked,
current-user-owned `0600` regular files opened without following symlinks.
Windows applies equivalent owner, protected-DACL, and no-reparse checks to the
directory, existing state, and replacement temporary. Windows replacement
hard-links the old target as a recovery copy, flushes that directory entry,
publishes with `MoveFileEx` replacement plus write-through semantics, flushes
the directory again, and restores the backup at startup if the target is absent.
Each replacement also recovers or clears a leftover backup before creating the
next one, preventing a failed flush or cleanup from wedging later writes.
A kernel-held lifetime lock keyed by the state path excludes overlapping
collector writers and is released by orderly close or process exit. Windows
derives that lock key from the final path of an open state or parent-directory
handle, collapsing case, extended-device, short-name, and directory aliases.
Unix resolves the existing state path or its parent before deriving the key,
collapsing aliases introduced by symlinks in ancestor directories.
The fixed lock file uses exclusive creation and no-follow opening on both
platforms; unsafe pre-existing entries are removed, directory-synced, and
recreated with current-user-only protection. Repair is serialized cross-process
with the parent-directory kernel lock on Unix and a case-normalized named kernel
mutex on Windows before rechecking and unlinking the unsafe entry.
Signal shutdown waits for the HTTP server to drain active handlers before closing
the store and releasing this lifetime lock, so a rolling replacement cannot load
or write state while an old ingestion is still persisting. This drain is
deliberately unbounded rather than releasing the writer lock after a timeout.
Snapshot and image ETags change only with state revision or rendered response
content. Snapshot responses use a weak revision validator because their
generation timestamp changes without a semantic state change; rendered PNGs
use strong content hashes. TTL checks always use the real clock; only
relative-time rendering and its image cache key use the configured bucket.

Prompts, transcripts, assistant messages, credentials, tool inputs, and tool
outputs are not part of the protocol. Metadata is default-deny: the schema and
Go validator expose only `hook`, `simulated`, and `agent_type`, with matching
per-key types. Wire and persisted decoding retain numeric metadata as exact JSON
numbers instead of converting through `float64`; omission is valid, while an
explicit JSON `null` is rejected because the schema requires an object. Only
valid UTF-8 reaches JSON decoding, preventing malformed identifiers from being
normalized into colliding replacement-character strings. Only explicit,
trusted hook fields drive lifecycle state;
assistant text is neither inspected for classification nor forwarded. Claude
invocation IDs are random, fixed-length 256-bit values independent of both the
bearer credential and provider payload, preventing the collector or a token
holder from testing guesses about private hook content through visible IDs.
The queued normalized event retains that ID across delivery retries. Raw Claude
hook input must also pass the protocol's UTF-8 and paired-scalar-escape checks
before provider JSON decoding. Adapter delivery is detached, bounded, and
incapable of controlling the coding agent. Derived machine labels and task
titles are rune-safely bounded.

The provider-facing Claude process is configured as a current-schema asynchronous
Claude Code command hook (30-second timeout), so it cannot block or control the
agent while it normalizes raw input only in memory and writes each privacy-safe
event to a bounded owner-only spool before launching a detached delivery process.
Raw input is never placed in process arguments,
environment variables, durable files, or requests. The completed event inode is
hard-linked into its final queue name before file or directory sync begins. If
Claude terminates a hook during either uncancellable durability barrier, or the
detached supervisor launch fails, the target remains recoverable. A hook reports
success only after the file and directory barriers succeed; on a sync failure it
kicks the persistent supervisor and exits non-zero. The persistent supervisor
reopens and re-syncs the file and directory before any delivery.
Claude Code's current hook payload has neither a source timestamp nor a
monotonic invocation sequence. The asynchronous integration therefore uses
best-effort local invocation/admission ordering and never reads private
transcripts to manufacture ordering data.
Unix
spools must be current-user-owned and are tightened to mode `0700`; Windows
spools must be current-user-owned and receive a protected DACL containing only
the current user's full-access ACE. One
cross-process worker retries queued events with their original IDs until
acknowledged, while continuing past a rejected event so independent later
updates are not starved. Per-attempt network timeouts and kernel-released file
locks keep provider hooks isolated from collector outages. Enqueue, drain, and
supervisor ownership is bound to each process's open handle, so process exit
releases it and neither stale timestamps nor wall-clock jumps can fence out a
live holder. Concurrent enqueues wait at most 250 ms for the primary lane. Longer
contention publishes through an atomically claimed reserve slot within the same
total event bound; no collector network I/O runs under the primary lock. The
target link precedes sync in both lanes, so a provider timeout cannot remove a
complete event merely because sync stalled. The configurable primary phase is
capped at 750 ms, maintenance and capacity
scans are cancellable in 128-entry batches, and primary-budget exhaustion falls
through to the reserve. The fallback temporary starts
under a pre-lock staging name, acquires its kernel lock, and only then renames
into the cleanup-visible namespace. Cleanup therefore cannot unlink the file in
the create-to-lock window; a pre-lock crash remnant becomes reclaimable after one
minute. Under the enqueue lock, every enqueue removes
crash-left temporary event files before admitting new work. The same protected-token checks apply on the adapter
host. A persistent
`supervise` mode runs under the host service manager, holds a singleton lease,
polls even while the spool is empty, and provides a durable wake/restart path
when a detached kick or worker crashes during a quiet session.
On Windows, each hard-link publication and acknowledgement removal is followed
by a directory `FlushFileBuffers`, matching the Unix directory-sync durability
contract. The supervisor repeats the file and directory barrier before it can
authenticate an event to the collector.
Queued event reads stat the opened file and remain stream-limited to 64 KiB, so
corrupt oversized entries cannot turn the event-count bound into unbounded memory.
Each queued child must also be a stable, no-follow, private current-user-owned
regular file. Event enumeration discards pre-existing foreign or shared children
after the parent is tightened and before capacity accounting or delivery; enqueue
protects new files before publication.
Fixed-name enqueue, drain, and supervisor locks are created exclusively and
opened without following links. Pre-existing entries that fail current-user
ownership or privacy checks are removed, directory-synced, and safely recreated.
One sixteenth of the configured capacity (at least one, at most 256) is reserved
for contention slots, so the primary and fallback lanes remain jointly bounded.
Kernel locks on active fallback temporaries distinguish live publication from
crash leftovers during cleanup.

Structurally valid event batches continue across per-event admission failures
and return ordered per-event status records with HTTP 207 when mixed; only a
shared persistence failure aborts the batch. This prevents one permanently
rejected identity from starving later updates on every retry. The simulator
retains only rejected events from a mixed response and retries their stable IDs
before advancing. The batch envelope is strictly an array; JSON `null` is not
an empty batch and is rejected.

The renderer always sorts the complete state set waiting, done, working, then
recent-first inside each state, before applying configurable capacity. Accepted
fixed-panel grids have one or two columns and one through six rows; other shapes
are rejected before they can overlap typography or icons. The last slot becomes
an omitted-tail per-state count when overflowing. Its output is an exact
800x480 two-color PNG. Custom header titles are fitted into the pixels reserved
before the right-aligned lifecycle totals. Each tile similarly fits its machine
label only into the pixels preceding the right-aligned relative time plus a
fixed gap. The panel thresholds each decoded RGB565 scanline and packs it
MSB-first for the Seeed_GFX one-bit sprite; it performs a full e-paper
refresh only after a changed ETag, bounded PNG download, successful decode, and
exact dimension validation. The RTC-retained validator is versioned so a
firmware update that changes image interpretation forces one corrective redraw.

Canopi's first listener is loopback by default. A concrete private/link-local
listener requires explicit LAN opt-in and an absolute TLS certificate/key pair;
wildcard, public, and plaintext LAN binds fail closed. The panel accepts only an
HTTPS render URL, synchronizes a valid wall clock over NTP before its first
request, and validates the collector certificate against its configured CA.
Adapter and simulator origins use the same HTTPS-except-literal-loopback
policy, require every explicit port to be canonical decimal in the range
1-65535, and refuse redirects, so no reusable bearer is sent to an unvalidated
target or over plaintext LAN traffic. Empty, zero, leading-zero, non-numeric,
and out-of-range explicit ports fail closed rather than falling back to a
scheme default.
This shared-token LAN MVP is not yet Punaro device-authenticated and must not be
mounted on the public Punaro origin. Its bearer token must be a protected,
current-user-owned regular file (or equivalent current-user-only Windows ACL),
opened without following symlinks and rejected if its identity changes during
open. The collector loads its TLS private key through that protected loader and
constructs the in-memory certificate before serving, so the HTTP server never
reopens a replaceable key path. Collector, provider adapter, and simulator share
the same bearer-token loader.

Simulator event IDs include a random per-process run identity, preventing a
restart from colliding with the collector's durable dedupe window. A failed
post retains the exact pending batch and event IDs for retry before the
simulation advances. State transitions use the current tick timestamp so a
resumed working update always orders after the preceding wait.

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
- Server, adapter, bootstrap, Telegram, and fleet readiness use the shared
  schema-version 1 doctor contract in `docs/doctor.md`. Reports are bounded,
  content-free, deterministic, and read-only; remediation identifiers never
  grant authority to repair, restart, enroll, update, or reroute anything.
- Client updates pull signed artifacts from the fixed GitHub Releases origin
  `https://github.com/rock3r/punaro/releases/download`. The gateway names a
  signed release; it never supplies a URL, command, or unsigned `latest`
  pointer. `punaro-bootstrap update` verifies catalog/manifest signatures and
  exact artifact digests, then publishes `current`/`previous` slots.
  Familiar client command names are installer-owned copies of one stable,
  closed-allowlist dispatcher. On POSIX it replaces itself with the selected
  signed-slot payload; on Windows it starts that exact payload with inherited
  stdio and propagates its exit status. Built-in updates replace signed slot
  artifacts, never these dispatcher copies. Doctor requires the adapter,
  enrollment, memory, and trusted-attachment dispatchers to be regular,
  byte-identical executables, while the client installer waits for every
  Windows destination to become replaceable before overwriting it. When that
  installer replaces an enabled repeating Windows task, it disables the task
  for the complete replacement critical section, stops instances even if they
  started while the fence was acquired, and restores the prior enabled/running
  state on failure. A restoration failure is reported together with the original
  installation error. It terminates only processes whose verified image is the
  exact fixed bootstrap path, confirms their bounded exit, and then applies the
  same replaceability fence.
  POSIX source installer likewise binds service-manager ownership to the exact
  managed LaunchAgent plist or systemd unit path: it never reloads or restarts
  a foreign same-name entry, and an explicit enable fails closed on conflict.
  Platform services launch `punaro-bootstrap run`, which supervises the
  current-slot adapter, requires a local ready signal within 60 seconds when a
  previous slot exists, rolls back once if the fresh catalog still allows that
  previous release, and otherwise enters recovery-only. A generation that
  already passed that ready gate is not re-tested as a candidate after reboot.
  The supervisor stays
  parked until a later signed update or seed clears that marker, then exits so
  the platform service restarts onto the repaired slot. An unreadable update
  journal also enters recovery-only. Invalid `generation.json`,
  `healthy-generation.json`, `release.pub`, or `auto-rollback.json` nodes are
  quarantined so signed repair and supervision can continue. An exhausted
  generation high-water mark is rejected instead of wrapping. Source installers
  persist `--keys-file` into `release.pub` and refuse to leave a signed previous
  slot without that key set, so catalog-gated rollback remains available. `run` holds a separate `run.lock` lease for
  the child's lifetime so two supervisors cannot share the same mailbox and
  ready file; the transaction lock stays free for `update`. A crash-safe
  `run.pid` records the child's pid and image path. A starting marker is written
  before the child is launched so a crash in that window cannot leave an
  untracked adapter; the next supervisor identity-checks matching images on
  Linux, macOS, and Windows and takes the lease only when they are gone. The next supervisor kills
  that process only when the live image still matches, and it removes the file
  when the child or supervisor exits. If the image cannot be verified, the
  next supervisor refuses the run lease instead of launching a second adapter. A later publish stops the old adapter
  with SIGTERM and a bounded wait before SIGKILL so the service can restart
  onto the new slot. A healthy child that exits while the
  supervisor is still running is a supervisor failure so systemd/launchd restart
  it. The one-shot rollback decision is durable across supervisor restarts so a
  later failure cannot swap back to the known-unhealthy slot. Enrollment is not
  implemented yet.
- PostgreSQL is the sole authoritative server database after cutover; SQLite is
  retained for client recovery, migration evidence, and parity tests only.
- HTTP fetch/ack is authoritative; WebSocket carries topic ID and sequence only.
- Remote MCP is an optional OAuth-scoped adapter over the Punaro service, never
  a remotely exposed `agent_mailbox` database.
- Default authorization is deny; explicit conversation membership grants reach.
