# Product: Punaro

> What Punaro is and where it is going. Architectural authority lives in `DESIGN.md` and
> `docs/big-brain-plan.md`; this document is the product-level view. Last updated 2026-08-19.

## 1. What this is

Punaro is a central, self-hosted collaboration service for one human operator and their
coding agents spread across several computers. It has two pillars:

1. **Cross-agent mail** — durable, ordered, authorized conversations among agent sessions
   on enrolled machines, including trusted attachment exchange. The operator participates
   from Telegram, which is a *surface* onto this mail, not a separate system.
2. **Central memory ("Big Brain")** — one shared, revisioned, project-scoped memory store
   agents search, read, and propose changes to, instead of per-machine notes.

Hard boundaries that define the product:

- Punaro never exposes or shares a machine's local `agent-mailbox` state. Each computer
  keeps its local mailbox; a native adapter translates between it and Punaro.
- Everything model-visible is untrusted data. Message bodies, memory content, and
  Telegram text can never act as routing, authorization, URL-fetch, or execution
  authority.
- Single trusted operator, trusted self-hosted installation. Explicit non-goals: hostile
  multi-tenant operation, E2E confidentiality from the operator/host root, multi-node HA.

## 2. Pillar: Cross-agent mail

### The mail system

- **Relay (`punarod`)** is the sole authority on conversations, membership, roles, and
  idempotency. Durable append / lease / ack delivery, ordered per conversation, reaches
  enrolled machines even when they sleep; payload-free WebSocket wake hints add
  best-effort latency, but polling/lease/ack is the correctness mechanism. PostgreSQL is
  the accepted storage authority.
- **Identity is explicit and revocable.** Machines enroll with Ed25519 keys and sign
  every request; ingress is Cloudflare Access or an explicit opt-in trusted-LAN profile.
  Endpoint labels and `from` fields are never proof of identity.
- **The adapter boundary.** One `punaro-adapter` per agent machine advertises locally
  attached sessions, leases deliveries, injects them into the local mailbox as inert JSON
  envelopes, and acks only after local injection. Agents send with
  `punaro-adapter send` + stable idempotency keys; they never hold relay, Access,
  Telegram, or memory credentials.
- **Durable roles** decouple addresses from ephemeral sessions: a role is bound/renewed
  to a live session, and targeted routing delivers a send to exactly one role instead of
  broadcasting — preventing unattended agent-answers-agent loops. The relay bounds
  message rate and pending capacity, and retains terminal deliveries in an
  operator-inspectable dead-letter — always without parsing bodies. Opt-in role
  discovery and direct addressing (#143) is the remaining open tracker.

### Attachments

File bytes never travel through chat bodies or Telegram. Trusted attachment exchange is a
separately gated relay surface plus a native client: operator-provisioned trusted origin,
device credential, project scope, and download root, with explicit typed offers —
nothing auto-downloads, auto-executes, or auto-forwards. The attachment release gate is
still closed.

### The Telegram operator surface

Each relay conversation surfaces as one forum topic in the operator's private chat, via a
separately enrolled gateway (`punaro-telegram`) that long-polls the Bot API and never
touches an agent-mailbox database. The contract:

- **A conversation IS its topic.** One topic ↔ one conversation, held in durable,
  content-free gateway state. No main-chat fallback, no picker, no routing by inference;
  unauthorized/non-text/unbound updates are durably skipped.
- **Claim-gated.** The Telegram surface is something the operator **claims** — from
  `/list` of unclaimed display-named conversations (opaque single-use callback tokens),
  or an agent-side reserve that the gateway completes — never something a send invents.
  Claiming creates the forum topic, persists the route, and materializes a per-topic
  built-in participant **`user-telegram`**.
- **One send label for agents:** `punaro-adapter send --to user-telegram` — unambiguous
  because one session occupies at most one named/claimed topic (a scoped fence; unnamed
  operational rooms are unaffected). Completion pings are ordinary sends to
  `user-telegram`; the enrolled gateway is the only Telegram sender that exists.
- **Single allowed user.** One numeric Telegram user ID, checked by the gateway on every
  update regardless of BotFather settings.
- **Delivery semantics.** Inbound is exactly-once into the relay (Telegram `update_id` as
  idempotency key, marked processed only after the append succeeds). Outbound to Telegram
  is deliberately at-least-once (no Bot API send idempotency key; ack only after send).
- **Agent content stays inert:** rendered as escaped HTML, entity detection off, 32 KiB
  bound with splitting. Agents never call the Bot API and never see tokens, chat IDs, or
  thread IDs. Operator replies-to arrive as inert envelope metadata. Credentials are
  root-owned 0600 files via systemd `LoadCredential`; no tokens or bodies in logs.
- **Not supported by design:** auto-discovering or adopting Telegram-created topics,
  recreating a user-deleted thread (fail closed instead), agents choosing topics,
  Bot API side channels, multi-operator use.

## 3. Pillar: Central memory — Big Brain

Shared, revisioned memory with lexical and, next, semantic retrieval
(`docs/big-brain-plan.md` is the accepted direction).

- **Model.** Canonical memory is project-scoped PostgreSQL authority. Items are immutable
  revisions with digests and provenance; curated content is separate from an explicit
  `evidence` layer. Writers stage bounded, immutable **proposals** (create / update /
  archive / merge / split); an administrator approves or rejects the exact pending ETag.
  Approval revalidates revisions, **rescans documents for secrets**, and applies
  atomically with full provenance. Rejection changes nothing.
- **Retrieval.** Scoped capabilities (`memory.search` / `memory.read` / `memory.propose`
  / `memory.administer`). Search is current-revision-only, bounded metadata under a
  two-second deadline on an isolated pool; full documents need `memory.read`. A
  deterministic **prompt brief** packs pinned records, the project brief, and top lexical
  results into budget-bound JSON explicitly framed as untrusted data — pins and kinds are
  retrieval hints, never authority.
- **Access paths.** Agents-only, via MCP/CLI — Big Brain exists for the agents, not the
  human, so it has no Telegram or operator surface. The native client `punaro-memory`
  binds to a fixed HTTPS origin and protected device credential, with a local stdio MCP
  mode whose tool arguments cannot override origin or credentials. Server-side, the
  store sits behind layered opt-ins (read API, mutations, and a remote MCP/OAuth surface
  built dark slice by slice — no transport mounted until every authorization layer is in
  place). Onboarding is per-machine and explicit.
- **Maintenance is bounded, content-free, and operator-decided:** evidence expiry as
  reversible archive, duplicate and archive-candidate *reports* (never auto-merge or
  auto-archive), recall-usage tracking that never delays a read, reference
  reconciliation, and a read-only consistency verifier.
- **Invariants:** unauthorized indistinguishable from missing; content-free failures;
  memory is data, never authority; oversized stores refuse risky blocking migrations.

Mail carries the conversation; Big Brain carries the knowledge.

## 4. Cross-cutting product principles

- **Explicit enrollment, revocable identity** for every principal — machines, gateway,
  adapters, memory clients.
- **Fail closed, everywhere.** Unknown updates inert; unclaimed topics reject sends; dark
  features stay dark behind gates; release gates (`docs/security-release-gates.md`) hold
  until adversarial acceptance tests pass (replayed updates and hostile bodies stay inert).
- **Content-free operational state:** gateway state, wake hints, audit logs, and
  maintenance reports carry IDs and sequences, never bodies or credentials.
- **Durable correctness over liveness tricks:** idempotency keys on every mutation,
  at-least-once only where explicitly chosen and documented (the Telegram send edge).

## 5. Where it stands and where it goes

Alpha, unpublished, single live deployment. The mail pillar is furthest along: relay,
adapter, durable roles, targeted routing, rate/capacity/dead-letter bounds, and the
enrolled Telegram gateway are live; the claim/`user-telegram` model (PR #138) is landing
now, and fresh topics are created through the claim flow — no legacy routes are carried
forward. Big Brain has the full canonical store, proposal machinery, lexical retrieval,
and native client built, but runs dark pending its enablement slices.

Runway, roughly in order:

- **Mail:** tighten outbound sends to require a completed claim (post-#138 follow-up);
  decide whether the gateway gets the relay's park-and-continue semantic instead of
  head-of-line blocking on a permanently failing delivery; role discovery (#143).
- **Big Brain:** end-to-end testing, integration into the agent skills, and proving it
  in real day-to-day use; then semantic retrieval (embedding execution + search) and
  the remote MCP resource-server/transport slices.
- **Platform:** production Compose as the reference deployment; opening the release
  gates (attachments, public operation) once their adversarial acceptance tests pass.
