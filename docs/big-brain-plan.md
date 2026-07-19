# Punaro pragmatic platform and Big Brain plan

Status: accepted implementation direction (2026-07-19)

This document proposes the next architectural direction for Punaro. It covers
the central server, mail relay, attachments, shared memory ("Big Brain"),
client integration, deployment, migration, and the security/UX balance that
governs all of them.

## Direction

Punaro will be a pragmatic, self-hosted collaboration service for agents and
their operator. Its primary goal is to make agent-to-agent communication,
attachment exchange, and shared memory reliable and pleasant across multiple
agents and machines.

Punaro is not a hostile multi-tenant SaaS, a secrets manager, or a system for
confidential government data. The server and its operator are trusted with
message, attachment, and memory content. Application-level encryption at rest,
end-to-end encryption, zero-knowledge storage, and resistance to a compromised
server or trusted LAN are explicit non-goals.

That does not make security optional. Punaro must protect against realistic
unauthorized access, accidental cross-scope disclosure, unsafe untrusted input,
credential loss, public endpoint abuse, corruption, and operational mistakes.
Security controls must be proportionate to that threat model and must not make
the ordinary agent workflow cumbersome.

The governing rule is:

> Protect the boundary; streamline everything inside it.

## Decisions

1. Ship the central server as versioned OCI images. Docker Compose is the
   reference single-node deployment; other OCI runtimes may be supported.
2. Use PostgreSQL as the only authoritative server database for identities,
   mail, attachment metadata, memory, jobs, idempotency, and audit events.
3. Store attachment bytes outside PostgreSQL on a private local volume first,
   with an optional object-storage backend later.
4. Keep client-local SQLite only for offline queues, deduplication, crash
   recovery, and optional explicitly stale read caching. It is never a second
   central authority.
5. Use a relational control plane with document-shaped memory revisions.
   PostgreSQL `JSONB`, full-text search, and pgvector provide the initial memory
   storage and retrieval stack.
6. Treat vector, lexical, summary, and relationship indexes as derived data.
   Canonical memory revisions and provenance remain rebuildable source data.
7. Replace the production direction for encrypted attachment v2/v3 with a
   conventional trusted-relay upload/download protocol over authenticated TLS.
   Existing experimental code remains untouched until an explicit retirement
   change is reviewed and approved.
8. Use revocable high-entropy device credentials over TLS for ordinary Punaro
   clients. Remote MCP uses the OAuth flow required by the MCP protocol.
   Cloudflare Access is an optional admission layer, not required application
   authorization.
9. Store mail, attachment, and memory content as plaintext application data.
   TLS remains mandatory at Internet ingress. Host, filesystem, platform, or
   backup encryption may be used operationally but is not part of Punaro's
   application security contract.
10. Scan every memory write path for likely secrets and direct users toward a
    dedicated secret manager such as 1Password CLI. Secret references are
    allowed; resolved secret values are not memory.
11. Integrate Compose Pi through a selectable memory backend. Local mode keeps
    its current SQLite memory. Punaro mode makes Big Brain the sole writable
    authority; network failure must not silently create a second writable
    local brain.
12. Add deterministic memory maintenance before model-assisted consolidation.
    "Dreaming" may propose reversible, evidence-backed changes but may not
    silently rewrite trusted memories.
13. Treat Local and Punaro memory as independent corpora. Initial import is
    explicit and idempotent; v1 does not queue offline Big Brain writes or
    silently synchronize changes made after switching back to Local mode.
14. Publish one Punaro application image containing role subcommands. Compose
    runs separate containers only where operational isolation is useful; the
    default deployment is `punarod` plus PostgreSQL.

## Product and threat model

### Expected deployment

- One self-hosted Punaro installation controlled by one operator or household.
- Several trusted machines and many concurrent agent sessions.
- Optional Telegram and remote MCP access through an Internet-facing tunnel or
  reverse proxy.
- Cloud-hosted models may already receive the same technical content.
- The Punaro host, database administrator, and trusted LAN are inside the trust
  boundary.

### Punaro must handle well

- Accidental public exposure and reverse-proxy mistakes.
- Opportunistic scanning, malformed requests, and credential guessing.
- Lost, stolen, expired, or revoked client credentials.
- One client attempting to use another project, conversation, or attachment.
- Agent or Telegram content attempting to change routing, authorization,
  configuration, or filesystem behavior.
- Path traversal, unsafe names, symlinks, and accidental attachment overwrite.
- Duplicate requests, retries, concurrent updates, crashes, and partial work.
- Runaway clients exhausting database connections, storage, queues, or worker
  capacity.
- Accidental secret persistence in shared memory.
- Failed upgrades, incompatible schemas, corrupt state, and restore failures.

### Punaro should contain reasonably

- A compromised authorized agent should remain limited to its granted projects
  and conversations.
- A compromised client credential should be independently revocable.
- A broken or malicious memory record must remain inert to Punaro's control
  plane, even though its text may still influence a model that reads it.
- A failed embedding or consolidation worker must not make mail unavailable.
- A failed attachment upload must not expose a partial downloadable artifact.

### Explicit non-goals

- Defending data from the Punaro operator, host root, or database administrator.
- Surviving an advanced attacker established on the trusted LAN or server.
- Hostile customer isolation within a public multi-tenant service.
- End-to-end confidentiality, forward secrecy, or traffic-analysis resistance.
- Punaro-managed encryption keys or recovery ceremonies.
- Protecting an agent after its machine, OS, and keychain are fully compromised.
- Hiding content from third-party model providers chosen by the operator.
- Compliance-grade audit non-repudiation.

### Security decision rule

Every proposed control must document:

1. The realistic threat it mitigates.
2. Its expected reduction in likelihood or impact.
3. Its user, operator, recovery, and implementation cost.
4. A simpler alternative and why it is insufficient.

Controls whose cost materially outweighs their benefit under this threat model
must be rejected. Recovery complexity, bypass incentives, and user workarounds
count as security costs.

## System topology

```text
agent process
    |
    | local MCP / CLI / protected local IPC
    v
punaro client -----------------------------------------------+
    |                                                        |
    | authenticated HTTPS + payload-free change hints        |
    v                                                        |
public/LAN ingress                                            |
    |                                                        |
    v                                                        |
punarod                                                       |
    |-- PostgreSQL: auth, relay, memory, metadata, jobs       |
    |-- blob volume: attachment bytes                        |
    |-- memory worker: embeddings and deterministic upkeep   |
    `-- optional consolidator: proposal-only dreaming        |
                                                             |
remote MCP client -- OAuth --> punaro MCP gateway -----------+
Telegram gateway ---- device credential ---------------------+
```

The central API is authoritative. WebSocket or SSE notifications contain only
opaque identifiers and change sequence numbers and may be dropped. Clients
recover by fetching state over HTTPS.

### Reference container deployment

The supplied production Compose bundle contains:

- `punarod`: API, authorization, mail, attachment control, memory CRUD/search.
- `postgres`: pinned PostgreSQL major with pgvector.
- `brain-worker`: optional bounded embedding and maintenance worker.
- `punaro-telegram`: optional profile.
- `punaro-mcp`: optional remote MCP profile.
- `cloudflared`: optional ingress profile.
- `backup`: optional scheduled use of the supported backup tooling.

The release uses one Punaro application image containing server, worker,
gateway, migration, and administration subcommands. Compose may run that image
under different commands, database roles, pools, and resource limits. The
default profile runs only `punarod` and PostgreSQL; Telegram, remote MCP,
Cloudflare, semantic indexing, and scheduled backups are opt-in. Server
containers run non-root with a read-only root filesystem, no additional
capabilities, `no-new-privileges`, bounded temporary storage, and no Docker
socket. PostgreSQL and attachment storage are not published directly.

The local adapter/client remains a native host process because it needs the OS
keychain, local filesystem, and local agent/mailbox integration.

## Authentication and authorization

### Device authentication

- Initial ownership is created only by a host-local administration command such
  as `punaro init` or `docker compose run --rm punaro-admin init`. A pristine
  deployment has no public "first user wins" enrollment path.
- The operator creates a named client enrollment from the host-local CLI. It
  returns a short-lived, single-use code bound to that pending client.
- Redeeming the code creates one high-entropy credential per installation.
- The client stores it in the OS keychain or a protected service credential.
- A credential has a public lookup ID and at least 256 random secret bits.
  PostgreSQL stores an indexed SHA-256 digest and compares it in constant time;
  slow password hashing would add denial-of-service cost without helping a
  random bearer token.
- Credentials have an ID, label, creation time, last-used time, capabilities,
  optional expiry, and revocation state.
- The server accepts credentials only over TLS outside the same-host container
  network, except when the operator explicitly enables trusted-LAN HTTP for
  validated private or link-local source and bind addresses. Publicly routable
  addresses never qualify for that exception.
- Enrollment, listing, rotation, and revocation have operator-friendly CLI/UI
  paths; ordinary requests require no interactive approval.

Signed request bodies and durable replay nonces are not required. Mutation
idempotency and optimistic concurrency remain required for correctness.
Revocation invalidates authentication caches and closes or forces
reauthentication of long-lived notification sessions within a short documented
bound.

The release bundle supplies a small `punaro` operator wrapper with supported
happy paths:

- `punaro init`: choose data/backup paths and LAN, existing-proxy, or Internet
  ingress mode; generate configuration and the first operator.
- `punaro up`: initialize a pristine database or start an already-compatible
  schema, wait for readiness, and run a basic doctor check. It refuses an
  existing schema that needs migration and directs the operator to
  `punaro update`; raw `docker compose up` never migrates either, and
  `punarod` fails readiness on schema mismatch.
- `punaro client add --name NAME`: show the proposed effective grants, then
  issue one single-use enrollment code after confirmation.
- `punaro status` / `punaro doctor`: report core and optional capabilities.

Internet mode fails closed without TLS at the ingress. LAN-only plaintext HTTP
may be enabled explicitly for a trusted private or link-local network with a
clear warning and address validation; the default bind remains loopback or an
internal container network.

### Authorization

Authorization is enforced by `punarod` for every operation. Friendly names,
paths, endpoint labels, memory text, and caller-provided project identifiers are
never proof of authority.

Initial capabilities are intentionally small:

- Project: discover, create, read, write, attach-unclaimed identity, administer.
- Conversation: send, receive, administer.
- Memory: search/read, propose, write, administer/purge.
- Attachment: upload, download, delete.

Enrollment uses understandable role templates rather than a capability
ceremony. The default `trusted-agent` template grants project creation,
unclaimed-identity attachment, and non-administrative mail, attachment, and
memory read/write access to operator-selected projects. A created project gives
the client ordinary write membership while the installation owner retains
administration. `--all-projects` is an explicit dynamic grant covering current
and future projects in a trusted personal installation. Owner/admin, project
merge or membership administration, purge, and backup/restore remain separate
roles or grants. The CLI prints the expanded grants and target projects before
creating the enrollment code.

Application queries include explicit authorized scope predicates. PostgreSQL
row-level security is optional defense-in-depth, not a product requirement.

### Remote MCP

Remote MCP is a separate adapter over the same authoritative service. It uses
the current MCP OAuth requirements, short-lived scoped access tokens, refresh
rotation where required, and an established authorization implementation.
Default grants are memory search/read/propose; direct write, purge, and broad
administration require explicit operator grants.

## PostgreSQL layout

One PostgreSQL cluster is the authoritative transaction and backup boundary.
Schemas and roles isolate workloads without losing cross-domain transactions:

- `auth`: devices, principals, capability grants, token hashes.
- `relay`: projects, endpoints, conversations, messages, deliveries, leases,
  idempotency.
- `attachment`: uploads, artifacts, recipients, lifecycle, quotas.
- `brain`: scopes, memory items, revisions, chunks, proposals, sources, edges,
  usage.
- `jobs`: transactional outbox, worker leases, retries, change sequence.
- `audit`: content-free security and administrative events.

Separate connection pools and timeouts prevent indexing or consolidation from
starving message delivery. The application role is not the schema owner and
cannot perform schema changes during normal requests.

Schema migration uses a PostgreSQL advisory lock and a recorded compatibility
version. Ordinary migrations follow expand/contract compatibility. Destructive
or large migrations require an explicit migration job and a verified backup.

### Resource isolation and ceilings

The server publishes configurable hard ceilings with safe defaults for:

- Request bytes, JSON nesting/field sizes, page size, and response bytes.
- Concurrent requests and sustained request rate per device.
- Search query length, candidate/result count, context budget, and SQL timeout.
- Per-project and global mail backlog and memory/evidence growth.
- Job queue depth, attempts, execution time, and retained terminal failures.
- Audit-event retention and maintenance batch size.
- Attachment upload size, concurrent uploads, and storage quotas.

Mail has a reserved PostgreSQL connection budget and bounded statement timeout.
Brain search/indexing and consolidation use separate smaller pools. When limits
are reached, optional work is shed with actionable `429` or `503` responses
before mail delivery is starved. Limits are correctness and availability
controls, not hostile-tenant billing machinery.

## Project identity and scope upgrades

The Git remote is a project identity, not the database primary key.

`projects` use opaque server-assigned IDs. `project_identities` attach one or
more verified locators:

- Local Git installation identity.
- Normalized Git remote alias.
- Explicit operator alias.
- Non-Git local workspace registration.

A local Git repository may store its assigned project ID in local Git config,
shared through the repository's common Git directory but never committed.
The Punaro client also maintains a recoverable local mapping. Non-Git projects
use the client registry and an explicit relink flow after moves.

When a remote appears:

1. The client strips credentials, lowercases the host, normalizes only
   well-understood syntax such as a trailing `.git`, and preserves path case for
   hosts whose repository semantics are unknown.
2. A caller with `project.identity.attach-unclaimed` may attach a currently
   unclaimed locator to a project it can write. The locator is uniquely claimed
   transactionally.
3. If the locator is new, the existing project is upgraded in place and no
   memory rows move.
4. If it belongs to another project, attachment is rejected unless the caller
   has `project.administer` for both projects and requests a merge preview bound
   to the exact identity, ACL, and content/resource generations of both
   projects. The content generation advances on relevant create, move, delete,
   proposal, conversation, memory, and grant-affecting changes.
5. Approval pauses writes to both projects, locks the project rows in
   deterministic ID order, rechecks all three generations, resolves declared
   logical-key conflicts, and performs one bounded transactional merge.
6. The old project ID remains a permanent lookup alias for stale clients. It is
   not part of a redirect graph, does not receive new rows, and never grants
   access by itself.

The preview includes memory counts, conversations, pending proposals, newly
authorized principals, private records that remain private, and conflicts.
Memberships are not unioned automatically: source data becomes visible to the
existing canonical project membership identified in the preview, while
agent-private records retain their narrower grants. Attaching a remote never
grants the caller or another client new access. A changed identity, ACL, or
content generation invalidates the preview and requires another review.

## Mail relay

The current durable mail semantics remain requirements after PostgreSQL
migration:

- Immutable messages with stable IDs.
- Transactional per-conversation sequence assignment.
- At-least-once delivery with durable recipient deduplication.
- Bounded leases with generation/fencing.
- Idempotent conditional acknowledgment.
- No cursor advancement across an unacknowledged gap.
- Payload-free, lossy wake notifications.
- Explicit conversation membership and endpoint ownership.

PostgreSQL migration is not allowed to weaken these invariants. Exact
duplicate, retry, stale-lease, crash/restart, detach/reattach, and cursor-gap
tests must be ported before cutover.

## Trusted-relay attachments

The production attachment design becomes a conventional authenticated private
file service. The server may read stored attachment bytes; confidentiality from
the operator is not promised.

Lifecycle:

1. Authorized sender creates a `RESERVED` upload with scope, bounded size,
   display name, media type, digest, and idempotency key.
2. The server reserves bounded capacity and returns an opaque upload ID.
3. The client streams bytes over authenticated HTTPS without holding a database
   transaction open.
4. The server writes to a private staging file and verifies exact size/digest.
5. Completion fsyncs the file, renames it within the same filesystem to a new
   immutable final path, and fsyncs the containing directory.
6. A short conditional PostgreSQL transaction reauthorizes the sender and
   publishes `READY` metadata, but the artifact remains unshared. Only `READY`
   artifacts are eligible for download.
7. The transaction that appends the referencing message creates attachment
   recipient links from that message's recipient snapshot. Membership additions
   or removals during upload therefore neither broaden nor retain access through
   a stale reservation; a sender revoked before completion cannot publish.
8. A final blob without `READY` metadata is a grace-period orphan. `READY`
   metadata without its blob is `CORRUPT`, never a partial download. The
   reconciler reports and handles both states without inventing cross-store
   atomicity.
9. Authorized recipients download through an authenticated bounded stream.
10. The client verifies the digest and finalizes beneath a configured safe
   download root using atomic no-replace behavior. Interactive approval is
   needed only for a requested destination outside that root.
11. Delete first hides/tombstones metadata, then removes the immutable blob
    asynchronously after the backup/restore safety window.

Required properties:

- Partial uploads are never downloadable.
- Artifact IDs are random and do not provide authorization.
- No unauthenticated public URLs.
- No server-side URL fetching or execution.
- Display names never become server or client paths without safe handling.
- Upload, per-project, per-device, and total storage quotas.
- Bounded abandoned-upload reaping and explicit retention policy.
- Delete authorization and idempotency.
- Content hashes provide integrity, not global cross-scope existence oracles.
- No cross-artifact blob deduplication initially.

Initial blob storage is a private local volume using opaque per-artifact final
paths; the verified digest lives in authorized metadata. An object-store
interface may be added after real scale or operational need is demonstrated.

## Big Brain memory

### Memory layers

Big Brain stores two related forms:

1. Curated memories: decisions, preferences, project facts, procedures,
   feedback, and references suitable for compact prompt context.
2. Evidence records: immutable or append-only source excerpts and references
   preserving where curated knowledge came from.

Raw conversations, mail, and attachments are not ingested wholesale by
default. Evidence ingestion is explicit per project/source with bounded size,
retention, and cost visibility. Promotion of evidence into curated memory is a
separate action or proposal.

Canonical memory content is revisioned and document-shaped. The relational
schema governs identity, scope, authorization, provenance, concurrency, and
jobs; it does not attempt to normalize human knowledge into a mandatory graph.

Core records:

- `memory_items`: stable ID, brain, scope, kind, state, trust, current revision.
- `memory_revisions`: append-only JSONB document, content hash, synchronously
  generated weighted full-text vector, author, provenance, timestamps.
- `memory_chunks`: revision/chunk identity, embedding generation/model,
  embedding, index state.
- `memory_sources`: message, session, attachment, import, or external source
  references.
- `memory_edges`: structural provenance such as `derived_from`, plus
  revision-bound optional semantic claims such as `supports`, `contradicts`,
  and `supersedes`.
- `memory_proposals`: staged create/update/merge/split/archive actions bound to
  exact source revisions.
- `memory_usage`: recall count and last-recalled time.

Semantic similarity and inferred relationships are soft derived data and may
be rebuilt. Semantic edges never become mandatory graph consistency. Titles
are not globally unique. An optional logical key may be unique inside a scope
when the product knows that the record represents one mutable fact.

### Memory tools/API

The native versioned API provides bounded operations equivalent to:

- `memory_create`
- `memory_search`
- `memory_get`
- `memory_update`
- `memory_delete`
- `memory_propose`
- proposal approve/reject
- bounded project brief/context retrieval
- change fetch by monotonic sequence

Creates and mutations use idempotency keys. The standard invariant is
`(principal, operation, key) -> request hash, status, result/resource`: an exact
retry returns the original result, while reuse with a changed body, operation,
or principal conflicts. Retention exceeds the supported retry window. Reads
expose a revision/ETag. Updates, proposal approval, archive, and delete use
compare-and-swap. `memory_delete` removes canonical content and derived indexes
while retaining only a content-free audit tombstone; automated retention uses
a separate reversible archive operation.

### Retrieval

Retrieval is authorization-filtered before ranking and uses:

1. Exact logical/title matches.
2. Weighted PostgreSQL full-text search over title, summary, keywords, and body.
3. Exact pgvector similarity initially.
4. Reciprocal-rank fusion of lexical and semantic candidates.
5. Trust, current/superseded state, and bounded recency/usage adjustments.

Search returns bounded summaries, authorized source snippets, provenance, and
IDs. Full bodies require `memory_get`. A copied excerpt promoted into a target
memory is governed by the target scope. A live snippet or detailed reference to
a message, attachment, or session requires independent authorization to that
source; otherwise the API returns an opaque/redacted source reference.

Prompt context contains pinned core memories, a small project brief, and
query-relevant summaries under a strict character or token budget. It is framed
as untrusted data, but framing cannot prevent model influence. Punaro therefore
keeps routing, authorization, destination paths, URL fetching, secret
resolution, and destructive capabilities outside memory-controlled arguments.
Raw imported/Telegram evidence is never promoted into pinned curated memory
without an explicit proposal or deterministic operator rule. An `op://`
locator is inert metadata, not authority to invoke 1Password.

Approximate vector indexes are added only after corpus benchmarks justify them.
If the embedding worker is unavailable, writes and lexical search continue;
responses report semantic degradation.

### Indexing

Canonical revision commit, synchronous lexical vector, change sequence, and an
embedding job are one PostgreSQL transaction. Lexical search always joins to
`memory_items.current_revision`, so a new revision is immediately searchable
and stale chunks cannot shadow it. A bounded worker:

1. Claims jobs with a lease using `FOR UPDATE SKIP LOCKED`.
2. Re-checks the exact revision and content hash.
3. Chunks and embeds with a pinned, identified model.
4. Stores derived rows only if the revision is still current or intentionally
   retained.
5. Publishes only with the exact current job lease token/generation as well as
   the expected revision/content hash.
6. Retries with bounded backoff and a terminal diagnostic state.

Embedding model changes build a new index generation beside the old one and
record a starting change sequence. Writes after that point are enqueued for the
building generation as well as the active one. The worker replays through a
caught-up watermark and activates the new generation atomically only after
validation. Search remains on the old generation until that switch.

### Secret prevention

Secret scanning is deterministic, best-effort defense against accidental
misuse, not a confidentiality claim.

- Client scans for immediate feedback; server scans authoritatively.
- Create, update, proposal approval, import, consolidation output, and
  attachment-derived text all pass the same guard.
- Indexing cannot start before the authoritative scan succeeds.
- Errors identify the field/rule without echoing the suspected value.
- Logs and audit events never contain the value.
- High-confidence secret values have no model override. An operator may approve
  a narrowly fingerprinted false positive without creating a broad rule that
  weakens future scans.
- 1Password references, environment-variable names, placeholders, and prose
  directing an agent to retrieve a secret just in time are supported.
- Existing records may be rescanned after rule updates and quarantined for
  operator review rather than silently deleted. Quarantine suppresses automatic
  search/prompt injection but keeps the record available to the operator.
- Rejected content never reaches embedding or consolidation providers.

### Maintenance and dreaming

Deterministic maintenance ships first:

- Remove obsolete derived chunks and embeddings.
- Rebuild indexes after model changes.
- Detect exact content duplicates.
- Expire abandoned proposals and explicitly ephemeral evidence.
- Reconcile permanent project lookup aliases and orphaned references.
- Produce bounded archive candidates from policy and usage.
- Verify index/database consistency.

Model-assisted dreaming is optional and later. It processes only changes since
a per-scope checkpoint and may propose:

- Near-duplicate merges.
- Contradiction or supersession links.
- Updating a curated fact from newer evidence.
- Splitting an overloaded memory.
- Promoting repeated evidence into a procedure or preference.
- Refreshing a project brief.

Dream output is a proposal with exact evidence and source revisions. It cannot
silently rewrite human-authored or human-verified memories. CAS prevents stale
approval. Narrow low-risk auto-approval may later be configured for exact
duplicates or agent-private derived summaries. One fenced worker owns a scope's
consolidation run; server load and change volume, not client idleness alone,
trigger work.

## Compose Pi integration

Compose Pi gains a Punaro integration setting with independently reported mail,
attachment, and memory capabilities. Internally memory is a backend choice:

- `Local`: current Compose Pi SQLite memory is authoritative.
- `Punaro`: Big Brain is the sole writable authority.

These are independent corpora, not synchronized replicas. Settings show which
backend is active, when the Local corpus was last active, and the last observed
Punaro timeline/change sequence. Backend-specific semantics are explicit:
Punaro-mode Compose Pi records use a unique logical key derived from normalized
scope/title so current title-matched update behavior remains deterministic,
even though other Big Brain clients may create records with duplicate titles.
Import previews expose collisions. In Punaro mode explicit delete remains a hard
content delete matching Compose Pi; archive/restore is a distinct maintenance
surface.

### Enabling Punaro memory

1. Authenticate/enroll the Punaro client without exposing its credential to an
   agent prompt.
2. Resolve or create the current project scope.
3. Preview local global/workspace memories and their destination scopes.
4. Persist a local backend transition `IMPORTING(batch_id, snapshot_revision)`
   and take a stable local snapshot. Import identities are namespaced by Compose
   Pi installation UUID, local memory ID, and source revision.
5. Import selected records with a manifest of expected IDs/count/hash and
   preserved provenance. Exact retries are idempotent; conflicting incremental
   re-imports become proposals rather than overwrites.
6. Briefly freeze local memory mutations, import any delta since the snapshot,
   and verify the server manifest.
7. Store the completed checkpoint and switch `IMPORTING` to `PUNARO` in one
   local SQLite transaction. A crash before this point resumes the same batch;
   a crash after it cannot return to writable Local mode accidentally.

Existing memory tools, proposal UI, and Settings components are reused where
their semantics match. Labels and actions that differ between local and shared
memory must be explicit rather than hidden behind identical UI.

### Failure and disable behavior

- Punaro network failure never silently switches to writable local memory.
- V1 does not queue offline Big Brain creates or updates. Mutations return a
  clear retryable-unavailable result; durable queued memory writes are added
  only after demonstrated need.
- A content-bounded local brief cache is keyed by project, server timeline, and
  change sequence. Prompt send uses a short remote timeout and proceeds with a
  visibly stale cache or no memory context when Punaro is unavailable.
- Disabling Punaro returns to the preserved independent local database only
  after any in-flight operation is finished or explicitly abandoned. No
  Punaro-bound operation may replay after disable.
- Re-enabling does not silently import Local changes made while Punaro was off;
  the user starts an incremental import preview.
- Copying shared Punaro memories into local storage is an explicit scoped export,
  not an automatic side effect of disabling integration.

## Container delivery and operations

### Release artifacts

Each release publishes:

- Semantically versioned, immutable image digests.
- Linux `amd64` and `arm64` images.
- A pinned compatible production Compose bundle.
- SBOM and automated vulnerability scan.
- Database compatibility and rollback floor.
- Migration, backup, and operator release notes.

Production examples never use an unpinned `latest` tag. The PostgreSQL major is
pinned and upgraded by an explicit procedure; a Punaro image update must not
silently perform a PostgreSQL major upgrade.

Image signing/provenance may be added when the supported updater verifies it;
publishing an unused signature is not a release gate. Docker Compose v2 on
Linux is the initial supported runtime. Podman, NAS platforms, and orchestrators
remain best-effort until their filesystem/network contracts have smoke tests.

### Supported update and rollback

`punaro update` is the one supported happy path:

1. Preflight disk capacity, current health, target manifest compatibility, and
   target PostgreSQL major.
2. Pull and locally preflight the digest-pinned release bundle while preserving
   the previous image lock.
3. Create a durable update transaction ID and acquire the database maintenance
   fence. Every application mutation transaction participates in this fence;
   acquisition therefore drains committed in-flight mutations before the gate
   closes, and later mutations receive an explicit retryable maintenance error
   before acknowledgment.
4. Stop every writer container. While the fence remains active, create and
   verify a named pre-update backup, then record a marker binding that backup,
   source schema, target release, and update transaction ID. A backup failure
   permits `punaro update --abort` to restart the old version and clear the
   fence because migration has not begun.
5. Run a one-shot migrator container only after validating that marker, using a
   schema-owner credential unavailable to the normal `punarod` role.
6. Start the new image in fenced read-only maintenance mode, wait for deep
   readiness, and run a non-mutating `punaro doctor`.
7. Atomically mark the update transaction committed and release the write fence.

The update state and owner are durable in PostgreSQL. Rerunning `punaro update`
detects an unfinished transaction and resumes or explains the valid recovery
choice rather than starting another. Before migration, abort may return to the
old version. After migration starts, recovery remains fenced and follows the
declared compatible-image rollback or verified-backup restore path; that path
must also pass readiness and doctor before committing the recovery transaction
and reopening writes. A crashed updater can leave a visible maintenance outage,
but cannot silently drop the fence or allow the old and new versions to write.

An image-only rollback is supported only while the current schema remains
compatible with the previous image. After an incompatible migration, rollback
means restoring the named pre-update backup into a stopped or new stack. The
tool explains which case applies; the plan does not promise rolling upgrades or
zero downtime for a self-hosted single-node service.

### State and secrets

- Containers are disposable; database and blob volumes are external state.
- Database, blob, or secret volumes are never baked into or committed with an
  image.
- Container secrets or read-only credential files are preferred over ordinary
  environment values visible through inspection.
- The only Internet ingress is the configured tunnel/reverse proxy.
- Same-host container traffic may use a private network without application
  TLS. Direct LAN and Internet traffic use authenticated ingress; Internet
  ingress always uses TLS.

### Health

- Liveness: process event loop is alive.
- Core readiness: schema, database, auth material, and mail path are usable.
- Attachment readiness: blob store and quotas are usable.
- Brain readiness: canonical and lexical memory paths are usable.
- Semantic status: ready or explicitly degraded without failing core readiness.
- Consolidation status: informational; never gates mail.

### Backup and restore

Finalized blobs are immutable and physical blob garbage collection is delayed
beyond the backup retention/safety window. `punaro backup` opens a PostgreSQL
repeatable-read transaction, exports its snapshot, runs `pg_dump` against that
snapshot, and queries the `READY` blob manifest in the same snapshot. It keeps
the exporting transaction open until both are complete, and blocks physical
blob GC until the subsequent size/hash-verified blob copy finishes. Writes
after the snapshot are simply outside that restore point. A local mounted
backup directory with modest retention is the default; off-host/NAS copying is
recommended but does not block startup.

Supported commands include `backup`, `backup list`, `backup verify`, and
`restore --into-new-stack`. Restore validates the manifest before making the
new stack ready, preserves the installation identity, rotates its timeline, and
generates target deployment configuration rather than overwriting the host's
existing configuration. The backup includes Punaro-owned database credentials
and generated configuration required by the restored stack. Host-managed TLS,
reverse-proxy or tunnel configuration and third-party Telegram/OAuth credentials
are listed as external dependencies and must be supplied again or re-enrolled
before those optional gateways report ready. Maintainer release gates exercise
clean-stack restore; operator restore drills are strongly recommended rather
than forced during installation.

Every server state includes an installation ID and a timeline ID alongside its
monotonic change sequence. Restoring a backup rotates the timeline ID. Clients
that observe a new timeline invalidate later cursors/caches, enumerate
authoritative state, and reconsider pending operations using stable
client-generated IDs. A cursor from a future pre-restore timeline is never
silently accepted.

## Migration from current Punaro

Migration is staged; no long-lived dual authority is allowed.

### Phase A: direction and compatibility

- Accept this plan and update `DESIGN.md` to the trusted-relay threat model.
- Mark attachment v2/v3 as superseded for future production direction while
  keeping existing code and evidence intact.
- Define PostgreSQL schema/version conventions and store interfaces.
- Add production OCI/Compose contracts without changing active routing.

### Phase B: PostgreSQL foundation

- Add PostgreSQL-backed auth, idempotency, audit, job, and project primitives.
- Implement bounded migrations and compatibility checks.
- Add backup/restore and container upgrade drills.
- Add host-local first-owner bootstrap and single-use client enrollment.
- Provide a staged operator-approved exchange from existing enrolled Ed25519
  machine identities to new device credentials; disable legacy auth only after
  every intended client has migrated or been explicitly retired.
- Preserve current SQLite implementation for parity testing only.

### Phase C: mail migration

- Implement the relay store against PostgreSQL test-first.
- Run the complete queue/auth/lease/retry/adversarial suite against both stores.
- Build a one-shot SQLite-to-PostgreSQL migration tool with dry-run, counts,
  constraints, sequence/cursor verification, and resumable idempotent import.
- Quiesce and expire every active lease by clearing its holder and incrementing
  its generation while preserving unacknowledged deliveries/cursors. Record a
  source fingerprint and destination migration epoch, migrate, and verify.
- Rollback to SQLite is allowed only before the cutover barrier reopens writes.
  After PostgreSQL accepts new work, the old file is a protected forensic/source
  artifact, not a rollback database; recovery uses PostgreSQL backup or forward
  repair.
- Do not use ongoing dual writes.

### Phase D: trusted attachments

- Specify and test the new bounded upload/download lifecycle.
- Implement server blob storage and PostgreSQL metadata.
- Implement native client sender/receiver recovery and safe finalization.
- Run crash, quota, authorization, partial upload, path, digest, and reaper tests.
- Retire legacy attachment production switches only after the new path passes
  release gates.

### Phase E: Big Brain lexical foundation

- Add project/scopes, memory revisions, provenance, proposals, CAS, secret
  scanning, full-text search, prompt briefs, and deterministic maintenance.
- Add native local MCP/CLI tools.
- Prove concurrent multi-agent CRUD/search and authorization isolation.

### Phase F: Compose Pi integration

- Introduce backend selection without changing local behavior when disabled.
- Add import preview/checkpoint, project identity upgrade, failure UX, and
  explicit export.
- Run local/Punaro mode, toggle, outage, conflict, and migration E2E tests.

### Phase G: semantic retrieval

- Add pgvector, the bounded embedding worker, model versioning, hybrid ranking,
  degradation, and retrieval evaluations.
- Add approximate indexing only if measured scale requires it.

### Phase H: optional dreaming and remote MCP

- Add proposal-only incremental consolidation with explicit policy and budget.
- Add the OAuth-protected remote MCP gateway and scope grants.
- Test both features independently; neither is required for core mail/memory.

## Required adversarial and failure testing

The testing standard is realistic for a self-hosted collaboration service. It
must aggressively test likely failures and authorization mistakes without
inventing nation-state or hostile-cloud-tenant requirements outside the threat
model.

### Identity and authorization

- Pristine deployment rejects public enrollment before host-local bootstrap.
- Single-use enrollment code: wrong client, expiry, replay, concurrent redeem,
  and successful transition to permanent device credential.
- `trusted-agent` template expansion, selected-project versus `--all-projects`
  grants including future-project behavior, printed confirmation, and proof
  that admin/purge are not implied.
- Create a new local project, later attach its first unclaimed Git remote
  without operator intervention, and require project admin plus preview when
  the remote is already claimed by another project.
- Unknown, malformed, expired, and revoked credentials.
- Revocation invalidates cached auth and long-lived notification sessions within
  the documented bound.
- Credential for machine A attempting machine B/project B operations.
- Removed project/conversation member retaining stale client state.
- Friendly label or guessed opaque ID used as claimed authority.
- Remote MCP token with insufficient or wrong resource scope.
- Direct-origin/public-port bypass attempts when the selected reference ingress
  profile promises a closed origin.
- Redaction verification for credentials and auth headers in logs/errors.

### Mail correctness

- Duplicate every mutation and lose every response boundary.
- Crash before/after append, lease, injection, and acknowledgment.
- Concurrent senders assigning conversation sequence.
- Stale lease token/generation and two consumers for one endpoint.
- Cursor gap, detach/reattach, revocation while leased, and backlog recovery.
- Database restart, slow transaction, pool exhaustion, and disk-full behavior.

### Attachments

- Unauthorized upload/download/delete and guessed IDs.
- Partial, oversized, undersized, digest-mismatched, duplicate, interrupted,
  and abandoned uploads.
- Kill after staged-file fsync, final rename, directory fsync, `READY` metadata
  commit, delete tombstone, and physical GC; verify visibility and reconciliation
  at each boundary.
- Filename traversal, absolute paths, reserved names, symlinks, and existing
  destination files on every supported client OS.
- Add/remove a conversation member during upload, revoke the sender before
  completion, and verify that only message-append recipient snapshots create
  download grants.
- Quota races, concurrent reaping/download, artifact deletion, and orphan
  reconciliation.
- Blob volume unavailable, read-only, full, or restored out of sync.
- Restore metadata newer than the blob backup and vice versa; `READY` without a
  verified blob is never downloadable.

### Memory and concurrency

- Concurrent creates, CAS updates, proposal approve/reject, archive, and purge.
- Stale proposal targeting a newer memory revision.
- Concurrent remote-locator claims; ACL, identity, or source/canonical content
  change after merge preview; deterministic merge locking; private-record
  preservation; and old-ID alias.
- Unauthorized scopes excluded before ranking, counts, snippets, and full get.
- Memory readable while its live message/attachment source is unauthorized;
  copied target-scope evidence remains readable and the live reference is
  redacted.
- Search while embeddings are pending, failed, stale, or being reindexed.
- Create/update/delete during embedding-generation rebuild; caught-up watermark
  activation; worker crash/lease expiry and stale result publication.
- Deterministic maintenance racing with active recall/usage recording.
- Dream proposal evidence changing before approval.
- Compose mutation during import; crash after server import but before local
  backend switch; import retry/partial import; local-project-to-remote conflict;
  disable/re-enable after both independent corpora changed.
- Same idempotency key with changed body, operation, or principal.
- Restore while clients retain later timeline cursors, dedupe state, and cached
  prompt briefs.

### Untrusted content and secrets

- Messages/memories attempting to issue routing, authorization, URL-fetch, or
  execution instructions.
- Malicious memory can influence model text but cannot supply server-generated
  scope/destination arguments, trigger URL fetches, invoke `op read`, or bypass
  destructive-operation authorization.
- Secret patterns in every write/import/approval/consolidation path.
- Placeholders, environment references, and 1Password locators accepted without
  weakening detection of real values.
- Error/log/audit output never echoing rejected secret material.
- Oversized, deeply nested, malformed, and unknown JSON fields.

### Containers and operations

- Start with missing/corrupt config, secrets, schema, volume, and database.
- Read-only root filesystem, non-root UID, dropped capabilities, and no-new-
  privileges verified in the built image.
- Only intended ingress reachable; PostgreSQL/blob services not host-published.
- Upgrade, failed migration, compatible rollback, incompatible downgrade, and
  PostgreSQL major-version refusal.
- `punaro up` and raw `docker compose up` refuse a required migration; the
  migrator rejects a missing, stale, or mismatched backup/upgrade marker.
- Attempt mutations before pull, during the maintenance fence, after the backup,
  and across a failed incompatible migration; every acknowledged mutation must
  exist after rollback, while fenced requests fail explicitly and may retry.
- Kill the updater or writer containers after fence acquisition, writer stop,
  backup, migration, new-server start, and doctor failure. The durable fence
  survives restart, rerun resumes the same transaction, and no mutation is
  acknowledged until update or recovery commit releases it.
- First install in LAN, existing-proxy, and Internet modes; unsafe public bind
  rejected in Internet mode, and trusted-LAN HTTP rejected for publicly routable
  bind/source addresses.
- Backup during concurrent upload/delete, dump/manifest snapshot agreement,
  restore into a clean stack, external-dependency prompts, and restored service
  E2E.
- Mail remains available when semantic or dreaming workers fail or overload.
- `amd64` and `arm64` image smoke tests.

### UX and pragmatic-security review

- Enrollment, revocation, project merge, import, update, backup, and rollback
  can be completed from documented happy paths without editing database rows.
- Routine send/upload/search/write does not require interactive approvals.
- Security errors are actionable without disclosing protected content.
- Degraded/offline state does not create silent data divergence.
- Every remaining high-friction control identifies a realistic threat that
  justifies it under this document's threat model.

## Milestone completion gates

Each implementation milestone requires:

1. Focused failing tests before behavior changes.
2. Relevant adversarial/failure tests above.
3. Full Punaro quality gate.
4. Schema/API documentation and upgrade/rollback notes.
5. Container image scan and deployment smoke test when the milestone changes a
   server artifact.
6. Explicit residual risks and intentionally deferred work.

The maintained Internet reference profile additionally requires release
evidence for direct-origin bypass, credential revocation, rate limiting,
clean-stack backup restore, and malformed-input drills. Individual operators
run `doctor` and backup verification; they are encouraged, not forced, to repeat
the full maintainer restore suite before first use.

## Review questions

Adversarial reviewers should answer:

1. Does the plan accidentally optimize for a hostile SaaS or high-confidentiality
   environment that is explicitly out of scope?
2. Does any simplification permit likely unauthorized access, cross-project
   leakage, corruption, or unrecoverable state?
3. Are PostgreSQL transactions, idempotency, CAS, and worker fencing sufficient
   at every cross-domain boundary?
4. Can project identity upgrade or Compose Pi backend switching create split
   authority or surprising disclosure?
5. Can attachment lifecycle crashes produce visible partial files, orphaned
   metadata, or destructive client writes?
6. Can search, indexing, or dreaming leak unauthorized content or silently
   corrupt canonical memory?
7. Is the container update/rollback/backup story genuinely operable by a
   self-hosting user?
8. Which controls remain too complex for the realistic threat they mitigate?
9. Which likely, mundane threats are still under-protected?

## Adversarial review record

On 2026-07-19 three independent subagents reviewed the draft from architecture
and consistency, pragmatic security, and self-hosted operations/UX
perspectives. Every reviewer received this explicit constraint:

> We are not building a SaaS that hosts confidential government data. Be
> realistic; overengineering or security friction without proportionate benefit
> is a design failure.

No reviewer found that PostgreSQL, the trusted-server threat model, container
delivery, or the phased Big Brain direction should be abandoned. Material
findings and resolutions follow.

| ID | Finding | Resolution |
| --- | --- | --- |
| AR-1 / SR-2 | Filesystem rename and PostgreSQL publication cannot be one atomic commit. | Replaced with explicit `RESERVED`/`READY`/`CORRUPT` lifecycle, fsync/rename ordering, visibility boundary, orphan reconciliation, tombstone-first deletion, and restore-skew tests. |
| AR-2 / OR-2 | Compose Pi import/switch lacked a linearization point and could create two writable authorities. | Added persisted `LOCAL`/`IMPORTING`/`PUNARO` transition, stable manifest/delta import, brief mutation freeze, one-transaction local switch, independent-corpus semantics, and no offline writes in v1. |
| SR-1 / OR-3 | Initial enrollment had no trust root and risked public first-user-wins takeover. | Made first owner host-local only; added named, short-lived, single-use client enrollment and pristine-public-bootstrap tests. |
| AR-3 / SR-3 / OR-6 | Project collision/redirect semantics could disclose data or create permanent graph maintenance. | Common upgrade attaches remote in place. Collision uses generation-bound preview, no membership union, deterministic locks, bounded one-shot merge, private-grant preservation, and a permanent lookup alias rather than redirect graph/background rewriting. |
| AR-4 | SQLite was incorrectly described as a post-cutover rollback source; leases and legacy auth migration were undefined. | SQLite rollback ends before writes reopen. Active leases are invalidated with generation advance, old SQLite becomes forensic evidence, and existing identities receive a staged token-exchange path. |
| AR-5 | Asynchronous chunking could delay lexical visibility; embedding rebuild and worker locks lacked fencing. | Lexical vector is synchronous on the canonical revision; search joins current revision; embedding jobs use lease generations; rebuilds use start sequence, dual enqueue/replay, caught-up watermark, then atomic activation. |
| AR-6 / OR-8 | Compose Pi local and Big Brain title/delete semantics were incompatible. | Added a Compose Pi logical-key compatibility profile, collision preview, explicit hard delete for Compose Pi/Big Brain, and separate maintenance archive semantics. |
| AR-7 | Memory source snippets could leak a source the caller no longer has permission to read. | Target-scope copied evidence and live source references now have distinct authorization rules; unauthorized live references are opaque/redacted and tested. |
| AR-8 | Idempotency did not explicitly bind the key to request identity. | Standardized principal/operation/key plus request hash and immutable prior result; changed-body/operation/principal conflicts are required tests. |
| SR-4 | Database restore could rewind a sequence behind cached client cursors. | Added installation/timeline IDs; restore rotates the timeline and clients invalidate future cursors/caches before re-enumeration. |
| SR-5 | “Inert prompt data” overstated what framing can guarantee. | Narrowed the guarantee to control-plane inertness, accepted residual model influence, prohibited memory-controlled authority/destinations/fetch/secret resolution, and added tests. |
| SR-6 | Resource exhaustion controls were aspirations rather than a contract. | Added hard configurable ceilings, mail-reserved connection budget, optional-work load shedding, timeouts, retention, and `429`/`503` behavior. |
| OR-1 | Container update/rollback had no executable migration actor or boundary. | Added `punaro update` preflight, verified backup, pinned pull, short quiescence, one-shot schema-owner migrator, deep readiness, compatibility-aware rollback, and explicit restore requirement. |
| OR-4 | Backup/restore remained vague and potentially burdensome. | Made finalized blobs immutable, delayed GC, added consistent DB/blob manifest backups and supported backup/verify/new-stack restore commands; off-host copies and operator drills are recommended rather than startup gates. |
| OR-5 | Remote prompt briefs could block Compose Pi prompt submission. | Added short timeout and bounded timeline/change-keyed local brief cache; prompt sending proceeds with visibly stale or absent memory context. |
| SR-S1 / OR-7 | Slow token hashing and multiple application images added cost without material benefit. | Chose indexed SHA-256 digest for random 256-bit tokens and one versioned application image with role subcommands; optional services remain Compose profiles. |
| SR-S2 | Image signatures were required without a consuming verifier. | Kept digest pinning, SBOM, and scanning; deferred signing until the supported updater verifies it. |
| SR-S3 | Per-attachment approval would harm routine UX. | Defined a configured safe download root with automatic safe finalization; prompt only outside it. |
| AR-9 | Project-merge approval was not invalidated by content added after preview. | Added a project content/resource generation, bound previews to identity/ACL/content generations, and recheck all three after locking. |
| AR-10 | Long uploads left recipient and revoked-sender semantics ambiguous. | Completion reauthorizes the sender and publishes an unshared artifact; message append grants its recipient snapshot atomically. |
| OR-9 | TLS-only credentials contradicted the explicit trusted-LAN HTTP mode. | Scoped the exception to an operator-enabled mode with validated private/link-local bind and source addresses; public addresses remain TLS-only. |
| OR-10 | `punaro up` appeared able to bypass the backup-gated update transaction. | Limited `up` to pristine or compatible schemas, made raw Compose non-migrating, and bound the migrator to a verified backup/upgrade marker. |
| OR-11 | Database dump and blob manifest lacked one named snapshot boundary; restore configuration was unclear. | Both consume one exported repeatable-read snapshot, GC is fenced through verified blob copy, and restore now distinguishes bundled Punaro configuration from external ingress/third-party dependencies. |
| OR-12 | Client enrollment had capabilities but no usable default grant profile. | Added a printed `trusted-agent` role template for selected projects or explicit `--all-projects`; administrative and purge grants stay separate. |
| OR-13 | The default role still required an operator ceremony to create a project or attach its first Git remote. | Added scoped project creation and unclaimed-identity attachment, made `--all-projects` explicitly cover future projects, and kept claimed-identity merge/membership changes admin-gated. |
| SR-7 | The rollback backup preceded write quiescence, so accepted writes could be lost after an incompatible migration failure. | Pull/preflight now precedes a maintenance fence; in-flight mutations drain or abort before the backup, and the fence remains through backup, marker validation, and migration. |
| OR-14 | The update fence had no durable owner, crash-resume contract, or post-doctor release point. | Added a durable update transaction, participation by every mutation, writer shutdown, read-only new-server validation, resumable recovery, and atomic release only after doctor succeeds. |

Review was iterative. A second pass found AR-9, AR-10, and OR-9 through OR-12;
targeted regression passes then found OR-13, SR-7, and OR-14. All were
incorporated. Final confirmations from the architecture, security, and
operations reviewers reported no remaining P0/P1 issue or threat-model drift.

### Deliberately accepted residual risks

- One PostgreSQL outage affects mail and memory.
- Server/root/trusted-LAN compromise exposes plaintext content.
- An already authorized model may be influenced by malicious content it reads;
  Punaro prevents that content from becoming control-plane authority.
- Read-only caches and previously downloaded files cannot be retracted after
  revocation.
- Temporary orphan blobs are acceptable when bounded, invisible, and reaped.
- Exact vector search may slow before measured scale justifies ANN indexing.
- No HA, hostile-tenant isolation, E2EE, compliance audit, antivirus pipeline,
  or cryptographic non-repudiation is promised.
