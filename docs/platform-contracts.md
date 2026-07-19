# Platform compatibility contracts

Status: accepted Phase A contract. These contracts constrain implementation
slices for the [Punaro pragmatic platform and Big Brain plan](big-brain-plan.md)
without changing the current alpha runtime.

## Compatibility boundary

- PostgreSQL becomes the sole authoritative server database only at the
  explicitly fenced mail cutover. No implementation may run SQLite and
  PostgreSQL as simultaneous writable server authorities.
- Before that barrier, SQLite remains the active relay and PostgreSQL paths are
  dark/selectable parity targets. After the barrier, the old SQLite file is a
  protected migration/forensic source, not a rollback database.
- Existing versioned HTTP routes, Ed25519 identities, and attachment v2/v3
  records are never silently reinterpreted. Auth exchange and attachment
  retirement are explicit independently reviewed migrations.
- Native client SQLite is limited to offline queues, deduplication, crash
  recovery, and explicitly stale read caches. It is not server authority.
- Compose Pi integration is outside the currently authorized Punaro delivery
  scope. The accepted plan retains its future Phase F unchanged. General Punaro
  APIs remain clean, but this program adds no contract solely for Compose Pi.

## PostgreSQL schemas and roles

One PostgreSQL cluster is the transaction and backup boundary. Migrations own
the versioned schemas `auth`, `relay`, `attachment`, `brain`, `jobs`, and
`audit`. Every migration has an immutable ordered version, checksum,
compatibility floor, and descriptive name. A PostgreSQL advisory lock
serializes migration actors. A dirty, missing, newer, or incompatible schema
fails readiness with an actionable content-free diagnostic.

The schema-owner role is available only to an explicit one-shot migrator. The
normal application role cannot create, alter, or drop schema objects. Separate
bounded pools and statement timeouts isolate mail from attachment, brain, and
optional worker load. PostgreSQL and blob services are private and never
host-published by the reference deployment.

Ordinary `punarod` startup and raw `docker compose up` never apply migrations.
The supported `punaro up` wrapper may initialize a pristine schema or start an
already compatible one. Every required upgrade migration goes through the
operator update transaction with its declared backup and rollback boundary.

## Narrow store interfaces

Store boundaries are domain-specific and accept an explicit principal,
operation, and scope. Their queries enforce authorized-scope predicates in the
same transaction as the protected read or mutation; a prior friendly-name,
opaque-ID, or cache lookup is never sufficient. They do not expose raw database
handles and must not grow into one cross-domain god interface.

- Auth store: principals, credentials, grants, enrollment, revocation, and
  replay/session invalidation.
- Project store: opaque projects, identities, memberships, generations, merge
  previews, and lookup aliases.
- Relay store: conversations, immutable append, recipient snapshots,
  deliveries, fenced leases, conditional ack, and contiguous cursors.
- Idempotency store: `(principal, operation, key)` bound to request hash and an
  immutable prior result.
- Attachment store/blob store: reservations, lifecycle metadata, grants,
  quotas, immutable blob operations, tombstones, and reconciliation.
- Brain store: scoped canonical revisions, sources, proposals, derived-index
  state, usage, and change sequences.
- Job/audit stores: fenced bounded work and content-free events.

Each PostgreSQL store must pass the same observable contract suite as the
implementation it replaces where parity is required. Transactions stay inside
one store when possible; cross-domain atomic operations are explicit service
methods whose interface documents the shared transaction boundary.

### Implemented dark control-plane primitives

Schema version 3 is the minimum for the current PostgreSQL opt-in. Version 2 adds
opaque principals and projects, active capability grants with exactly one of
installation, selected-project, or dynamic all-project scope, generic
idempotency, closed audit events, and one transactional work/outbox table.
`project.discover` is never installation-wide: it is selected-project or
dynamic-all scoped, while only `project.create` is currently installation
scoped. A dynamic grant applies to current and future projects but still
requires the queried opaque project to exist.

Grant and revoke mutations carry an explicit acting principal and lock its
active administration grant in the same transaction. Exact-project
`project.administer` can mutate grants only for that project; dynamic
all-project `project.administer` can mutate selected-project, installation, and
all-project grants. `project.create`, subject identifiers, and requested scopes
never authorize grant administration.

Idempotency keys are globally unique UUIDs bound to principal, operation, and a
SHA-256 request hash. Only the hash and a bounded immutable JSON outcome are
stored; the request body is not. Exact concurrent and lost-response retries
return the first outcome. Reusing a key with another body, operation, or
principal returns one content-free conflict.

The work table is both transactional outbox and worker queue until a real
delivery destination requires separate fan-out. Database constraints and a
locked capacity counter bound payload size, depth, attempts, and state. Claims
use `FOR UPDATE SKIP LOCKED`, database-time expiry, a fresh token, and an
increasing generation. Completion or retry requires the exact unexpired fence;
the holder must also remain active and authorized for the job project. Expired
final attempts become terminal failures independently of caller authorization,
so dead rows cannot pin queue capacity. Terminal and audit pruning is limited
to bounded security-definer functions. Audit rows contain only closed
action/outcome/target classes, opaque IDs, sequence, and time—never arbitrary
details.

Queue scheduling is a bounded delay from PostgreSQL time, never an
application-clock timestamp. Each claimable job kind maps to a server-selected
capability and target shape; enqueue rejects unknown kinds and missing required
project IDs. Only an active principal holding that capability for the opaque job
project can receive its payload and lease fence. Unknown kinds, disabled
principals, and unauthorized holders receive no lease.

Enqueue, completion, retry/failure, and exhausted-lease terminalization append
closed, content-free job audit events in the same transaction as the queue
state change. Claim locks the exact active principal/grant evidence used to
authorize the lease, so concurrent disablement or revocation cannot commit
between authorization and lease publication. A bounded `SKIP LOCKED`
pre-candidate batch first reserves disjoint job rows, then locks authorization
evidence only for those projects instead of unrelated grants held by the worker.

Version 3 adds one schema-owner-only installation-owner row; bounded pending
enrollments with digest-only codes and immutable grant expansions; digest-only
device credentials with expiry, last-use, short-lived retry-recoverable rotation codes, revocation, and
generation fences; and a content-free intended-Ed25519-machine inventory. The
application role can read but cannot create ownership or enrollment plans. It
can consume only the fixed redemption columns, insert a credential with its
server-constrained defaults, and coalesce `last_used_at`; it cannot rotate or
revoke credentials. Host-local administration uses a direct `punaro_owner`
connection and is not exposed as an HTTP route.

The `trusted-agent` template contains installation `project.create`; selected
or explicit dynamic-all project discover/read/write and attach-unclaimed;
conversation send/receive; memory search/read/propose/write; and attachment
upload/download. It excludes attachment delete, every administer/purge
capability, merge/membership administration, backup, and restore.

## Server invariants

- At-least-once mail delivery, immutable message IDs, operation-bound
  idempotency, recipient leases with generation/token fencing, conditional
  acknowledgment, and no cursor advancement across an unacknowledged gap.
- Authorization is server-side on every lookup and mutation. Friendly names,
  paths, opaque IDs, prompt content, and caller-supplied scopes are not proof of
  authority.
- Installation ID, timeline ID, and monotonic change sequence accompany server
  state. Restore rotates the timeline so future cached cursors are rejected.
- Canonical memory revisions and provenance are source data. Lexical vectors,
  embeddings, summaries, and inferred relationships are derived and
  rebuildable.
- Attachment metadata never claims filesystem/database atomicity. Only READY
  metadata backed by a verified immutable blob is downloadable.
- Hard ceilings bound requests, pages, queues, jobs, attachments, search, and
  retention. Optional work sheds load before mail is starved.
- Logs, errors, metrics, and audit events contain no credentials, auth headers,
  message bodies, raw Telegram content, rejected secret material, or memory
  bodies.

## OCI and Compose contract

The release publishes one semantically versioned, digest-addressable Punaro
application image for Linux amd64 and arm64. Role subcommands cover server,
worker, gateway, migration, administration, and supported backup operations.
An SBOM, vulnerability scan, database compatibility range, rollback floor,
Compose bundle, and migration/backup release notes accompany it. `latest` is
not a production reference; PostgreSQL major upgrades are always explicit.

The default Compose profile runs only `punarod` and pinned PostgreSQL with
private persistent database and blob volumes. Brain worker, Telegram, remote
MCP, Cloudflare ingress, and scheduled backup are opt-in profiles. Containers
run as non-root with read-only roots, all capabilities dropped,
`no-new-privileges`, bounded temporary filesystems, and no Docker socket.

The default Dockerfile and Compose file remain the alpha build/run baseline.
M-1 adds an explicit `punaro-migrate` image command and a separate, ephemeral
pgvector Compose stack solely for substrate integration tests. PostgreSQL is
disabled by default, the relay continues to use SQLite, and the integration
stack has a private network with no published database port. Later slices may
add the production bundle only with clean-start,
readiness, backup/restore, migration refusal, port-isolation, multi-arch, SBOM,
and image-scan evidence. Active routing does not change merely because a
PostgreSQL service or image role exists.

## Upgrade and rollback rule

Every slice declares whether it is additive, reversible, or crosses an
authority barrier. Expand/contract changes preserve the documented image
compatibility window. Destructive or large migrations require a verified named
backup and the durable maintenance fence. Before migration begins, abort may
restart the old image. After an incompatible migration begins, recovery stays
fenced and uses a declared compatible image or verified-backup restore; it
never reopens an obsolete writer against newer state.
