# Fleet-global agent configuration

Status: accepted for implementation of GitHub issues
[#210](https://github.com/rock3r/punaro/issues/210)–[#217](https://github.com/rock3r/punaro/issues/217)
plus copy-on-apply shared skills, managed-file marks, and machine-local
addendum/user rehydration. This contract **replaces** the earlier #214
trailer-marker and #215 dest-alias/symlink clauses.

This document is the contract. `DESIGN.md` records the protocol and security
invariants as they land. Binary product releases remain `internal/release`;
this feature is a separate data-only synchronizer.

## Overview

An operator explicitly publishes one immutable Git commit from a configured
source repository. Punaro validates and materializes a content-addressed v1
release **before** changing desired fleet state. Enrolled clients receive a
payload-free WebSocket wake hint, HTTP-fetch the exact release under
server-side authorization, and atomically apply a managed tree on macOS,
Linux, and Windows. Clients never publish. Failed apply keeps last known-good.
Configuration contents never appear in logs, inventory, audit, wake hints,
status, or doctor output.

## Background & Motivation

Punaro already has enrolled machine identity, signed HTTP, payload-free wake
hints (`internal/relay.Notifier`), cross-platform adapters, and content-free
doctor reports. Operators still copy `AGENTS.md` and Agent Skills by hand.
Existing `scripts/install-agent-guidance.sh` is a local installer, not a fleet
synchronizer, and must not become the v1 apply path.

## Goals & Non-Goals

Goals: issues #211–#217 plus:

1. Machine-global `AGENTS.md`/`skills/` **and** project-only trees matched by
   top-level directory names under a configured base path (default `~/src`) or
   an explicit machine-local path override that is never published back.
2. Shared skills defined once under `common/<skill>/`, opted in per project by
   a regular `COMMON` file. Apply copies them into present member projects as
   regular files. They are never written to `~/.agents/skills`.
3. Rehydrate each managed dest from the published file, machine-local addendums
   under `~/punaro/addendums`, and a preserved `<!-- user -->` region.
   `CLAUDE.md` is `AGENTS.md` plus Claude addendum(s), as a regular file. No
   dest symlinks, junctions, or `CLAUDE.md` aliases.

Non-goals: general dotfile sync, arbitrary destinations, executable/plugin
deployment, recursive workspace discovery, bidirectional editing,
client-originated publication, following branches/tags/repo changes, guaranteed
hot reload, provisioning a new relay, checking official `docs/release-evidence/`
boxes from a LAN run.

## Key Decisions

1. **Full commit identity only.** `ParseCommitID` accepts lowercase hex of
   length 40 (SHA-1) or 64 (SHA-256). Branches, tags, `HEAD`, short hashes,
   mixed case, and any `/` are rejected before Git is invoked.
2. **Source repository is operator configuration**, stored in the host-local
   installation, never taken from a client or from the commit contents.
3. **Validate and materialize before desired-state mutation.** Store the
   immutable release bytes, then atomically set the singleton desired row. A
   failed publish leaves the prior desired revision unchanged. Identical retry
   is idempotent. Rollback is `publish` of a previously stored digest's source
   commit (same command).
4. **Layout uses an explicit `projects/` prefix** so project names cannot
   collide with `skills/` or `AGENTS.md`. Matching on the machine is still
   top-level directory names under the base path.
5. **v1 is data only.** `scripts/` files may exist as regular files. Punaro
   never executes them, never records destinations or post-install commands,
   and never treats mode bits as activation.
6. **Reserved live markers are illegal in fleet source** and reserved on disk:
   `<!-- punaro-managed -->`, `<!-- punaro-addendum -->` /
   `<!--/punaro-addendum-->`, `<!-- user -->` / `<!--/user-->`. Punaro creates
   an empty user region if missing and preserves it across
   publish/rollback/reconverge. Unmarked unmanaged dests are collisions.
7. **Operator CLI talks to PostgreSQL via the owner DSN** (same pattern as
   `punaro client add` in `cmd/punaro`). Clients talk to signed HTTP on
   `punarod`. Clients have no publish route.
8. **Wake hints reuse `Notifier` with a reserved topic id `fleet-config`**
   and `sequence` equal to the desired generation. No digest, commit, path, or
   contents. HTTP remains authoritative. Broadcast to every currently
   registered enrolled-machine subscription.
9. **Release bytes live in PostgreSQL `bytea`** under a hard size bound. v1
   volume is small; a separate blob store would add a deployable surface.
10. **Package name `internal/fleetconfig`** so it cannot be confused with
    `internal/release` (signed product artifacts).
11. **Harness projection is a built-in adapter table**, not a plugin runtime.
    Unknown installed harnesses report `unsupported`.
12. **Destinations are always regular files.** Apply never creates dest
    symlinks, junctions, or `CLAUDE.md` aliases. `CLAUDE.md` is composed from
    `AGENTS.md` plus Claude addendum(s). Never overwrite a colliding real file
    that is not already Punaro-managed.

## Source tree layout

A published commit must contain:

```text
AGENTS.md                              # required, machine-global
skills/<skill>/SKILL.md                # optional bounded global skills
skills/<skill>/**                      # optional data files (never executed)
common/<skill>/SKILL.md                # optional shared skill, defined once
common/<skill>/**                      # optional data files (never executed)
projects/<project>/AGENTS.md           # optional project-only
projects/<project>/skills/<skill>/...  # optional private project skills
projects/<project>/skills/<skill>/COMMON  # opt-in to common/<skill>/
```

No other top-level names. No extra files next to `AGENTS.md`. Empty
directories are ignored (not archived). Source still forbids symlinks.

`COMMON` is a regular file whose body is empty or the skill name. It cannot
sit next to a private skill tree. Dangling `COMMON` (no matching
`common/<skill>/`) is rejected. A common skill with no members is valid.
Common skills count once toward the 64 cap.

Project and skill directory names match
`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$` (same shape as `auth.client_installations.machine_id`).

`SKILL.md` must begin with YAML frontmatter containing `name` and
`description`. `name` must equal the parent directory. Additional frontmatter
keys are ignored and not executed.

## Validation

`InspectRoot` uses `Lstat` and never follows links. Reject:

| Condition | Reason |
| --- | --- |
| Absolute path, `\`, NUL, `.`, `..`, empty component | Path escape |
| Path not USTAR-representable (over 255 bytes, or no `/` split with prefix ≤155 and suffix ≤100) | Archive format |
| Duplicate path or case-colliding path | Windows/macOS case folding |
| Symlink, extra hard link (`Nlink > 1` on Unix), device, socket, FIFO, non-regular file | Unsafe file type |
| File larger than 256 KiB | Bound |
| More than 64 skills (global + all projects) | Bound |
| More than 512 files or 4 MiB total | Bound |
| Missing global `AGENTS.md` | Required |
| Global or project `AGENTS.md` contains reserved live markers | Markers are machine-local |
| `SKILL.md` contains reserved live markers | Same |
| Dangling `COMMON` (no `common/<skill>/`) | Opt-in without a definition |
| `COMMON` next to a private skill tree | Mix is illegal |
| Malformed `SKILL.md` frontmatter | Contract |
| UTF-8 invalid or NUL in text files (`AGENTS.md`, `SKILL.md`) | Text contract |
| Executable activation fields, destination lists, or post-install commands in any Punaro-owned metadata | Data only |

`ParseCommitID` is independent of the tree.

## Deterministic materialization

1. Walk validated files, hash each SHA-256.
2. Build a versioned manifest binding source commit, every relative path
   (slash-separated), byte length, content digest, skill count, total bytes.
3. Compute release digest as SHA-256 of the canonical digest plaintext:

   ```text
   fleet-config-v1\n
   <source-commit>\n
   <path>\0<size>\0<file-sha256>\n
   …sorted by path…
   ```

4. Archive as gzip+tar of those files (and their parent directories):
   sorted paths, mode `0644` files / `0755` dirs, uid/gid 0, empty uname/gname,
   mtime unix 0, gzip Name empty, ModTime unix 0, OS = 3 (Unix). Directory
   headers omit a trailing slash so a 100-byte final directory component stays
   inside the USTAR name field.
5. Identical input bytes yield identical archive bytes and digest.

The archive does not include addendum or user text. Manifest `digest` is the release
identity used as the desired-state key.

## Trust boundary

```text
configured repo  --explicit publish COMMIT-->  git object
       |                                         |
       | InspectRoot + Validate + Materialize    |
       v                                         v
 immutable (manifest, archive, digest) stored first
       |
       | atomic desired-state row (generation++)
       v
 enrolled clients: wake hint -> GET desired -> GET archive by digest
       |
       v
 local apply (atomic rename) + last-known-good
```

Changing the repository without `fleet-config publish` causes no fleet change.
A digest not produced by this pipeline is never desired state.

## Operator CLI

Host-local `punaro` commands, owner DSN, installation directory:

```text
punaro fleet-config configure --directory DIR --repository ABSOLUTE_GIT_DIR --yes
punaro fleet-config publish --directory DIR COMMIT
punaro fleet-config publish --directory DIR --yes --confirm-preview-hash HASH COMMIT
punaro fleet-config status --directory DIR
```

`publish` without `--yes` prints a content-free preview (source commit, release
digest, skill count, total bytes, current desired revision/digest/generation)
and a preview hash. `--yes` requires that exact hash, matching `punaro client add`.

Rollback is `publish` of a previously published commit that still exists as a
stored release (or can be rematerialized identically from the configured repo).

Failed materialize or store does not update desired. Retry of the same commit
after success returns the same digest and does not bump generation.

## Data model (PostgreSQL schema `fleet`, migration 058)

```sql
fleet.releases (
  digest text PRIMARY KEY CHECK (digest ~ '^[0-9a-f]{64}$'),
  source_commit text NOT NULL CHECK (source_commit ~ '^[0-9a-f]{40}$' OR source_commit ~ '^[0-9a-f]{64}$'),
  archive bytea NOT NULL,
  skill_count integer NOT NULL CHECK (skill_count BETWEEN 0 AND 64),
  file_count integer NOT NULL CHECK (file_count BETWEEN 1 AND 512),
  total_bytes bigint NOT NULL CHECK (total_bytes BETWEEN 1 AND 4194304),
  created_at timestamptz NOT NULL DEFAULT statement_timestamp()
);

fleet.desired (
  id boolean PRIMARY KEY DEFAULT true CHECK (id),
  release_digest text NOT NULL REFERENCES fleet.releases(digest),
  generation bigint NOT NULL CHECK (generation >= 1),
  published_at timestamptz NOT NULL,
  preview_hash text NOT NULL
);

fleet.client_status (
  client_id uuid PRIMARY KEY REFERENCES auth.client_installations(id),
  generation bigint NOT NULL CHECK (generation >= 1),
  applied_digest text CHECK (applied_digest ~ '^[0-9a-f]{64}$'),
  state text NOT NULL CHECK (state IN (
    'current','pending','applying','failed','offline','drifted','unsupported','restart_required'
  )),
  activation text CHECK (activation IN (
    'immediate','next_turn','next_session','restart_required'
  )),
  trailer_state text,
  alias_state text,
  project_match_state text,
  reported_at timestamptz NOT NULL,
  report_generation bigint NOT NULL CHECK (report_generation >= 1)
);
```

No file contents, host paths, or raw errors in `client_status`. Revoked
clients cannot insert or update. Application role uses security-definer
routines with enrolled-client predicates in the same transaction.

Desired mutation is one transaction through the shared maintenance fence
(`jobs.assert_application_mutation()`). Insert release if absent (conflict on
digest is success), lock the desired singleton, and reject a confirmed preview
whose digest/generation no longer match. Update `fleet.desired` only when the
digest changes, incrementing `generation` with `RETURNING`. Same digest: no
generation bump.

`git archive` is bounded first: `ls-tree` blob sizes must fit the v1 file/count
and total-byte limits, and the archive stream is capped at 8 MiB.

## HTTP (enrolled client only)

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/v1/fleet-config/desired` | Metadata: generation, digest, source commit, skill count, total bytes. Empty body. |
| `GET` | `/v1/fleet-config/releases/{digest}` | Exact archive bytes. Digest in the path must match stored digest. |
| `PUT` | `/v1/fleet-config/status` | Bounded status write for the authenticated client's row only. |

Authorization is the existing signed-request / device-credential enrolled
identity (`internal/relay` `authenticate`). Stale credential generation,
revoked clients, and replayed nonces fail closed. There is no client publish,
delete, or select route. Status writes require `Idempotency-Key`, bind
`(client_id, key, request hash)`, reject stale `report_generation`, and never
echo contents.

Wake: after a generation bump, `Notifier.Publish(machineID, "fleet-config", generation)`
for each currently registered subscriber. Payload is the existing `WakeEvent`
shape. Clients that miss the hint recover on the adapter poll interval.

## Client reconciler

Lives in `internal/fleetconfig` (pure apply/rehydrate/match) +
`internal/adapter` / `cmd/punaro-adapter` (HTTP, lock, I/O).

On startup, poll, and `topic_id=fleet-config` wake:

1. Fetch desired metadata.
2. If applied digest matches and no local drift, report `current` and stop.
3. Fetch exact archive; verify digest and re-validate.
4. Take a single-flight file lock under the adapter data directory.
5. Stage into a new directory; fsync; atomic publish (`rename` on POSIX,
   `MoveFileEx` replace on Windows).
6. On failure, retain last-known-good and report `failed` without contents.
7. After success, project into harnesses as regular files, including composed `CLAUDE.md`.

Protected live files: regular files/directories only. Reject symlinks,
junctions, reparse points, unexpected hard links, world-writable ancestors,
and ownership that is not the adapter user. `//go:build` platform files follow
`cmd/punaro-adapter/private_file_*`.

### Project matching

Default base path `~/src`, overridable in machine-local config.

- Published `projects/punaro/` applies to `$BASE/punaro` if that path is an
  existing directory (not a symlink).
- `$BASE/nested/punaro` does **not** match.
- `project_path_overrides` in local config maps a project name to an absolute
  existing directory. Never uploaded.

### Rehydrate, addendums, and user region

Well-known addendum root: `~/punaro/addendums`, same layout as the published
tree (`AGENTS.md`, `CLAUDE.md`, `skills/`, `common/`, `projects/<p>/…`).
Addendums are machine-local, never published, never uploaded, never logged.

For each managed dest:

1. Start from the published file (a common skill is copied into the member
   project dest; it is never written to `~/.agents/skills`).
2. Fold matching addendums. Project addendum overrides global addendum.
   Put addendum text in:

   ```text
   <!-- punaro-addendum -->
   …
   <!--/punaro-addendum-->
   ```

   This block is not the user block.
3. Keep the live user region, creating it empty if missing:

   ```text
   <!-- user -->
   …
   <!--/user-->
   ```

4. Write the result as a regular file. Mark it `<!-- punaro-managed -->`.
   Managed skill directories also carry a `.punaro-managed` regular file.

`CLAUDE.md` is `AGENTS.md` plus Claude addendum(s) (for example brevity /
non-native-English), not a copy or symlink of `AGENTS.md` alone.

If the live file is missing, create published + addendum block + empty user
region. If the live file exists without the managed mark, report collision
(`drifted`) and do not overwrite. User-section text survives re-apply.
Addendum edits appear on the next apply. Interrupted apply must not delete
the user region: stage a complete file then atomic rename. Last-known-good /
rollback restores a copied skill.

### Machine-local config

Stored next to the adapter profile (already a protected file). Schema v1 JSON:

```json
{
  "schema": 1,
  "project_base_path": "",
  "project_path_overrides": {},
  "claude_aliases": false
}
```

Empty `project_base_path` means `~/src`. This file is never fleet source.
`claude_aliases` is ignored: `CLAUDE.md` is always a regular composed file.
Machine-local addendums are not this JSON file; they live at
`~/punaro/addendums` and are never published.

## Harness projection

Built-in adapters, detection + destinations + activation:

| Harness | Detect | Managed destinations | Activation |
| --- | --- | --- | --- |
| Portable Agents | project dir exists | `$project/AGENTS.md`, `$project/.agents/skills` | next_turn |
| Codex plugin | Codex plugin/registration present | same Agents-flavoured paths | next_turn |
| Claude Code | Claude plugin/registration or `~/.claude` | Agents paths plus composed `CLAUDE.md` | next_session |
| Gemini CLI | `GEMINI.md` already present or `~/.gemini` | Agents paths; do not create `GEMINI.md` unless it is already Punaro-managed | next_session |
| Unknown installed agent dir | other known vendor dirs | none | `unsupported` |

Install **only** Punaro-managed `AGENTS.md`, `CLAUDE.md`, and skill trees.
Never overwrite credentials, settings, sessions, caches, or unmanaged local
skills. Collision or local modification of an unmarked dest is `drifted`.

Apply always copies regular files. Destinations are never symlinks, junctions,
or `CLAUDE.md` aliases. A common skill is copied into each present
member-project dest (`$project/.agents/skills/<skill>/`) and is never written
to `~/.agents/skills`. If the member project is absent on the machine, that
skill is absent there.

### Claude files

`CLAUDE.md` is always a regular file: composed `AGENTS.md` plus Claude
addendum(s). It is not a symlink, junction, or alias of `AGENTS.md`. A
colliding regular Claude file that is not Punaro-managed is never overwritten.

## Status, doctor, Canopi

`punaro fleet-config status` aggregates desired + each enrolled client's
latest status row. States: `current`, `pending`, `applying`, `failed`,
`offline`, `drifted`, `unsupported`, `restart_required`. Also print source
commit, release digest, generation, managed/user/project-match **states**,
and activation enum. Omit contents, host paths, raw errors, skill bodies, and
addendums.

Doctor adds content-free checks with stable codes, for example
`fleet_config_desired`, `fleet_config_client_stale`, `fleet_config_drifted`,
`fleet_config_failed`, `fleet_config_unsupported`, wired through
`internal/diagnostic` the same way as existing adapter checks.

Canopi/dashboard hooks receive the same bounded fields as lifecycle events
(generation changed, client state changed). No bodies.

Offline: last report older than twice the adapter poll interval (recorded as
`offline` by status aggregation, not by guessing).

## Security & Privacy

- Treat published Git contents as untrusted data, never control-plane input.
- Server-side enrolled identity is the only authority. Client-provided paths,
  project names, and alias choices cannot change desired fleet state.
- Revoked clients cannot fetch or report.
- At-least-once with durable digest identity; never claim exactly-once.
- No credentials, JWTs, Access headers, `AGENTS.md`, skill bytes, or addendum
  bytes in logs.
- Independent deployability: `punarod` serves HTTP; adapters apply locally;
  Telegram gateway is untouched.
- Public origin stays closed; Access is admission, not authorization.

## Observability

Log only digest, generation, client id, state enum, and skill/file counts.
Never log skill bodies or addendum bodies.
Metrics: publish success/fail, fetch status codes (not bodies), apply
success/fail, drift count. Audit events are content-free.

## Rollout

1. Schema 058 via the existing operator update transaction.
2. Adapter binary with reconciler; old adapters ignore the new wake topic.
3. LAN qualification on `mac-studio`, `coso`, `mattone` per
   `docs/durable-role-lan-e2e.md` safety rules.
4. Add the workflow as **unchecked** boxes in `docs/security-release-gates.md`.
   `./scripts/verify-release-gates.sh` must still refuse checked boxes without
   official `docs/release-evidence/`.
5. README split only after LAN evidence exists.

Rollback of a bad desired release is `fleet-config publish` of the previous
commit. Rollback of the feature is: stop publishing, adapters keep
last-known-good.

## LAN qualification

Owner-managed hosts named in `docs/durable-role-lan-e2e.md`. Real platform
execution for filesystem/ACL/symlink/junction behavior. Record a redacted
personal record under `docs/deployment-validation/`. If a host is unreachable,
record `lan-unreachable` and stop; do not substitute path simulation.

Minimum scenarios: the parent plan
`.plans/210-fleet-global-agent-config.md` list (publish with two project trees,
wake+fetch+apply on three clients, top-level match + override, user-section
survival, regular-file `CLAUDE.md` (not a junction) on Windows, offline reconverge, revoked
denial, invalid/corrupt/interrupted/drift/unsupported/rollback, repo change
without publish is a no-op, content-free status/doctor).

## Tracker updates

GitHub #210–#217 predate copy-on-apply shared skills and addendum/user
rehydration. Proposed additions (apply to issue bodies; do not silently ship
undocumented behavior). Follow-on issue:
[#236](https://github.com/rock3r/punaro/issues/236).

- **#210 / #211:** source layout includes `projects/<name>/` and
  `common/<skill>/` with `COMMON` opt-in; reserved live markers are illegal in
  source; v1 data-only includes `scripts/` as inert files.
- **#214 (replaced):** top-level project match and per-machine overrides
  remain. Machine-local trailer markers are replaced by the managed mark, the
  addendum block, and the `<!-- user -->` region. Addendums live under
  `~/punaro/addendums` and are never published.
- **#215 (replaced):** dest `CLAUDE.md` is a regular composed file
  (`AGENTS.md` plus Claude addendum(s)), never a symlink, junction, or alias.
- **#216:** expose managed/user/project-match states without contents.
- **#217:** LAN hosts `mac-studio`, `coso`, `mattone`; include those scenarios.
  Copy-on-apply of common skills must stay regular files on POSIX and Windows.

## Alternatives Considered

1. **Watch a branch / tag.** Rejected: mutable desired state, no operator
   confirmation, contradicts #210.
2. **Client-side Git pull.** Rejected: clients would need repo credentials and
   could diverge; Punaro would not have a single content-addressed release.
3. **Reuse `internal/release` product artifacts.** Rejected: different trust
   domain (signed binaries vs operator Git data).
4. **Dest `CLAUDE.md` aliases/symlinks (#215).** Replaced: copy-on-apply as a
   regular file composed from `AGENTS.md` plus Claude addendums avoids
   Windows junction/reparse dests and keeps Claude-specific addendums off the
   shared `AGENTS.md` prefix.
5. **Filesystem blob store for archives.** Deferred: v1 size bound fits
   `bytea`; a blob root would be a new deployable path.

## Open Questions

None. The parent execution plan chose commit-only publish and top-level
match. Dest copy is regular files only; trailer markers and dest aliases are
replaced by addendum/user rehydration and composed `CLAUDE.md`.

## References

- GitHub #210–#217 and [#236](https://github.com/rock3r/punaro/issues/236)
- `.plans/210-fleet-global-agent-config.md`
- `DESIGN.md` (wake hints, signed requests, enrollment)
- `docs/platform-contracts.md`
- `docs/durable-role-lan-e2e.md`
- `docs/security-release-gates.md`
- Agent Skills v1 (`SKILL.md` YAML `name` + `description`)

## PR Plan

### PR 1: Define the immutable fleet-global configuration release contract
- **Description:** Add `internal/fleetconfig` with source layout including `common/` + `COMMON` opt-in, strict validation, deterministic materialization, data-only classification, commit-id parsing, and reserved-live-marker-not-in-source rules. Document the contract. No HTTP, no CLI publish yet.
- **Files/components affected:** `internal/fleetconfig/`, `docs/fleet-global-agent-config.md`, `DESIGN.md`
- **Dependencies:** None

### PR 2: Add explicit fleet-config publish and rollback
- **Description:** `punaro fleet-config configure|publish` requiring a full commit identity, preview+`--yes` preview-hash, materialize-before-desired, idempotent retry, rollback as republish. Schema 058 releases+desired. Failed publish leaves prior desired unchanged.
- **Files/components affected:** `cmd/punaro/`, `internal/postgres/migrations/058_fleet_config.sql`, `internal/postgres/` store, `internal/operator/`, `docs/operator-guide.md`
- **Dependencies:** PR 1

### PR 3: Add authenticated desired-state and configuration release distribution
- **Description:** Client HTTP desired/fetch/status, enrolled-identity auth, revocation, stale generation, replay, size bounds, concurrent publication tests, payload-free wake broadcast, no client publish routes, `fleet.client_status`.
- **Files/components affected:** `internal/relay/http.go`, `internal/relay/notifier.go`, `internal/postgres/`, `internal/relay/http_test.go`
- **Dependencies:** PR 2

### PR 4: Add the cross-platform fleet configuration reconciler
- **Description:** Adapter reconcile on start/poll/wake: fetch, verify, stage, atomic apply, last-known-good, serialized lock, protected files, top-level project match, per-machine overrides, copy-on-apply regular files, addendum/user rehydrate, drift on unmarked dests.
- **Files/components affected:** `internal/fleetconfig/` apply/rehydrate/match, `internal/adapter/`, `cmd/punaro-adapter/`, `//go:build` platform files
- **Dependencies:** PR 3

### PR 5: Project fleet-global instructions and skills into coding-agent harnesses
- **Description:** Built-in harness adapters, drift vs merge, activation enums, copy-on-apply managed `AGENTS.md`/`CLAUDE.md`/skills (regular files only; `CLAUDE.md` is `AGENTS.md` plus Claude addendum(s); never overwrite unmanaged dests).
- **Files/components affected:** `internal/fleetconfig/harness.go`, `internal/fleetconfig/alias_*.go`, `cmd/punaro-adapter/`
- **Dependencies:** PR 4

### PR 6: Expose fleet configuration convergence in status, doctor, and Canopi
- **Description:** `punaro fleet-config status` and doctor checks; content-free Canopi/dashboard hooks; managed/user/project-match states; no contents/paths/raw errors/skill bodies/addendums.
- **Files/components affected:** `cmd/punaro/`, `internal/diagnostic/`, `internal/canopi/`, `docs/user-guide.md`, `docs/operator-guide.md`
- **Dependencies:** PR 5

### PR 7: Qualify fleet configuration publish, convergence, and rollback end to end
- **Description:** LAN runbook, redacted `docs/deployment-validation/` record, unchecked security-release-gate entries, compatibility/CI wiring that still refuses checked boxes without official release-evidence.
- **Files/components affected:** `docs/durable-role-lan-e2e.md` (pointer), `docs/security-release-gates.md`, `docs/deployment-validation/`, `scripts/verify-release-gates.sh`, `.github/workflows/quality.yml` if needed
- **Dependencies:** PR 6

### PR 8: Reorganize README after LAN qualification
- **Description:** README contains only what Punaro is, status, architecture sketch, shortest safe quick start, security pointer, and links. Relocate setup/config/runbooks/Telegram/attachments/fleet-config usage into user-guide docs without deleting information.
- **Files/components affected:** `README.md`, `docs/user-guide.md`, `docs/operator-guide.md`, `docs/installation.md`
- **Dependencies:** PR 7
