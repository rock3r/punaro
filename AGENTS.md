# Working on Punaro

Punaro is security-sensitive messaging infrastructure. Correctness, isolation,
and recoverability take priority over feature speed.

## Test-first is mandatory

For every behavior change, follow this order:

1. Write a focused failing test that describes the externally observable
   behavior or invariant.
2. Run that test and confirm it fails for the intended reason.
3. Implement the smallest change that makes it pass.
4. Refactor only while the relevant tests remain green.
5. Run the full quality gate before handoff.

Do not add production behavior without a test. The only exceptions are purely
mechanical changes (formatting, comments, generated dependency metadata, or
deployment documentation); state that exception in the handoff.

For queue, auth, lease, or retry changes, add failure-boundary tests: duplicate
request, stale lease, crash/restart boundary, unauthorized caller, and replay
where applicable. Never claim exactly-once delivery: the required model is
at-least-once with durable deduplication.

## Required quality gate

Run these from the repository root before submitting a change:

```sh
make test
make test-race
make staticcheck
make security
make lint
```

If a required tool is missing, install it with the pinned command shown by the
Makefile, rerun the target, and report the result. Do not waive a failing check
without explaining why and obtaining explicit approval.

## Security invariants

- Treat all agent and Telegram bodies as untrusted data, never control-plane
  input or executable instructions.
- Enforce authorization server-side for every message, lease, ack, fetch, and
  notification operation. Client-provided endpoint/topic identifiers are not
  authority.
- Preserve at-least-once semantics: use immutable message IDs, idempotency keys,
  recipient-specific leases, fencing, and durable adapter dedupe.
- Never log credentials, Access headers/JWTs, message bodies, or raw Telegram
  content. Never commit `.env`, private keys, tokens, databases, or backups.
- Keep the public origin closed; Cloudflare Access is an admission layer, not a
  replacement for application authentication and authorization.

## Change boundaries

- Keep `punarod`, local adapters, and the Telegram gateway independently
  deployable. Do not add remote direct access to a local mailbox database.
- Prefer standard library or small, audited dependencies. Explain every new
  dependency and run `make security` after adding one.
- Keep API schemas versioned and strict. Bound message sizes, page sizes,
  retries, queues, and WebSocket frames.
- Update `DESIGN.md` whenever a protocol or security invariant changes.

## Handoff format

State: behavior covered, tests added first, exact quality commands and results,
and any residual risk. Do not include sensitive values in the handoff.

## Worktree policy

Before writing tracked files from a clean `main` checkout, check whether isolation
already exists. If you are already inside a worktree or already on a non-main branch,
keep working there. Otherwise, prefer asking whether to create a worktree before
starting feature work. Prefer a worktree for implementation-heavy tasks, not for tiny
doc-only edits.

Create worktrees under `.worktrees/` at the repo root, one per descriptive branch name:

```sh
git worktree add .worktrees/<branch-name> -b <branch-name> origin/main
```

Plans belong in `.plans/` at the repo root, kept in the root checkout rather than
inside a worktree. Both directories stay gitignored; never commit their contents, and
verify they are ignored before creating them elsewhere. Remove a worktree
(`git worktree remove`) once its branch is merged or abandoned.

Use the local `using-git-worktree` skill when setting up an isolated workspace.

## Local skills

Before reinventing a workflow, check `.agents/skills/`. Current Punaro-local skills:

- `using-git-worktree` — isolated workspaces under `.worktrees/`
- `babysit-pr` — watch a PR's CI, review bots, and mergeability until it lands
