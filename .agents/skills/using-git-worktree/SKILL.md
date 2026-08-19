---
name: using-git-worktree
description: Use when starting nontrivial Punaro work that should stay isolated from the main checkout. Creates or reuses a safe git worktree with sensible defaults.
---

# Using Git Worktrees

## Purpose

Create isolated workspaces for implementation work without disturbing the main checkout.
Prefer a worktree for implementation-heavy tasks, not for tiny doc-only edits.

## Before creating anything

Check whether isolation already exists:

1. Are you already inside a worktree? (`git worktree list`, `git rev-parse --git-dir`)
2. Are you already on a non-main branch?

If either is true, report that isolation already exists and keep working there.
Never create a feature branch in a dirty main checkout.

## Directory selection

Create worktrees under `.worktrees/` at the repo root (create it if missing). Before
creating a project-local worktree directory, verify it is gitignored; if it is not, fix
that first.

Never place a Punaro worktree under a world-writable ancestor such as `/tmp` or
`$TMPDIR`: the adapter's invocation tests create fixtures inside the checkout and
require protected, non-symlink path components, so the quality gate fails from such a
location even when the code is fine.

## Creation flow

1. Determine the current branch and the default branch.
2. Choose the base branch (normally `origin/main`).
3. Create a new worktree with a descriptive `agent/<feature>` branch name.
4. Run `make test` in the worktree as an initial sanity check before editing.

```sh
git rev-parse --abbrev-ref HEAD
git worktree add .worktrees/<branch-name> -b agent/<branch-name> origin/main
make test
```

## Before pushing

Run the full Punaro quality gate from the worktree root (see AGENTS.md):

```sh
make test
make test-race
make staticcheck
make security
make lint
```

## Punaro notes

- Keep `.plans/` in the root checkout rather than inside the worktree.
- After a merged PR: switch the primary checkout to `main` if needed, remove the feature
  worktree (`git worktree remove`), and delete only the local feature branch.
