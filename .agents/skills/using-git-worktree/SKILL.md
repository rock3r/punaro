---
name: using-git-worktree
description: Keep nontrivial Punaro work isolated from main.
---

# Using Git Worktrees

Adapted from Spectre's worktree workflow for this Go repository.

Before changing tracked files, inspect `git worktree list` and the current
branch. If already on a non-main worktree, keep using it. Otherwise create a
descriptive `agent/<feature>` branch from `main` in an ignored local worktree
directory, then run `make test` before editing. Never create a feature branch
in a dirty main checkout.

Before pushing from a worktree, run the full Punaro gate:

```sh
make test
make test-race
make staticcheck
make security
make lint
```

After a merged PR, switch the primary checkout to `main`, remove the feature
worktree, and delete only the local feature branch.
