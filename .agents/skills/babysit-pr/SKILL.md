---
name: babysit-pr
description: >
  Babysit a GitHub pull request after creation by continuously polling CI checks/workflow
  runs, new review comments, and mergeability state until the PR is ready to merge (or
  merged/closed). Diagnose failures, retry likely flaky failures up to 3 times, auto-fix
  and push branch-related issues when appropriate, and stop only when user help is required
  (e.g. CI infrastructure issues, exhausted flaky retries, or ambiguous/blocking review
  feedback). Use when the user asks to monitor a PR, watch CI, handle review comments, or
  keep an eye on failures and feedback on an open PR.
allowed-tools: Bash(python3 */skills/babysit-pr/scripts/*), Bash(gh pr *), Bash(gh run *), Bash(gh api *), Bash(git fetch *), Bash(git rebase *), Bash(git merge *), Bash(git checkout *), Bash(git switch *), Bash(git push *), Bash(git add *), Bash(git commit *), Bash(git remote *), Bash(git diff *), Bash(git log *), Bash(git status), Bash(git branch *), Bash(git worktree *), Bash(make *), Read, Edit
---

# PR Babysitter

Monitor a PR persistently until one of the terminal states is reached:

- PR merged or closed
- CI fully green, no unaddressed review comments, no merge conflicts
- A situation requiring user intervention

The watcher script is the **sole authority** on readiness. Do not manually poll or infer
readiness from raw `gh pr checks`, `gh pr view`, workflow-run, or flat-comment output;
those commands may be used only for targeted diagnosis after the watcher reports a
non-ready verdict, never to declare a PR green. If the script is unavailable, treat that
as a tooling defect, report it, and do not substitute ad-hoc polling.

Throughout this document, "the full Punaro gate" means the quality gate from AGENTS.md:
`make test`, `make test-race`, `make staticcheck`, `make security`, `make lint`.

## Inputs

- No PR argument — infer from current branch (`--pr auto`)
- PR number — e.g. `123`
- PR URL — e.g. `https://github.com/rock3r/punaro/pull/123`

## Core workflow

0. **Before running any script**, output a single line so the user knows which PR this
   conversation is tracking — e.g. `Babysitting PR [#123](https://github.com/rock3r/punaro/pull/123)`.
1. Start with `--once` (default) — it blocks until something needs your attention, then returns.
2. Run the watcher to snapshot PR/CI/review state.
3. Inspect the `actions` list in the JSON output.
4. Diagnose CI failures — classify as branch-related (fix and push) vs. flaky (retry).
5. Process actionable review comments from trusted humans and the review bots.
6. Verify mergeability on each loop.
7. After any push, relaunch the watcher in the same turn.
8. Continue until a terminal stop condition is reached.

## Key commands

```bash
# Wait until something needs attention, then return one snapshot (default)
python3 .agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --once

# Instant snapshot of current state (no waiting)
python3 .agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --snapshot

# Continuously poll, emitting JSONL snapshots (for streaming-capable consumers)
python3 .agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --watch

# Trigger a rerun of failed jobs for the current SHA
python3 .agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --retry-failed-now

# Explicit PR number or URL
python3 .agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr 42 --once
```

## Stop conditions

| `actions` value | Meaning |
|---|---|
| `stop_pr_closed` | PR was merged or closed — done |
| `stop_ready_to_merge` | CI green, no blocking reviews, no conflicts — the only positive readiness verdict. Before acting on it, run the full Punaro gate locally on the PR head (a PR can go green without any babysitter push, and the gate must still pass before merge) |
| `stop_exhausted_retries` | Flaky reruns hit the retry limit — user must investigate |
| `stop_non_retryable_failure` | Terminal failure is not in retry-eligible workflows — diagnose/fix before continuing |
| `stop_bugbot_not_green` | Cursor Bugbot is not clean — do not merge |
| `stop_session_timeout` | `--max-session-minutes` elapsed (default 90 min) — stop and report |
| `diagnose_hung_check` | A pending check exceeded its hung threshold — stop and report |
| `diagnose_merge_conflict` | PR is merge-conflicted (`CONFLICTING` / `DIRTY`) — resolve before waiting on checks |
| `diagnose_branch_behind` | PR branch is behind its base — rebase onto the PR's base ref (batch with any pending fixes) |
| `diagnose_skipping_checks` | One or more checks completed with `neutral`/`skipping` — investigate why |
| `wait_bugbot` | Bugbot still running — do not push or merge |
| `wait_codex` | Codex is still reviewing (👀 reaction present) — do not push or merge |
| `wait_coderabbit` | CodeRabbit is still reviewing — do not push or merge |

Keep polling when CI is running (`idle`), when new review items arrive
(`process_review_comment`), when any review bot is still running, or when CI is green but
the PR is awaiting approval.

## Post-merge cleanup (when `stop_pr_closed` and PR is merged)

1. **If currently on the PR branch or inside its worktree, switch away first** — check
   out `main`, or `cd` to the main checkout.
2. **Remove the git worktree** if the branch was checked out in one — find it with
   `git worktree list` (worktrees live under `.worktrees/`). Do this before touching the
   branch: `git branch -D` refuses while a worktree still has the branch checked out.
3. **Delete the local branch** (squash merges leave it unmerged by default):
   `git branch -D <head_branch>`.

**Only delete the local branch and worktree** — never touch remote branches. Skip
silently if the branch or worktree doesn't exist locally.

## Push discipline — batch all fixes before pushing (cost control)

Each push triggers new review-bot runs. **Never push until all of the following are true:**

1. The full Punaro gate passes locally (no CI failures to fix after the push).
2. No review bot is still in progress — wait for all of them to finish so their comments,
   if any, can be collected and fixed in the same push.
3. You have incorporated all currently visible actionable bot comments into the pending
   local fix batch.

After pushing the fix batch, resolve all bot threads on GitHub (or reply + resolve when no
code change is needed). No open bot threads should remain when the PR is merged.

If a bot finishes while you are mid-fix and posts new comments, incorporate those fixes
into the same commit before pushing.

## Conflict batching strategy (use when PR shows `CONFLICTING`/`DIRTY` or `diagnose_branch_behind`)

1. **Do not push immediately.** Wait until no review bot is in progress.
2. Snapshot latest status/comments.
3. Rebase the branch onto the PR's actual base ref — resolve it with
   `gh pr view <n> --json baseRefName`, fetch that base from the repository the PR
   *targets* before rebasing onto its updated remote-tracking ref (for a same-repo PR
   that remote is `origin`; for a cross-repository PR resolve the base repo's remote
   first — a fork's `origin/<base>` is the wrong history). Never assume `main`, and
   never rebase onto a stale or wrong-remote local ref.
4. Resolve conflicts and **in the same fix cycle** apply all actionable bot comments.
5. Run the full Punaro gate.
6. Push once, with `--force-with-lease`: the rebase rewrote the commit IDs, so an
   ordinary push is rejected as non-fast-forward, and an unqualified force push could
   overwrite concurrent remote updates.

This avoids paying for multiple bot reruns and prevents a ping-pong where a conflict-fix
push is immediately followed by a second bot-fix push.

## Review-bot merge gates (mandatory)

**Never merge until every present review bot reports clean.**

### Bugbot (CI check)

- Still in progress → keep polling, do not push.
- `NEUTRAL` → it found potential issues. Read the inline comments from `cursor[bot]`, fix
  every reported issue locally, run the full Punaro gate, then push once.
- `SKIPPING` → treat as **not green**; Bugbot may have posted comments before skipping —
  check `gh api repos/{owner}/{repo}/pulls/{pr}/comments` for `cursor[bot]` comments and
  fix them; if none exist, re-request review or ask the user.
- `SUCCESS` (or a SHA-matched clean manual Bugbot review — the watcher accepts both) →
  gate is clear.

### Codex (emoji reaction)

Codex uses emoji reactions, not a CI check: a 👀 reaction from
`chatgpt-codex-connector[bot]` means it is actively reviewing (`codex_gate.reviewing` is
`true`, `wait_codex` is emitted — do not push or merge). Reaction removed with no new
comments → satisfied. Reaction removed with comments → fix them under push discipline.

### CodeRabbit (presence-conditional)

CodeRabbit gates a PR only when it shows signs of life (a CodeRabbit check, reaction, or
authored comment); when dormant the watcher degrades to a Bugbot+Codex-only gate. While
`coderabbit_gate.reviewing` is `true` (`wait_coderabbit`), do not push or merge; treat its
comments like any other bot comments.

## Decision rules

See `references/heuristics.md` for the full classification checklist:

- **Branch-related failure**: first make sure you are editing the right checkout —
  `HEAD` must match the watcher's reported `head_branch`/`head_sha`; when invoked with
  an explicit PR number from `main` or an unrelated branch, check the PR branch out in
  an isolated worktree before touching anything. Then edit the code, collect all other
  pending issues (bot and human reviews), fix everything, run the full Punaro gate, and
  push once.
- **Likely flaky/unrelated**: rerun via `--retry-failed-now`; retry budget defaults to 3
  per SHA. Only retry-eligible workflows are auto-rerun; ordinary CI failures are
  diagnose/fix-first.
- **Ambiguous or requires product decision**: stop and ask the user.

## Review bots

The watcher surfaces feedback from:

- **cursor[bot]** — Cursor Bugbot (CI check-based code review)
- **chatgpt-codex-connector[bot]** — OpenAI Codex (emoji reaction-based code review)
- **coderabbitai** — CodeRabbit (presence-conditional review)
- Trusted humans: authors with `OWNER`, `MEMBER`, or `COLLABORATOR` association

> **Note**: if additional review bots are enabled on the repo, add their login keyword to
> `REVIEW_BOT_LOGIN_KEYWORDS` in `scripts/gh_pr_watch.py`.

## Worktree gotchas

When working from a git worktree, watch out for rebases silently reverting fixes — after
a rebase, verify key changes survived. Always run the full Punaro gate before pushing;
see the quality gate in [AGENTS.md](../../../AGENTS.md).

## Choosing a mode based on harness capabilities

- **Harness streams tool output to the model** (e.g. Claude Code subagents): use
  `--watch`. The script runs continuously, emitting JSONL snapshots as events; the model
  acts on each as it arrives. The script exits on terminal stop conditions.
- **Harness only returns output after tool exit** (most tool-use loops): use `--once`
  (the default). The script blocks internally, polling every 30 seconds, and returns only
  when something needs agent attention. The model never sleeps blindly. Typical loop:
  run `--once` → act on `actions` → if not terminal, run `--once` again.
- **Quick debugging / one-off inspection**: `--snapshot` for an instant point-in-time
  view with no waiting.

## Output format

All modes emit newline-delimited JSON.

- `--once` / `--snapshot` / `--retry-failed-now`: emit a top-level snapshot/result object
  where `actions` is directly available.
- `--watch`: emits event envelopes —
  `{"event":"snapshot","payload":{"snapshot":{...},"state_file":"...","next_poll_seconds":30}}`
  and `{"event":"stop","payload":{...}}`. Read actions from `payload.snapshot.actions`
  for `snapshot` events and `payload.actions` for `stop` events.

`blocking_review_items` contains actionable unresolved inline review comments; while it
is non-empty, `stop_ready_to_merge` is not emitted.

Example snapshot payload shape:

```json
{
  "pr": { "number": 42, "head_sha": "abc123", "mergeable": "MERGEABLE" },
  "checks": { "pending_count": 0, "failed_count": 1, "passed_count": 8, "skipping_count": 0, "all_terminal": true },
  "failed_runs": [{ "run_id": 123, "workflow_name": "CI", "conclusion": "failure", "retry_eligible": false }],
  "bugbot_gate": { "status": "completed", "conclusion": "success", "is_success": true },
  "codex_gate": { "reviewing": false, "status": "idle" },
  "coderabbit_gate": { "reviewing": false },
  "hung_checks": [],
  "new_review_items": [],
  "blocking_review_items": [],
  "actions": ["diagnose_ci_failure", "stop_non_retryable_failure"],
  "retry_state": { "current_sha_retries_used": 0, "max_flaky_retries": 3 }
}
```
