---
name: babysit-pr
description: Monitor a Punaro pull request until checks, reviews, and merge are complete.
---

# PR Babysitter

Adapted from Spectre's PR babysitter. After creating a PR, announce its URL,
then repeatedly inspect `gh pr view`, `gh pr checks`, workflow runs, and review
comments. Diagnose branch-caused failures locally; retry only demonstrably
transient failures up to three times per head SHA. Batch all CI and review fixes
into one tested push.

Never merge until all required checks are green, no actionable review comment
remains, the PR is mergeable, and a fresh local quality gate passes. After a
merge, remove the local worktree and feature branch only; do not mutate remote
history.
