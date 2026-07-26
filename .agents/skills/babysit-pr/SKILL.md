---
name: babysit-pr
description: Monitor a Punaro pull request until checks, reviews, and merge are complete.
---

# PR Babysitter

Adapted from Spectre's PR babysitter. After creating a PR, announce its URL,
then use the designated `babysit-pr` gate command as the sole authority for
polling and determining whether the PR is ready to merge. It incorporates
checks, review threads, mergeability, and required project gates into one
verdict:

```sh
python3 .agents/skills/babysit-pr/scripts/gh_pr_watch.py --pr auto --once
```

Use `--snapshot` only for a non-waiting diagnostic after the watcher reports a
non-ready action. The watcher’s terminal `stop_ready_to_merge` action is the
only positive readiness verdict; `stop_bugbot_not_green`,
`diagnose_skipping_checks`, and `process_review_comment` are merge blockers.

Do not manually poll or infer readiness from raw `gh pr checks`, `gh pr view`,
workflow-run, or flat-comment output. Those commands may be used only for
targeted diagnosis after the gate command reports a non-ready verdict; they
must not be used to declare a PR green. If the designated gate command/script
is unavailable, treat that as a tooling defect, report it, and do not substitute
ad-hoc polling for its verdict.

Diagnose branch-caused failures locally; retry only demonstrably transient
failures up to three times per head SHA. Batch all CI and review fixes into one
tested push.

Never merge until all required checks are green, no actionable review comment
remains, the PR is mergeable, and a fresh local quality gate passes. After a
merge, remove the local worktree and feature branch only; do not mutate remote
history.
