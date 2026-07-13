#!/bin/sh
set -eu

# This repository has no approved attachment release evidence.  Keep that fact
# mechanically checked so a runtime-exposure change cannot silently accompany a
# Markdown checklist edit.  An actual release requires a separately reviewed
# change to this verifier, protected-branch policy, signed tag, and GitHub
# environment approvals; CI alone cannot establish independent human approval.
if grep -Eq '^[-] \[[xX]\]' docs/security-release-gates.md; then
	printf '%s\n' 'release gates may not be checked in the withheld runtime state' >&2
	exit 1
fi

if find docs/release-evidence -type f -name '*.md' ! -name README.md | grep -q .; then
	printf '%s\n' 'release evidence is not accepted while all runtime capabilities are withheld' >&2
	exit 1
fi

GOCACHE="${GOCACHE:-/tmp/punaro-go-cache}" go test ./cmd/punarod -run '^TestRunFailsClosedBeforeStartingAttachmentRuntime$' -count=1
