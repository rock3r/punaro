#!/bin/sh
set -eu

# This repository has no approved attachment release evidence. Keep the gated
# runtime state mechanically checked so a core personal-release evidence record
# cannot silently open an attachment or public-relay capability. An actual
# Internet-facing production release requires protected-branch policy, a signed
# tag, and GitHub environment approvals; CI alone cannot establish independent
# human approval.
if grep -Eq '^[-] \[[xX]\]' docs/security-release-gates.md; then
	printf '%s\n' 'release gates may not be checked in the withheld runtime state' >&2
	exit 1
fi

GOCACHE="${GOCACHE:-/tmp/punaro-go-cache}" go test ./cmd/punarod -run '^TestRunFailsClosedBeforeStartingAttachmentRuntime$' -count=1
