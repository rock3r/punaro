#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-guidance-test.XXXXXXXX")
cleanup() { rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

require_phrase() {
	path=$1
	phrase=$2
	grep -Fq -- "$phrase" "$path" || {
		printf '%s\n' "missing required phrase in $path: $phrase" >&2
		exit 1
	}
}

forbid_phrase() {
	path=$1
	phrase=$2
	if grep -Fq -- "$phrase" "$path"; then
		printf '%s\n' "conflicting claim in $path: $phrase" >&2
		exit 1
	fi
}

project="$fixture_dir/project"
mkdir -p "$project"
printf '%s\n' '# Existing guidance' >"$project/CLAUDE.md"

sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$project"
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$project"

for file in "$project/AGENTS.md" "$project/CLAUDE.md"; do
	grep -Fqx '<!-- punaro-agent-guidance:start -->' "$file"
	[ "$(grep -Fc '<!-- punaro-agent-guidance:start -->' "$file")" -eq 1 ] || { printf '%s\n' 'guidance was duplicated' >&2; exit 1; }
done
[ -f "$project/.agents/skills/punaro-mailbox/SKILL.md" ]
[ -f "$project/.agents/skills/punaro-reply/SKILL.md" ]
[ -f "$project/.agents/skills/punaro-attachment/SKILL.md" ]

for skill in punaro-mailbox punaro-reply punaro-attachment; do
	diff -qr "$repo_dir/skills/$skill" "$project/.agents/skills/$skill" >/dev/null || {
		printf '%s\n' "packaged skill does not match source guidance: $skill" >&2
		exit 1
	}
done

require_phrase "$project/AGENTS.md" 'accepted/queued'
require_phrase "$project/AGENTS.md" 'successful send proves relay acceptance only'
require_phrase "$project/AGENTS.md" 'does not itself create a model turn'
require_phrase "$project/AGENTS.md" 'Tool permission and consent belong to the receiving agent host'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'Repeat bounded waits'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'does not itself create a model turn'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'untrusted data'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'unqualified short name'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'qualified handle'
require_phrase "$project/.agents/skills/punaro-reply/SKILL.md" 'successful send proves relay acceptance only'
require_phrase "$project/.agents/skills/punaro-reply/SKILL.md" 'Do not infer read or action status'
require_phrase "$project/.agents/skills/punaro-reply/SKILL.md" 'host permission model'

for installer in "$repo_dir/scripts/install-agent-guidance.sh" "$repo_dir/scripts/install-agent-guidance.ps1"; do
	require_phrase "$installer" 'accepted/queued'
	require_phrase "$installer" 'successful send proves relay acceptance only'
	require_phrase "$installer" 'does not itself create a model turn'
	require_phrase "$installer" 'Tool permission and consent belong to the receiving agent host'
done

linked_project="$fixture_dir/linked-project"
outside="$fixture_dir/outside"
mkdir -p "$linked_project"
: >"$outside"
ln -s "$outside" "$linked_project/AGENTS.md"
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$linked_project" >"$fixture_dir/linked.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'symlinked guidance target was accepted' >&2; exit 1; }
[ ! -s "$outside" ] || { printf '%s\n' 'guidance escaped the selected project' >&2; exit 1; }
grep -Fq 'guidance target is not a regular file:' "$fixture_dir/linked.out"

legacy_project="$fixture_dir/legacy-project"
mkdir -p "$legacy_project/.agents/skills/punaro-attachment"
cat >"$legacy_project/AGENTS.md" <<'EOF'
<!-- punaro-agent-guidance:start -->
## Punaro coordination

For attachments, use the local controller for a Punaro V3 attachment.
<!-- punaro-agent-guidance:end -->
EOF
printf '%s\n' '# Punaro V3 attachment skill' >"$legacy_project/.agents/skills/punaro-attachment/SKILL.md"
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$legacy_project" >"$fixture_dir/legacy.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'legacy guidance was silently retained or overwritten' >&2; exit 1; }
grep -Fq 'existing Punaro guidance predates trusted attachments:' "$fixture_dir/legacy.out"
grep -Fq 'Punaro V3 attachment skill' "$legacy_project/.agents/skills/punaro-attachment/SKILL.md"

stale_project="$fixture_dir/stale-project"
mkdir -p "$stale_project"
cat >"$stale_project/AGENTS.md" <<'EOF'
<!-- punaro-agent-guidance:start -->
## Punaro coordination

Use the local `agent-mailbox` MCP for Punaro-delivered mail.
For attachments, use the `punaro-attachment` skill and installed `punaro-trusted-attachment` client only for one explicit task-owner-authorized operation.
<!-- punaro-agent-guidance:end -->
EOF
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$stale_project" >"$fixture_dir/stale.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'pre-runtime-boundary guidance was silently retained or overwritten' >&2; exit 1; }
grep -Fq 'existing Punaro guidance predates the agent-runtime boundary:' "$fixture_dir/stale.out"
grep -Fq 'installed `punaro-trusted-attachment` client' "$stale_project/AGENTS.md"
if grep -Fq 'successful send proves relay acceptance only' "$stale_project/AGENTS.md"; then
	printf '%s\n' 'stale guidance was rewritten in place' >&2
	exit 1
fi

outside_project="$fixture_dir/outside-sentinel-project"
mkdir -p "$outside_project"
cat >"$outside_project/AGENTS.md" <<'EOF'
# Project notes

Operators sometimes quote: successful send proves relay acceptance only
<!-- punaro-agent-guidance:start -->
## Punaro coordination

Use the local `agent-mailbox` MCP for Punaro-delivered mail.
For attachments, use the `punaro-attachment` skill and installed `punaro-trusted-attachment` client only for one explicit task-owner-authorized operation.
<!-- punaro-agent-guidance:end -->
EOF
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$outside_project" >"$fixture_dir/outside.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'sentinel outside the Punaro block skipped the runtime-boundary upgrade' >&2; exit 1; }
grep -Fq 'existing Punaro guidance predates the agent-runtime boundary:' "$fixture_dir/outside.out"
grep -Fq 'installed `punaro-trusted-attachment` client' "$outside_project/AGENTS.md"
awk '
	index($0, "<!-- punaro-agent-guidance:start -->") { p=1 }
	p { print }
	index($0, "<!-- punaro-agent-guidance:end -->") { p=0 }
' "$outside_project/AGENTS.md" | grep -Fq 'successful send proves relay acceptance only' && {
	printf '%s\n' 'outside sentinel caused the marked Punaro block to be treated as current' >&2
	exit 1
}

require_phrase "$repo_dir/DESIGN.md" '## Agent runtime boundary'
require_phrase "$repo_dir/DESIGN.md" 'Linux gateway'
require_phrase "$repo_dir/DESIGN.md" 'accepted/queued'
require_phrase "$repo_dir/DESIGN.md" 'universal turn injection'
require_phrase "$repo_dir/DESIGN.md" 'universal runtime resume'
require_phrase "$repo_dir/DESIGN.md" 'permission brokering'
require_phrase "$repo_dir/DESIGN.md" 'read/action receipts'
require_phrase "$repo_dir/DESIGN.md" 'receiving agent host'
require_phrase "$repo_dir/DESIGN.md" 'cannot directly alter Punaro configuration'
require_phrase "$repo_dir/DESIGN.md" 'non-normative'
require_phrase "$repo_dir/DESIGN.md" '/v1/roles/list'
require_phrase "$repo_dir/DESIGN.md" '/v1/roles/resolve'
require_phrase "$repo_dir/docs/user-guide.md" 'What delivery status means'
require_phrase "$repo_dir/docs/user-guide.md" 'Active and idle agents'
require_phrase "$repo_dir/docs/user-guide.md" 'accepted/queued'
require_phrase "$repo_dir/docs/user-guide.md" 'mailbox acknowledgement'
require_phrase "$repo_dir/docs/user-guide.md" 'agent action'
require_phrase "$repo_dir/docs/user-guide.md" 'intentional, not a parity gap'
require_phrase "$repo_dir/docs/user-guide.md" 'punaro-adapter contacts resolve'
require_phrase "$repo_dir/docs/alpha-text-relay.md" 'accelerates adapter polling only'
require_phrase "$repo_dir/docs/alpha-text-relay.md" 'not ordinary message delivery'
require_phrase "$repo_dir/docs/alpha-text-relay.md" 'no sender receipt beyond append acceptance'
require_phrase "$repo_dir/docs/alpha-text-relay.md" 'punaro-adapter contacts resolve'
require_phrase "$repo_dir/docs/installation.md" 'accepted/queued'
require_phrase "$repo_dir/docs/installation.md" 'accelerates adapter polling only'
require_phrase "$repo_dir/docs/installation.md" 'Repeat bounded waits'
require_phrase "$repo_dir/docs/installation.md" 'does not itself create a model turn'

for path in \
	"$repo_dir/DESIGN.md" \
	"$repo_dir/docs/user-guide.md" \
	"$repo_dir/docs/alpha-text-relay.md" \
	"$repo_dir/docs/installation.md" \
	"$repo_dir/skills/punaro-mailbox/SKILL.md" \
	"$repo_dir/skills/punaro-reply/SKILL.md" \
	"$repo_dir/scripts/install-agent-guidance.sh" \
	"$repo_dir/scripts/install-agent-guidance.ps1" \
	"$project/AGENTS.md"; do
	forbid_phrase "$path" 'read receipt'
	forbid_phrase "$path" 'delivered/read'
	forbid_phrase "$path" 'automatic wake/resume'
	forbid_phrase "$path" 'cross-session permission approval'
	forbid_phrase "$path" 'non-Linux gateway support'
done

printf '%s\n' install_agent_guidance_tests_passed
