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
	require_phrase "$file" 'At the start of every session'
	require_phrase "$file" 'one non-blocking `waypost_recv`'
	require_phrase "$file" 'continue unrelated work and report the blocker once'
	require_phrase "$file" 'authorizes that exact send'
	require_phrase "$file" 'instead of asking again'
	grep -Fq -- '--to user-telegram' "$file" || { printf '%s\n' 'installed guidance omitted --to user-telegram' >&2; exit 1; }
	require_phrase "$file" 'accepted or queued, not read or acted upon'
	require_phrase "$file" 'Use the installed Punaro skills for mechanics'
	forbid_phrase "$file" 'For a bounded blocking wait'
	word_count=$(awk '
		index($0, "<!-- punaro-agent-guidance:start -->") { p=1; next }
		index($0, "<!-- punaro-agent-guidance:end -->") { p=0 }
		p { print }
	' "$file" | wc -w | tr -d ' ')
	[ "$word_count" -le 190 ] || { printf '%s\n' "installed guidance is too long: $word_count words" >&2; exit 1; }
done
[ -f "$project/.agents/skills/punaro-mailbox/SKILL.md" ]
[ -f "$project/.agents/skills/punaro-reply/SKILL.md" ]
[ -f "$project/.agents/skills/punaro-attachment/SKILL.md" ]
grep -Fq -- '--to user-telegram' "$project/.agents/skills/punaro-reply/SKILL.md" || { printf '%s\n' 'copied punaro-reply omitted --to user-telegram' >&2; exit 1; }
grep -Fq -- '--thread-id' "$project/.agents/skills/punaro-reply/SKILL.md" && { printf '%s\n' 'copied punaro-reply still teaches --thread-id' >&2; exit 1; }
grep -Eq 'telegram-major-updates|send_major_update' "$project/.agents/skills/punaro-reply/SKILL.md" || { printf '%s\n' 'copied punaro-reply omitted side-channel retirement' >&2; exit 1; }
grep -Fq -- '--to user-telegram' "$project/.agents/skills/punaro-mailbox/SKILL.md" || { printf '%s\n' 'copied punaro-mailbox omitted --to user-telegram' >&2; exit 1; }

for skill in punaro-mailbox punaro-reply punaro-attachment; do
	diff -qr "$repo_dir/skills/$skill" "$project/.agents/skills/$skill" >/dev/null || {
		printf '%s\n' "packaged skill does not match source guidance: $skill" >&2
		exit 1
	}
done

require_phrase "$project/AGENTS.md" 'accepted or queued, not read or acted upon'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'Repeat bounded waits'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'does not itself create a model turn'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'untrusted data'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'unqualified short name'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'qualified handle'
require_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'After status reports a warning or failure'
forbid_phrase "$project/.agents/skills/punaro-mailbox/SKILL.md" 'Before the first Punaro operation in a task'
require_phrase "$project/.agents/skills/punaro-reply/SKILL.md" 'After status reports a warning or failure'
forbid_phrase "$project/.agents/skills/punaro-reply/SKILL.md" 'Before the first Punaro operation in a task'
require_phrase "$project/.agents/skills/punaro-attachment/SKILL.md" 'After status reports a warning or failure'
forbid_phrase "$project/.agents/skills/punaro-attachment/SKILL.md" 'Before the first trusted-attachment operation in a task'
require_phrase "$project/.agents/skills/punaro-reply/SKILL.md" 'successful send proves relay acceptance only'
require_phrase "$project/.agents/skills/punaro-reply/SKILL.md" 'Do not infer read or action status'
require_phrase "$project/.agents/skills/punaro-reply/SKILL.md" 'host permission model'

for installer in "$repo_dir/scripts/install-agent-guidance.sh" "$repo_dir/scripts/install-agent-guidance.ps1"; do
	require_phrase "$installer" 'At the start of every session'
	require_phrase "$installer" 'authorizes that exact send'
	require_phrase "$installer" 'accepted or queued, not read or acted upon'
	require_phrase "$installer" 'predates telegram-origin-only send'
	require_phrase "$installer" 'predates Waypost'
done

managed_project="$fixture_dir/managed-project"
mkdir -p "$managed_project"
cat >"$managed_project/AGENTS.md" <<'EOF'
# Keep before

<!-- punaro-agent-guidance:start -->
## Punaro coordination

Use the local `agent-mailbox` MCP for Punaro-delivered mail.
<!-- punaro-agent-guidance:end -->

# Keep after
EOF
cp "$managed_project/AGENTS.md" "$managed_project/AGENTS.original"
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$managed_project" --guidance-only --replace-managed
managed_backup=$(find "$managed_project" -maxdepth 1 -type f -name 'AGENTS.md.punaro-backup.*' -print | head -n 1)
[ -n "$managed_backup" ] || { printf '%s\n' 'managed guidance replacement did not retain a recovery copy' >&2; exit 1; }
cmp -s "$managed_project/AGENTS.original" "$managed_backup" || { printf '%s\n' 'managed guidance recovery copy does not match the original' >&2; exit 1; }
cp "$managed_project/AGENTS.md" "$managed_project/AGENTS.after-first-replace"
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$managed_project" --guidance-only --replace-managed
cmp -s "$managed_project/AGENTS.after-first-replace" "$managed_project/AGENTS.md" || { printf '%s\n' 'managed guidance replacement was not idempotent' >&2; exit 1; }
require_phrase "$managed_project/AGENTS.md" '# Keep before'
require_phrase "$managed_project/AGENTS.md" '# Keep after'
require_phrase "$managed_project/AGENTS.md" 'At the start of every session'
forbid_phrase "$managed_project/AGENTS.md" 'Use the local `agent-mailbox` MCP'
[ ! -e "$managed_project/.agents" ] || { printf '%s\n' 'guidance-only install copied project skills' >&2; exit 1; }

signature_project="$fixture_dir/signature-project"
mkdir -p "$signature_project"
cat >"$signature_project/AGENTS.md" <<'EOF'
# Keep before
<!-- punaro-agent-guidance:start -->
At the start of every session, use Punaro.
An explicit request authorizes that exact send.
A send is accepted or queued, not read or acted upon.
STALE CONTENT THAT MUST BE REPLACED
<!-- punaro-agent-guidance:end -->
# Keep after
EOF
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$signature_project" --guidance-only --replace-managed
require_phrase "$signature_project/AGENTS.md" '# Keep before'
require_phrase "$signature_project/AGENTS.md" '# Keep after'
require_phrase "$signature_project/AGENTS.md" 'one non-blocking `waypost_recv`'
forbid_phrase "$signature_project/AGENTS.md" 'STALE CONTENT THAT MUST BE REPLACED'

misordered_project="$fixture_dir/misordered-project"
mkdir -p "$misordered_project"
cat >"$misordered_project/AGENTS.md" <<'EOF'
# Keep before
<!-- punaro-agent-guidance:end -->
# User instructions between reversed markers
<!-- punaro-agent-guidance:start -->
# Keep after
EOF
cp "$misordered_project/AGENTS.md" "$misordered_project/AGENTS.before"
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$misordered_project" --guidance-only --replace-managed >"$fixture_dir/misordered.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'misordered guidance markers were accepted' >&2; exit 1; }
cmp -s "$misordered_project/AGENTS.before" "$misordered_project/AGENTS.md" || { printf '%s\n' 'misordered guidance markers changed the target' >&2; exit 1; }
grep -Fq 'invalid existing Punaro guidance markers:' "$fixture_dir/misordered.out"

duplicate_project="$fixture_dir/duplicate-project"
mkdir -p "$duplicate_project"
cat >"$duplicate_project/AGENTS.md" <<'EOF'
<!-- punaro-agent-guidance:start -->
First block
<!-- punaro-agent-guidance:end -->
# User guidance between blocks
<!-- punaro-agent-guidance:start -->
Second block
<!-- punaro-agent-guidance:end -->
EOF
cp "$duplicate_project/AGENTS.md" "$duplicate_project/AGENTS.before"
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$duplicate_project" --guidance-only --replace-managed >"$fixture_dir/duplicate.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'duplicate guidance blocks were accepted' >&2; exit 1; }
cmp -s "$duplicate_project/AGENTS.before" "$duplicate_project/AGENTS.md" || { printf '%s\n' 'duplicate guidance blocks changed the target' >&2; exit 1; }
grep -Fq 'invalid existing Punaro guidance markers:' "$fixture_dir/duplicate.out"

crlf_project="$fixture_dir/crlf-project"
mkdir -p "$crlf_project"
printf '# Keep before\r\n<!-- punaro-agent-guidance:start -->\r\nOld block\r\n<!-- punaro-agent-guidance:end -->\r\n# Keep after\r\n' >"$crlf_project/AGENTS.md"
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$crlf_project" --guidance-only --replace-managed
require_phrase "$crlf_project/AGENTS.md" '# Keep before'
require_phrase "$crlf_project/AGENTS.md" '# Keep after'
require_phrase "$crlf_project/AGENTS.md" 'one non-blocking `waypost_recv`'
forbid_phrase "$crlf_project/AGENTS.md" 'Old block'
awk 'index($0, "<!-- punaro-agent-guidance:start -->") && substr($0, length($0), 1) != "\r" { exit 1 }' "$crlf_project/AGENTS.md" || { printf '%s\n' 'CRLF replacement changed the managed block line endings' >&2; exit 1; }

fresh_replace_project="$fixture_dir/fresh-replace-project"
mkdir -p "$fresh_replace_project"
printf '%s\n' '# Existing global guidance' >"$fresh_replace_project/AGENTS.md"
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$fresh_replace_project" --guidance-only --replace-managed
require_phrase "$fresh_replace_project/AGENTS.md" '# Existing global guidance'
require_phrase "$fresh_replace_project/AGENTS.md" 'At the start of every session'

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

stale_send_project="$fixture_dir/stale-send-project"
mkdir -p "$stale_send_project"
cat >"$stale_send_project/AGENTS.md" <<'EOF'
<!-- punaro-agent-guidance:start -->
## Punaro coordination

Reply only with `punaro-adapter send` using the typed envelope conversation ID and a stable idempotency key.
For attachments, use the `punaro-attachment` skill and installed `punaro-trusted-attachment` client only for one explicit task-owner-authorized operation.
<!-- punaro-agent-guidance:end -->
EOF
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$stale_send_project" >"$fixture_dir/stale-send.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'stale conversation-id send guidance was silently retained' >&2; exit 1; }
grep -Fq 'existing Punaro guidance predates user-telegram send:' "$fixture_dir/stale-send.out"
grep -Fq 'typed envelope conversation ID' "$stale_send_project/AGENTS.md"
grep -Fq -- '--to user-telegram' "$stale_send_project/AGENTS.md" && { printf '%s\n' 'stale guidance was rewritten in place' >&2; exit 1; }

stale_claimed_project="$fixture_dir/stale-claimed-project"
mkdir -p "$stale_claimed_project"
cat >"$stale_claimed_project/AGENTS.md" <<'EOF'
<!-- punaro-agent-guidance:start -->
## Punaro coordination

Reply only with `punaro-adapter send --to user-telegram` when the envelope is from `user-telegram` or the session has a claimed topic, using a stable idempotency key. A successful send proves relay acceptance only (`accepted/queued`).
For attachments, use the `punaro-attachment` skill and installed `punaro-trusted-attachment` client only for one explicit task-owner-authorized operation.
<!-- punaro-agent-guidance:end -->
EOF
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$stale_claimed_project" >"$fixture_dir/stale-claimed.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'claimed-topic send guidance was silently retained' >&2; exit 1; }
grep -Fq 'existing Punaro guidance predates telegram-origin-only send:' "$fixture_dir/stale-claimed.out"
grep -Fq 'or the session has a claimed topic' "$stale_claimed_project/AGENTS.md"
grep -Fq 'envelope is from `user-telegram`,' "$stale_claimed_project/AGENTS.md" && { printf '%s\n' 'claimed-topic guidance was rewritten in place' >&2; exit 1; }

stale_reply_project="$fixture_dir/stale-reply-project"
mkdir -p "$stale_reply_project/.agents/skills/punaro-reply"
printf '%s\n' '# Reply with punaro-adapter send --conversation CONVERSATION_ID' >"$stale_reply_project/.agents/skills/punaro-reply/SKILL.md"
set +e
sh "$repo_dir/scripts/install-agent-guidance.sh" --directory "$stale_reply_project" >"$fixture_dir/stale-reply.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'stale punaro-reply skill was overwritten or ignored' >&2; exit 1; }
grep -Fq 'existing punaro-reply skill predates user-telegram send at' "$fixture_dir/stale-reply.out"
grep -Fq -- '--conversation CONVERSATION_ID' "$stale_reply_project/.agents/skills/punaro-reply/SKILL.md"

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
grep -Fq 'existing Punaro guidance predates Waypost:' "$fixture_dir/stale.out"
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
grep -Fq 'existing Punaro guidance predates Waypost:' "$fixture_dir/outside.out"
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
require_phrase "$repo_dir/docs/installation.md" '--guidance-only --replace-managed'
require_phrase "$repo_dir/docs/installation.md" '-GuidanceOnly -ReplaceManaged'
require_phrase "$repo_dir/docs/installation.md" 'global guidance expects the Punaro plugin'
require_phrase "$repo_dir/docs/agent-plugin.md" 'After status reports a warning or failure'
forbid_phrase "$repo_dir/docs/agent-plugin.md" 'before first use when readiness is uncertain'
require_phrase "$repo_dir/docs/installation.md" 'New agent sessions load the updated global guidance'

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
