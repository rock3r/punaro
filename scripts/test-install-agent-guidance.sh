#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-guidance-test.XXXXXXXX")
cleanup() { rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

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

printf '%s\n' install_agent_guidance_tests_passed
