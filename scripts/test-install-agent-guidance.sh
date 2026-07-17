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

printf '%s\n' install_agent_guidance_tests_passed
