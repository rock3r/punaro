#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-retired-attachment-relay-test.XXXXXXXX")
cleanup() { rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

sentinel="$fixture_dir/sentinel"
printf '%s\n' unchanged >"$sentinel"
set +e
sh "$repo_dir/scripts/configure-attachment-v3-relay.sh" --root "$fixture_dir" --enable >"$fixture_dir/out" 2>&1
status=$?
set -e

[ "$status" -eq 2 ] || { printf '%s\n' 'retired relay configurer did not fail closed' >&2; exit 1; }
grep -Fq 'attachment v3 relay configuration is retired' "$fixture_dir/out"
[ "$(cat "$sentinel")" = unchanged ] || { printf '%s\n' 'retired relay configurer changed existing state' >&2; exit 1; }
[ "$(find "$fixture_dir" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')" -eq 2 ] || {
	printf '%s\n' 'retired relay configurer created deployment state' >&2
	exit 1
}
if grep -Eq 'systemctl|install -|mkdir|cp |mv |rm ' "$repo_dir/scripts/configure-attachment-v3-relay.sh"; then
	printf '%s\n' 'retired relay configurer still contains mutation commands' >&2
	exit 1
fi

printf '%s\n' attachment_v3_relay_retirement_tests_passed
