#!/bin/sh
# Exercise a staging-root server install without touching a host's service
# manager or accounts.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-server-install-test.XXXXXXXX")
cleanup() { chmod -R u+w -- "$fixture_dir" 2>/dev/null || true; rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

stage="$fixture_dir/stage"
sh "$repo_dir/scripts/install-server.sh" --root "$stage" >"$fixture_dir/out"

[ -x "$stage/usr/local/bin/punarod" ] || { printf '%s\n' 'relay binary was not installed' >&2; exit 1; }
[ -f "$stage/etc/systemd/system/punarod.service" ] || { printf '%s\n' 'relay systemd unit was not installed' >&2; exit 1; }
[ -f "$stage/etc/punaro/punaro.env" ] || { printf '%s\n' 'relay environment file was not installed' >&2; exit 1; }
grep -Fqx 'PUNARO_RELAY_ENABLED=true' "$stage/etc/punaro/punaro.env"
grep -Fq 'PUNARO_RELAY_MACHINES_JSON=' "$stage/etc/punaro/punaro.env"
grep -Fq 'systemctl daemon-reload' "$fixture_dir/out"

set +e
sh "$repo_dir/scripts/install-server.sh" --root relative >"$fixture_dir/invalid.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'relative staging root was accepted' >&2; exit 1; }
grep -Fqx 'root directory must be an absolute path' "$fixture_dir/invalid.out"

printf '%s\n' install_server_tests_passed
