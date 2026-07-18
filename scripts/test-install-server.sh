#!/bin/sh
# Exercise a staging-root server install without touching a host's service
# manager or accounts.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-server-install-test.XXXXXXXX")
cleanup() { chmod -R u+w -- "$fixture_dir" 2>/dev/null || true; rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

stage="$fixture_dir/stage"
machines="$fixture_dir/machines.json"
printf '%s\n' '[{"id":"laptop","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/laptop/"]}]' >"$machines"
sh "$repo_dir/scripts/install-server.sh" --root "$stage" \
	--machines-file "$machines" \
	--access-issuer https://team.cloudflareaccess.example \
	--access-audience punaro-relay \
	--access-jwks-url https://team.cloudflareaccess.example/cdn-cgi/access/certs >"$fixture_dir/out"

[ -x "$stage/usr/local/bin/punarod" ] || { printf '%s\n' 'relay binary was not installed' >&2; exit 1; }
[ -f "$stage/etc/systemd/system/punarod.service" ] || { printf '%s\n' 'relay systemd unit was not installed' >&2; exit 1; }
[ -f "$stage/etc/punaro/punaro.env" ] || { printf '%s\n' 'relay environment file was not installed' >&2; exit 1; }
grep -Fqx 'PUNARO_RELAY_ENABLED=true' "$stage/etc/punaro/punaro.env"
grep -Fqx 'PUNARO_RELAY_MACHINES_JSON=[{"endpoint_prefixes":["agent/laptop/"],"id":"laptop","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]' "$stage/etc/punaro/punaro.env"
grep -Fqx 'PUNARO_ACCESS_ISSUER=https://team.cloudflareaccess.example' "$stage/etc/punaro/punaro.env"
grep -Fqx 'PUNARO_ACCESS_AUDIENCE=punaro-relay' "$stage/etc/punaro/punaro.env"
grep -Fqx 'PUNARO_ACCESS_JWKS_FILE=/etc/punaro/jwks/current.json' "$stage/etc/punaro/punaro.env"
[ -f "$stage/etc/systemd/system/punaro-jwks-refresh.service" ] || { printf '%s\n' 'JWKS refresh service was not installed' >&2; exit 1; }
[ -f "$stage/etc/systemd/system/punaro-jwks-refresh.timer" ] || { printf '%s\n' 'JWKS refresh timer was not installed' >&2; exit 1; }
[ -x "$stage/usr/local/libexec/punaro/refresh-jwks" ] || { printf '%s\n' 'JWKS refresh helper was not installed' >&2; exit 1; }
[ -f "$stage/etc/punaro/jwks-refresh.env" ] || { printf '%s\n' 'JWKS refresh environment was not installed' >&2; exit 1; }
grep -Fqx 'PUNARO_ACCESS_JWKS_URL=https://team.cloudflareaccess.example/cdn-cgi/access/certs' "$stage/etc/punaro/jwks-refresh.env"
grep -Fq 'Use --machines-file /approved/public-machines.json --enable' "$fixture_dir/out"

# A legacy online-JWKS configuration must migrate cleanly to the installer
# managed local snapshot rather than leaving two mutually exclusive sources.
legacy_stage="$fixture_dir/legacy-stage"
sh "$repo_dir/scripts/install-server.sh" --root "$legacy_stage" --machines-file "$machines" >"$fixture_dir/legacy-first.out"
printf '%s\n' \
	'PUNARO_ACCESS_ISSUER=https://team.cloudflareaccess.example' \
	'PUNARO_ACCESS_AUDIENCE=punaro-relay' \
	'PUNARO_ACCESS_JWKS_URL=https://team.cloudflareaccess.example/cdn-cgi/access/certs' >>"$legacy_stage/etc/punaro/punaro.env"
sh "$repo_dir/scripts/install-server.sh" --root "$legacy_stage" \
	--access-issuer https://team.cloudflareaccess.example \
	--access-audience punaro-relay \
	--access-jwks-url https://team.cloudflareaccess.example/cdn-cgi/access/certs >"$fixture_dir/legacy-upgrade.out"
grep -Fqx 'PUNARO_ACCESS_JWKS_FILE=/etc/punaro/jwks/current.json' "$legacy_stage/etc/punaro/punaro.env"
if grep -Fq 'PUNARO_ACCESS_JWKS_URL=' "$legacy_stage/etc/punaro/punaro.env"; then
	printf '%s\n' 'legacy online JWKS URL was left alongside the local snapshot' >&2
	exit 1
fi

# --enable is also the live-apply path: it must restart an active relay after
# configuration updates rather than only enabling a service that is already up.
grep -Fqx "$(printf '\tsystemctl enable punarod.service')" "$repo_dir/scripts/install-server.sh"
grep -Fqx "$(printf '\tsystemctl restart punarod.service')" "$repo_dir/scripts/install-server.sh"
if grep -Fqx "$(printf '\tsystemctl enable --now punarod.service')" "$repo_dir/scripts/install-server.sh"; then
	printf '%s\n' 'live relay configuration would not be applied to an already-running service' >&2
	exit 1
fi

set +e
sh "$repo_dir/scripts/install-server.sh" --root relative >"$fixture_dir/invalid.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'relative staging root was accepted' >&2; exit 1; }
grep -Fqx 'root directory must be an absolute path' "$fixture_dir/invalid.out"

set +e
sh "$repo_dir/scripts/install-server.sh" --root "$fixture_dir/partial-access" \
	--access-issuer https://team.cloudflareaccess.example >"$fixture_dir/partial-access.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'partial Access configuration was accepted' >&2; exit 1; }
grep -Fqx 'Cloudflare Access setup requires --access-issuer, --access-audience, and --access-jwks-url together' "$fixture_dir/partial-access.out"

printf '%s\n' install_server_tests_passed
