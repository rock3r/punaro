#!/bin/sh
# Exercise v3 relay configuration in a staging root. No service is enabled.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-attachment-relay-test.XXXXXXXX")
cleanup() { chmod -R u+w -- "$fixture_dir" 2>/dev/null || true; rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

file_mode() {
	case "$(uname -s)" in
		Darwin) stat -f %Lp "$1" ;;
		*) stat -c %a "$1" ;;
	esac
}

stage="$fixture_dir/stage"
authority="$fixture_dir/authority"
client="$fixture_dir/client"
snapshot="$fixture_dir/directory.snapshot"
machines="$fixture_dir/machines.json"

sh "$repo_dir/scripts/install-server.sh" --root "$stage" >/dev/null
sh "$repo_dir/scripts/provision-attachment-v3.sh" authority --directory "$authority" >/dev/null
sh "$repo_dir/scripts/provision-attachment-v3.sh" client \
	--directory "$client" --authority-public "$authority/public.json" --machine-id macbook \
	--relay-url https://relay.example.invalid --role receiver >/dev/null
sh "$repo_dir/scripts/provision-attachment-v3.sh" authority-add-device \
	--directory "$authority" --device-enrollment "$client/device-enrollment.json" >/dev/null

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-attachment-relay-build.XXXXXXXX")
trap 'rm -rf -- "$build_dir"; cleanup' EXIT HUP INT TERM
(
	cd "$repo_dir"
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-directory" ./cmd/punaro-directory
)
"$build_dir/punaro-directory" build --config "$authority/directory-manifest.json" \
	--root-private-key-file "$authority/root.private" --output "$snapshot" --ttl 2m

device_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["attachment_device_id"])' "$client/device-enrollment.json")
printf '%s\n' "[{\"id\":\"macbook\",\"public_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"endpoint_prefixes\":[\"agent/macbook/\"],\"attachment_device_id\":\"$device_id\"}]" >"$machines"

sh "$repo_dir/scripts/configure-attachment-v3-relay.sh" --root "$stage" \
	--authority-public "$authority/public.json" --issuer-private-key "$authority/issuer.private" \
	--directory-snapshot "$snapshot" --relay-machines-file "$machines" >"$fixture_dir/out"

config="$stage/etc/punaro/punaro.env"
issuer="$stage/etc/punaro/credentials/v3-issuer.private"
published_snapshot="$stage/etc/punaro/directory/v3-directory.snapshot"
[ -f "$issuer" ] || { printf '%s\n' 'relay issuer key was not installed' >&2; exit 1; }
[ -f "$published_snapshot" ] || { printf '%s\n' 'relay directory snapshot was not installed' >&2; exit 1; }
[ "$(file_mode "$issuer")" = 600 ] || { printf '%s\n' 'relay issuer key is not private' >&2; exit 1; }
grep -Fqx 'PUNARO_ATTACHMENT_V3_ENABLED=true' "$config"
grep -Fqx 'PUNARO_PERMIT_ISSUANCE_ENABLED=false' "$config"
grep -Fqx 'PUNARO_ATTACHMENTS_ENABLED=false' "$config"
grep -Fqx 'PUNARO_ATTACHMENT_RELAY_ENABLED=false' "$config"
grep -Fqx 'PUNARO_DIRECTORY_ENABLED=true' "$config"
grep -Fqx 'PUNARO_DIRECTORY_SNAPSHOT_FILE=/etc/punaro/directory/v3-directory.snapshot' "$config"
grep -Fq "PUNARO_RELAY_MACHINES_JSON=[{\"attachment_device_id\":\"$device_id\"" "$config"
if grep -Fq -- "$(cat "$authority/issuer.private")" "$config" "$fixture_dir/out"; then
	printf '%s\n' 'relay configuration leaked the issuer private key' >&2; exit 1
fi
grep -Fq 'systemctl restart punarod.service' "$repo_dir/scripts/configure-attachment-v3-relay.sh"

symlink_stage="$fixture_dir/symlink-stage"
sh "$repo_dir/scripts/install-server.sh" --root "$symlink_stage" >/dev/null
mkdir "$fixture_dir/redirected-state"
ln -s "$fixture_dir/redirected-state" "$symlink_stage/etc/punaro/directory"
set +e
sh "$repo_dir/scripts/configure-attachment-v3-relay.sh" --root "$symlink_stage" \
	--authority-public "$authority/public.json" --issuer-private-key "$authority/issuer.private" \
	--directory-snapshot "$snapshot" --relay-machines-file "$machines" >"$fixture_dir/symlink-state.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'relay configuration followed a directory snapshot symlink' >&2; exit 1; }
grep -Fqx 'directory snapshot parent must be a non-symlink directory' "$fixture_dir/symlink-state.out"

printf '%s\n' '[{"id":"macbook","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","endpoint_prefixes":["agent/macbook/"]}]' >"$fixture_dir/no-device-binding.json"
set +e
sh "$repo_dir/scripts/configure-attachment-v3-relay.sh" --root "$stage" \
	--authority-public "$authority/public.json" --issuer-private-key "$authority/issuer.private" \
	--directory-snapshot "$snapshot" --relay-machines-file "$fixture_dir/no-device-binding.json" >"$fixture_dir/no-binding.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'relay configuration accepted unbound machines' >&2; exit 1; }
grep -Fqx 'relay machine enrollment must contain an attachment_device_id binding' "$fixture_dir/no-binding.out"

printf '%s\n' "[{\"id\":\"macbook\",\"public_key\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"endpoint_prefixes\":[\"agent/macbook/\"],\"attachment_device_id\":\"$device_id\",\"private_key\":\"forbidden\"}]" >"$fixture_dir/private-machine-field.json"
set +e
sh "$repo_dir/scripts/configure-attachment-v3-relay.sh" --root "$stage" \
	--authority-public "$authority/public.json" --issuer-private-key "$authority/issuer.private" \
	--directory-snapshot "$snapshot" --relay-machines-file "$fixture_dir/private-machine-field.json" >"$fixture_dir/private-machine-field.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'relay configuration accepted a private machine field' >&2; exit 1; }
grep -Fqx 'relay machine enrollment contains unsupported or secret fields' "$fixture_dir/private-machine-field.out"

printf '%s\n' attachment_v3_relay_configuration_tests_passed
