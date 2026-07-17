#!/bin/sh
# Configure a previously installed Punaro relay for the separately versioned
# attachment-v3 runtime. All inputs are local files: private material is never
# accepted through command-line values or printed by this script.
set -eu

umask 077

usage() {
	cat <<'EOF'
Usage: scripts/configure-attachment-v3-relay.sh \
  --authority-public ABSOLUTE_PUBLIC_JSON \
  --issuer-private-key ABSOLUTE_PRIVATE_KEY \
  --directory-snapshot ABSOLUTE_SIGNED_SNAPSHOT \
  --relay-machines-file ABSOLUTE_PUBLIC_JSON \
  [--root ABSOLUTE_STAGING_ROOT] [--enable]

Run after install-server.sh. It installs a private issuer credential and the
current root-signed directory snapshot, writes the v3-only relay settings, and
requires each configured transport machine to be explicitly bound to an
attachment device. --enable starts the systemd service only on a live Linux
relay; it is unavailable with --root.
EOF
}

fail() { printf '%s\n' "$1" >&2; exit 2; }

file_mode() {
	if stat -f %Lp "$1" >/dev/null 2>&1; then stat -f %Lp "$1"; else stat -c %a "$1"; fi
}

require_absolute_regular_file() {
	case "$1" in /*) ;; *) fail "$2 must be an absolute path" ;; esac
	[ -f "$1" ] && [ ! -L "$1" ] || fail "$2 must be a non-symlink regular file"
}

root_dir=/
authority_public=
issuer_private_key=
directory_snapshot=
relay_machines_file=
enable=0
while [ "$#" -gt 0 ]; do
	case "$1" in
		--root) [ "$#" -ge 2 ] || fail '--root requires a value'; root_dir=$2; shift 2 ;;
		--authority-public) [ "$#" -ge 2 ] || fail '--authority-public requires a value'; authority_public=$2; shift 2 ;;
		--issuer-private-key) [ "$#" -ge 2 ] || fail '--issuer-private-key requires a value'; issuer_private_key=$2; shift 2 ;;
		--directory-snapshot) [ "$#" -ge 2 ] || fail '--directory-snapshot requires a value'; directory_snapshot=$2; shift 2 ;;
		--relay-machines-file) [ "$#" -ge 2 ] || fail '--relay-machines-file requires a value'; relay_machines_file=$2; shift 2 ;;
		--enable) enable=1; shift ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

case "$root_dir" in /*) ;; *) fail 'root directory must be an absolute path' ;; esac
[ -n "$authority_public" ] || fail '--authority-public is required'
[ -n "$issuer_private_key" ] || fail '--issuer-private-key is required'
[ -n "$directory_snapshot" ] || fail '--directory-snapshot is required'
[ -n "$relay_machines_file" ] || fail '--relay-machines-file is required'
require_absolute_regular_file "$authority_public" 'authority public record'
require_absolute_regular_file "$issuer_private_key" 'issuer private key'
require_absolute_regular_file "$directory_snapshot" 'directory snapshot'
require_absolute_regular_file "$relay_machines_file" 'relay machines file'
[ "$(file_mode "$issuer_private_key")" = 600 ] || fail 'issuer private key must have mode 0600'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required to validate and render relay configuration'

if [ "$root_dir" = / ]; then
	[ "$(uname -s)" = Linux ] || fail 'live v3 relay configuration supports Linux systemd hosts only'
	[ "$(id -u)" -eq 0 ] || fail 'run live v3 relay configuration as root'
else
	[ "$enable" -eq 0 ] || fail '--enable is unavailable with a staging root'
fi

path_in_root() {
	if [ "$root_dir" = / ]; then printf '/%s\n' "$1"; else printf '%s/%s\n' "${root_dir%/}" "$1"; fi
}

config_file=$(path_in_root etc/punaro/punaro.env)
credentials_dir=$(path_in_root etc/punaro/credentials)
issuer_destination="$credentials_dir/v3-issuer.private"
private_dir=$(path_in_root var/lib/punaro/private)
snapshot_destination="$private_dir/v3-directory.snapshot"
v3_state_dir=$(path_in_root var/lib/punaro/attachment-v3)
[ -f "$config_file" ] && [ ! -L "$config_file" ] || fail 'install-server must create a regular relay configuration before v3 configuration'
issuer_stage="$issuer_destination.v3-next"
snapshot_stage="$snapshot_destination.v3-next"
config_stage="$config_file.v3-next"
[ ! -e "$issuer_stage" ] && [ ! -L "$issuer_stage" ] || fail 'staged issuer file already exists; inspect it before retrying'
[ ! -e "$snapshot_stage" ] && [ ! -L "$snapshot_stage" ] || fail 'staged snapshot file already exists; inspect it before retrying'
[ ! -e "$config_stage" ] && [ ! -L "$config_stage" ] || fail 'staged relay configuration already exists; inspect it before retrying'
cleanup_staged() {
	rm -f -- "$issuer_stage" "$snapshot_stage" "$config_stage"
}
trap cleanup_staged EXIT HUP INT TERM

render_error=$(mktemp "${TMPDIR:-/tmp}/punaro-attachment-relay-render.XXXXXXXX")
if ! python3 - "$config_file" "$authority_public" "$relay_machines_file" \
	'/etc/punaro/credentials/v3-issuer.private' '/var/lib/punaro/private/v3-directory.snapshot' \
	'/var/lib/punaro/attachment-v3/source.db' <<'PY' 2>"$render_error"
import base64
import json
import os
import sys

config_path, authority_path, machines_path, issuer_path, snapshot_path, source_store_path = sys.argv[1:]

def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)

def valid(value, size):
    if not isinstance(value, str) or "=" in value:
        raise ValueError("invalid public value")
    if len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) != size:
        raise ValueError("unexpected public value length")
    return value

authority = read_json(authority_path)
if authority.get("version") != 3:
    raise ValueError("authority public record must be version 3")
audience = valid(authority.get("audience"), 32)
root_key_id = valid(authority.get("root_key_id"), 32)
root_public_key = valid(authority.get("root_public_key"), 32)
issuer_key_id = valid(authority.get("issuer_key_id"), 32)
valid(authority.get("issuer_public_key"), 32)

machines = read_json(machines_path)
if not isinstance(machines, list) or not machines:
    raise ValueError("relay machine enrollment must be a non-empty JSON array")
bound = 0
seen_ids = set()
seen_devices = set()
for machine in machines:
    if not isinstance(machine, dict) or not isinstance(machine.get("id"), str) or machine["id"] in seen_ids:
        raise ValueError("relay machine enrollment contains invalid or duplicate machine IDs")
    seen_ids.add(machine["id"])
    device = machine.get("attachment_device_id")
    if device is not None:
        valid(device, 16)
        if device in seen_devices:
            raise ValueError("relay machine enrollment reuses an attachment_device_id")
        seen_devices.add(device)
        bound += 1
if bound == 0:
    raise ValueError("relay machine enrollment must contain an attachment_device_id binding")
machines_json = json.dumps(machines, sort_keys=True, separators=(",", ":"))

managed = {
    "PUNARO_DIRECTORY_ENABLED",
    "PUNARO_DIRECTORY_SNAPSHOT_FILE",
    "PUNARO_DIRECTORY_AUDIENCE",
    "PUNARO_DIRECTORY_ROOT_KEY_ID",
    "PUNARO_DIRECTORY_ROOT_PUBLIC_KEY",
    "PUNARO_PERMIT_ISSUANCE_ENABLED",
    "PUNARO_PERMIT_ISSUER_KEY_ID",
    "PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE",
    "PUNARO_PERMIT_MAX_LIFETIME_SECONDS",
    "PUNARO_PERMIT_MAX_BYTES",
    "PUNARO_PERMIT_MAX_CHUNKS",
    "PUNARO_PERMIT_MAX_OPERATIONS",
    "PUNARO_PERMIT_MAX_ACTIVE",
    "PUNARO_ATTACHMENT_V3_ENABLED",
    "PUNARO_ATTACHMENT_V3_SOURCE_STORE_FILE",
    "PUNARO_ATTACHMENTS_ENABLED",
    "PUNARO_ATTACHMENT_RELAY_ENABLED",
    "PUNARO_RELAY_MACHINES_JSON",
}
with open(config_path, encoding="utf-8") as handle:
    retained = [line.rstrip("\n") for line in handle if line.split("=", 1)[0].strip() not in managed]
settings = {
    "PUNARO_RELAY_MACHINES_JSON": machines_json,
    "PUNARO_DIRECTORY_ENABLED": "true",
    "PUNARO_DIRECTORY_SNAPSHOT_FILE": snapshot_path,
    "PUNARO_DIRECTORY_AUDIENCE": audience,
    "PUNARO_DIRECTORY_ROOT_KEY_ID": root_key_id,
    "PUNARO_DIRECTORY_ROOT_PUBLIC_KEY": root_public_key,
    "PUNARO_PERMIT_ISSUANCE_ENABLED": "false",
    "PUNARO_PERMIT_ISSUER_KEY_ID": issuer_key_id,
    "PUNARO_PERMIT_ISSUER_PRIVATE_KEY_FILE": issuer_path,
    "PUNARO_PERMIT_MAX_LIFETIME_SECONDS": "30",
    "PUNARO_PERMIT_MAX_BYTES": str(64 << 20),
    "PUNARO_PERMIT_MAX_CHUNKS": "4096",
    "PUNARO_PERMIT_MAX_OPERATIONS": "4096",
    "PUNARO_PERMIT_MAX_ACTIVE": "4096",
    "PUNARO_ATTACHMENT_V3_ENABLED": "true",
    "PUNARO_ATTACHMENT_V3_SOURCE_STORE_FILE": source_store_path,
    "PUNARO_ATTACHMENTS_ENABLED": "false",
    "PUNARO_ATTACHMENT_RELAY_ENABLED": "false",
}
temporary = config_path + ".v3-next"
fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    for line in retained:
        handle.write(line + "\n")
    handle.write("\n# Attachment v3: generated from explicit local public records and private files.\n")
    for key in sorted(settings):
        handle.write(f"{key}={settings[key]}\n")
os.chmod(temporary, 0o640)
PY
then
	message=$(sed -n '$s/^ValueError: //p' "$render_error")
	rm -f -- "$render_error"
	[ -n "$message" ] || message='could not validate or render attachment v3 relay configuration'
	fail "$message"
fi
rm -f -- "$render_error"

[ -f "$config_stage" ] && [ ! -L "$config_stage" ] || fail 'could not safely render staged relay configuration'

if [ "$root_dir" = / ]; then
	install -d -o root -g punaro -m 0750 "$credentials_dir"
	install -d -o root -g punaro -m 2750 "$private_dir"
	install -d -o punaro -g punaro -m 0700 "$v3_state_dir"
	install -m 0600 -o punaro -g punaro "$issuer_private_key" "$issuer_stage"
	install -m 0640 -o root -g punaro "$directory_snapshot" "$snapshot_stage"
else
	install -d -m 0700 "$credentials_dir" "$private_dir" "$v3_state_dir"
	install -m 0600 "$issuer_private_key" "$issuer_stage"
	install -m 0600 "$directory_snapshot" "$snapshot_stage"
fi
mv -f -- "$issuer_stage" "$issuer_destination"
mv -f -- "$snapshot_stage" "$snapshot_destination"
mv -f -- "$config_stage" "$config_file"

if [ "$root_dir" = / ]; then
	chown root:punaro "$config_file"
	chmod 0640 "$config_file"
fi

if [ "$enable" -eq 1 ]; then
	systemctl daemon-reload
	systemctl enable --now punarod.service
	systemctl is-active --quiet punarod.service
fi

printf '%s\n' 'attachment_v3_relay_configured'
printf '%s\n' 'V3 remains fail-closed until the signed directory is current and each machine-to-device binding matches a directory device.'
if [ "$enable" -eq 0 ]; then
	printf '%s\n' 'After reviewing the relay machine bindings, rerun with --enable on the Linux relay host.'
fi
