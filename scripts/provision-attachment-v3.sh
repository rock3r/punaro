#!/bin/sh
# Provision the local key material and public records required by Punaro
# attachment v3. This does not enable transfer: relay activation and explicit
# device/membership approval remain separate, fail-closed operator actions.
set -eu

umask 077

usage() {
	cat <<'EOF'
Usage:
  scripts/provision-attachment-v3.sh authority --directory ABSOLUTE_PRIVATE_DIRECTORY
  scripts/provision-attachment-v3.sh client --directory ABSOLUTE_PRIVATE_DIRECTORY \
    --authority-public ABSOLUTE_PUBLIC_JSON --machine-id ID \
    --role receiver|sender|both \
    [--host-key-service SERVICE --host-key-account ACCOUNT] \
    [--host-credential-directory DIRECTORY --host-credential-name NAME] \
    [--adapter-data-dir ABSOLUTE_DIRECTORY]

authority creates an offline root key, an issuer key, and public directory
records. Keep its directory off the relay and out of backups shared with
clients. client creates one device's signing and HPKE key material locally and
prints only a public enrollment record. Sender-capable devices require a
host-bound wrapping-key reference: Keychain service/account on macOS, or a
systemd credential directory/name on Linux. Provide the key itself through the
platform credential store, never through this command or an environment file.
EOF
}

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

require_absolute_new_directory() {
	case "$1" in
		/*) ;;
		*) fail "$2 must be an absolute path" ;;
	esac
	[ ! -e "$1" ] && [ ! -L "$1" ] || fail "$2 must not already exist"
}

require_absolute_regular_file() {
	case "$1" in
		/*) ;;
		*) fail "$2 must be an absolute path" ;;
	esac
	[ -f "$1" ] && [ ! -L "$1" ] || fail "$2 must be a non-symlink regular file"
}

require_absolute_private_directory() {
	case "$1" in
		/*) ;;
		*) fail "$2 must be an absolute path" ;;
	esac
	[ -d "$1" ] && [ ! -L "$1" ] || fail "$2 must be a non-symlink directory"
	if stat -f %Lp "$1" >/dev/null 2>&1; then mode=$(stat -f %Lp "$1"); else mode=$(stat -c %a "$1"); fi
	[ "$mode" = 700 ] || fail "$2 must have mode 0700"
}

require_safe_dotenv_value() {
	case "$1" in
		''|*[!A-Za-z0-9_./:@%+=,-]*) fail "$2 contains unsupported characters" ;;
	esac
}

require_machine_id() {
	case "$1" in
		''|*[!A-Za-z0-9._-]*|.*|-*) fail 'machine ID must start with a letter or digit and contain only letters, digits, dot, underscore, or hyphen' ;;
	esac
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
[ -f "$repo_dir/go.mod" ] && [ -d "$repo_dir/cmd/punaro-directory" ] || fail 'run this provisioner from a complete Punaro source checkout'
command -v go >/dev/null 2>&1 || fail 'Go is required to provision attachment v3 material from this checkout'
command -v python3 >/dev/null 2>&1 || fail 'python3 is required to render public provisioning records'

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-attachment-provision.XXXXXXXX")
cleanup() { rm -rf -- "$build_dir"; }
trap cleanup EXIT HUP INT TERM
(
	cd "$repo_dir"
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-directory" ./cmd/punaro-directory
)
directory_bin="$build_dir/punaro-directory"

new_id() {
	"$directory_bin" id --bytes "$1" >"$2"
}

authority() {
	directory=
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--directory) [ "$#" -ge 2 ] || fail '--directory requires a value'; directory=$2; shift 2 ;;
			--help) usage; exit 0 ;;
			*) fail "unknown authority option: $1" ;;
		esac
	done
	[ -n "$directory" ] || fail 'authority requires --directory'
	require_absolute_new_directory "$directory" 'authority directory'
	require_safe_dotenv_value "$directory" 'authority directory'
	mkdir -m 700 "$directory"

	"$directory_bin" keygen --algorithm ed25519 --private-key-file "$directory/root.private" >"$build_dir/root.public.json"
	"$directory_bin" keygen --algorithm ed25519 --private-key-file "$directory/issuer.private" >"$build_dir/issuer.public.json"
	new_id 32 "$build_dir/audience.json"
	new_id 32 "$build_dir/root-key-id.json"
	new_id 32 "$build_dir/issuer-key-id.json"
	chmod 600 "$directory/root.private" "$directory/issuer.private"

	python3 - "$directory" "$build_dir/audience.json" "$build_dir/root-key-id.json" "$build_dir/root.public.json" "$build_dir/issuer-key-id.json" "$build_dir/issuer.public.json" <<'PY'
import base64
import json
import os
import sys

directory, audience_path, root_id_path, root_path, issuer_id_path, issuer_path = sys.argv[1:]

def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)

def valid(value, size):
    if not isinstance(value, str) or "=" in value:
        raise ValueError("invalid public value")
    if base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)).__len__() != size:
        raise ValueError("unexpected public value length")
    return value

audience = valid(read_json(audience_path)["id"], 32)
root_key_id = valid(read_json(root_id_path)["id"], 32)
root_public_key = valid(read_json(root_path)["public_key"], 32)
issuer_key_id = valid(read_json(issuer_id_path)["id"], 32)
issuer_public_key = valid(read_json(issuer_path)["public_key"], 32)

public = {
    "version": 3,
    "audience": audience,
    "root_key_id": root_key_id,
    "root_public_key": root_public_key,
    "issuer_key_id": issuer_key_id,
    "issuer_public_key": issuer_public_key,
}
manifest = {
    "audience": audience,
    "root_key_id": root_key_id,
    "sequence": 1,
    "revocation_epoch": 1,
    "entries": [{"issuer": {"key_id": issuer_key_id, "public_key": issuer_public_key, "revoked": False}}],
}

for name, value, mode in (("public.json", public, 0o600), ("directory-manifest.json", manifest, 0o600)):
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    os.chmod(path, mode)
PY
	printf '%s\n' 'attachment_v3_authority_provisioned'
	printf '%s\n' "Public authority record: $directory/public.json"
	printf '%s\n' "Directory manifest seed: $directory/directory-manifest.json"
	printf '%s\n' 'Keep root.private offline. Copy only public.json and approved public device entries between roles.'
}

client() {
	directory=
	authority_public=
	machine_id=
	role=
	host_key_service=
	host_key_account=
	host_credential_directory=
	host_credential_name=
	adapter_data_dir="$HOME/.local/state/punaro-adapter"
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--directory) [ "$#" -ge 2 ] || fail '--directory requires a value'; directory=$2; shift 2 ;;
			--authority-public) [ "$#" -ge 2 ] || fail '--authority-public requires a value'; authority_public=$2; shift 2 ;;
			--machine-id) [ "$#" -ge 2 ] || fail '--machine-id requires a value'; machine_id=$2; shift 2 ;;
			--role) [ "$#" -ge 2 ] || fail '--role requires a value'; role=$2; shift 2 ;;
			--host-key-service) [ "$#" -ge 2 ] || fail '--host-key-service requires a value'; host_key_service=$2; shift 2 ;;
			--host-key-account) [ "$#" -ge 2 ] || fail '--host-key-account requires a value'; host_key_account=$2; shift 2 ;;
			--host-credential-directory) [ "$#" -ge 2 ] || fail '--host-credential-directory requires a value'; host_credential_directory=$2; shift 2 ;;
			--host-credential-name) [ "$#" -ge 2 ] || fail '--host-credential-name requires a value'; host_credential_name=$2; shift 2 ;;
			--adapter-data-dir) [ "$#" -ge 2 ] || fail '--adapter-data-dir requires a value'; adapter_data_dir=$2; shift 2 ;;
			--help) usage; exit 0 ;;
			*) fail "unknown client option: $1" ;;
		esac
	done
	[ -n "$directory" ] || fail 'client requires --directory'
	[ -n "$authority_public" ] || fail 'client requires --authority-public'
	[ -n "$machine_id" ] || fail 'client requires --machine-id'
	case "$role" in receiver|sender|both) ;; *) fail '--role must be receiver, sender, or both' ;; esac
	require_absolute_new_directory "$directory" 'client directory'
	require_absolute_regular_file "$authority_public" 'authority public record'
	require_safe_dotenv_value "$directory" 'client directory'
	require_safe_dotenv_value "$adapter_data_dir" 'adapter data directory'
	require_machine_id "$machine_id"
	host_platform=$(uname -s)
	if [ "$role" = sender ] || [ "$role" = both ]; then
		case "$host_platform" in
			Darwin)
				[ -n "$host_key_service" ] && [ -n "$host_key_account" ] || fail 'sender provisioning requires --host-key-service and --host-key-account'
				[ -z "$host_credential_directory$host_credential_name" ] || fail 'macOS sender provisioning does not accept systemd credential references'
				require_safe_dotenv_value "$host_key_service" 'host key service'
				require_safe_dotenv_value "$host_key_account" 'host key account'
				;;
			*)
				[ -n "$host_credential_directory" ] && [ -n "$host_credential_name" ] || fail 'sender provisioning requires --host-credential-directory and --host-credential-name'
				[ -z "$host_key_service$host_key_account" ] || fail 'Linux sender provisioning does not accept macOS keychain references'
				require_safe_dotenv_value "$host_credential_directory" 'host credential directory'
				require_safe_dotenv_value "$host_credential_name" 'host credential name'
				;;
		esac
	elif [ -n "$host_key_service$host_key_account$host_credential_directory$host_credential_name" ]; then
		fail 'host key references are only valid for sender-capable provisioning'
	fi
	mkdir -m 700 "$directory"

	"$directory_bin" keygen --algorithm ed25519 --private-key-file "$directory/device-signing.private" >"$build_dir/device-signing.public.json"
	"$directory_bin" keygen --algorithm x25519 --private-key-file "$directory/device-hpke.private" >"$build_dir/device-hpke.public.json"
	new_id 16 "$build_dir/device-id.json"
	new_id 32 "$build_dir/signing-key-id.json"
	new_id 32 "$build_dir/hpke-key-id.json"
	chmod 600 "$directory/device-signing.private" "$directory/device-hpke.private"

	python3 - "$directory" "$authority_public" "$machine_id" "$role" "$host_platform" "$adapter_data_dir" "$host_key_service" "$host_key_account" "$host_credential_directory" "$host_credential_name" "$build_dir/device-id.json" "$build_dir/signing-key-id.json" "$build_dir/device-signing.public.json" "$build_dir/hpke-key-id.json" "$build_dir/device-hpke.public.json" <<'PY'
import base64
import json
import os
import sys

(directory, authority_path, machine_id, role, host_platform, adapter_data_dir, host_service,
 host_account, host_credential_directory, host_credential_name, device_id_path,
 signing_id_path, signing_path, hpke_id_path, hpke_path) = sys.argv[1:]

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
audience = valid(authority["audience"], 32)
root_key_id = valid(authority["root_key_id"], 32)
root_public_key = valid(authority["root_public_key"], 32)
device_id = valid(read_json(device_id_path)["id"], 16)
signing_key_id = valid(read_json(signing_id_path)["id"], 32)
signing_public_key = valid(read_json(signing_path)["public_key"], 32)
hpke_key_id = valid(read_json(hpke_id_path)["id"], 32)
hpke_public_key = valid(read_json(hpke_path)["public_key"], 32)

device = {
    "device_id": device_id,
    "generation": 1,
    "signing_key_id": signing_key_id,
    "signing_public_key": signing_public_key,
    "hpke_key_id": hpke_key_id,
    "hpke_public_key": hpke_public_key,
    "revoked": False,
}
enrollment = {
    "version": 3,
    "machine_id": machine_id,
    "role": role,
    "attachment_device_id": device_id,
    "directory_entry": {"device": device},
}
public_path = os.path.join(directory, "device-enrollment.json")
fd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(enrollment, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
os.chmod(public_path, 0o600)

env = [
    "# Created by Punaro attachment-v3 provisioning. This owner-only file contains paths, not credentials.",
    "# Source adapter.env first; it supplies relay URL, machine key, and any Cloudflare Access service token.",
    f"PUNARO_ATTACHMENT_DIRECTORY_CHECKPOINT_FILE={directory}/directory-checkpoints.db",
    f"PUNARO_DIRECTORY_AUDIENCE={audience}",
    f"PUNARO_DIRECTORY_ROOT_KEY_ID={root_key_id}",
    f"PUNARO_DIRECTORY_ROOT_PUBLIC_KEY={root_public_key}",
]
if role in ("receiver", "both"):
    env += [
        f"PUNARO_ATTACHMENT_RECIPIENT_SIGNING_PRIVATE_KEY_FILE={directory}/device-signing.private",
        f"PUNARO_ATTACHMENT_RECIPIENT_HPKE_PRIVATE_KEY_FILE={directory}/device-hpke.private",
        f"PUNARO_ATTACHMENT_RECIPIENT_ID={device_id}",
        "PUNARO_ATTACHMENT_RECIPIENT_GENERATION=1",
        f"PUNARO_ATTACHMENT_CONTROLLER_JOURNAL={directory}/controller.db",
    ]
if role in ("sender", "both"):
    env += [
        f"PUNARO_ATTACHMENT_SENDER_SIGNING_PRIVATE_KEY_FILE={directory}/device-signing.private",
        f"PUNARO_ATTACHMENT_SENDER_ID={device_id}",
        "PUNARO_ATTACHMENT_SENDER_GENERATION=1",
        f"PUNARO_ATTACHMENT_SENDER_JOURNAL={directory}/sender.db",
        f"PUNARO_ATTACHMENT_ARTIFACT_STORE={directory}/artifacts.db",
        f"PUNARO_ATTACHMENT_OFFER_OUTBOX={adapter_data_dir}/attachment-offers.db",
    ]
    if host_platform == "Darwin":
        env += [
            f"PUNARO_ATTACHMENT_HOST_KEY_SERVICE={host_service}",
            f"PUNARO_ATTACHMENT_HOST_KEY_ACCOUNT={host_account}",
        ]
    else:
        env += [
            f"PUNARO_ATTACHMENT_HOST_CREDENTIAL_DIRECTORY={host_credential_directory}",
            f"PUNARO_ATTACHMENT_HOST_CREDENTIAL_NAME={host_credential_name}",
        ]
env_path = os.path.join(directory, "attachment-v3.env")
fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    handle.write("\n".join(env) + "\n")
os.chmod(env_path, 0o600)
PY
	printf '%s\n' 'attachment_v3_client_provisioned'
	printf '%s\n' "Public device enrollment: $directory/device-enrollment.json"
	printf '%s\n' 'Next: have the offline authority add that public device entry to the directory manifest, publish a fresh signed snapshot, configure the relay, then run punaro-attachment check before mapping or approving an offer.'
}

authority_add_device() {
	directory=
	device_enrollment=
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--directory) [ "$#" -ge 2 ] || fail '--directory requires a value'; directory=$2; shift 2 ;;
			--device-enrollment) [ "$#" -ge 2 ] || fail '--device-enrollment requires a value'; device_enrollment=$2; shift 2 ;;
			--help) usage; exit 0 ;;
			*) fail "unknown authority-add-device option: $1" ;;
		esac
	done
	[ -n "$directory" ] || fail 'authority-add-device requires --directory'
	[ -n "$device_enrollment" ] || fail 'authority-add-device requires --device-enrollment'
	require_absolute_private_directory "$directory" 'authority directory'
	require_absolute_regular_file "$directory/public.json" 'authority public record'
	require_absolute_regular_file "$directory/directory-manifest.json" 'directory manifest'
	require_absolute_regular_file "$device_enrollment" 'device enrollment'

	python3 - "$directory" "$device_enrollment" <<'PY'
import base64
import json
import os
import sys

directory, enrollment_path = sys.argv[1:]

def read_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)

def valid(value, size):
    if not isinstance(value, str) or "=" in value:
        raise ValueError("invalid public value")
    if len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))) != size:
        raise ValueError("unexpected public value length")
    return value

authority = read_json(os.path.join(directory, "public.json"))
manifest_path = os.path.join(directory, "directory-manifest.json")
manifest = read_json(manifest_path)
enrollment = read_json(enrollment_path)
if authority.get("version") != 3 or enrollment.get("version") != 3:
    raise ValueError("authority and device enrollment records must be version 3")
if manifest.get("audience") != authority.get("audience") or manifest.get("root_key_id") != authority.get("root_key_id"):
    raise ValueError("directory manifest does not match authority public record")
device = enrollment.get("directory_entry", {}).get("device")
if not isinstance(device, dict) or enrollment.get("attachment_device_id") != device.get("device_id"):
    raise ValueError("device enrollment has no matching directory device entry")
valid(device.get("device_id"), 16)
valid(device.get("signing_key_id"), 32)
valid(device.get("signing_public_key"), 32)
valid(device.get("hpke_key_id"), 32)
valid(device.get("hpke_public_key"), 32)
if device.get("generation") != 1 or device.get("revoked") is not False:
    raise ValueError("device enrollment must be an active generation-one device")
entries = manifest.get("entries")
if not isinstance(entries, list) or not isinstance(manifest.get("sequence"), int) or manifest["sequence"] < 1:
    raise ValueError("invalid directory manifest")
for entry in entries:
    prior = entry.get("device") if isinstance(entry, dict) else None
    if isinstance(prior, dict) and prior.get("device_id") == device["device_id"]:
        raise ValueError("directory already contains this attachment device")
entries.append({"device": device})
manifest["sequence"] += 1
temp_path = manifest_path + ".next"
fd = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as handle:
    json.dump(manifest, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
os.chmod(temp_path, 0o600)
os.replace(temp_path, manifest_path)
PY
	printf '%s\n' 'attachment_v3_directory_device_added'
	printf '%s\n' 'Publish a new signed snapshot before enabling or using attachment v3.'
}

[ "$#" -gt 0 ] || { usage >&2; exit 2; }
command=$1
shift
case "$command" in
	authority) authority "$@" ;;
	client) client "$@" ;;
	authority-add-device) authority_add_device "$@" ;;
	--help|-h) usage ;;
	*) fail "unknown command: $command" ;;
esac
