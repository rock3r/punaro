#!/bin/sh
# Install one local Punaro adapter from a trusted source checkout. The relay
# enrollment and Cloudflare Access credentials remain separate operator steps.
set -eu

umask 077

usage() {
	cat <<'EOF'
Usage: scripts/install-adapter.sh --relay-url HTTPS_URL --machine-id ID [options]

Install a per-user Punaro adapter, trusted-attachment client, and stateless
memory client; generate one private machine key, create the local attachment
group, and print enrollment.

Options:
  --relay-url HTTPS_URL       Public relay base URL (required)
  --machine-id ID             Unique machine ID; becomes agent/ID/ (required)
  --agent-mailbox-bin PATH    agent-mailbox executable (default: agent-mailbox)
  --mailbox-state-dir PATH    Local mailbox state directory
  --attached-group ADDRESS    Local group (default: group/punaro-attached)
  --agent-guidance-dir PATH   Add Punaro guidance and skills to this project
  --enable                    Start the per-user service after installation
  --help                      Show this help

Access credentials are deliberately not accepted as arguments. Add this
machine's distinct service-token pair to the owner-only adapter.env file after
the relay enrollment record has been approved.

Legacy encrypted attachment-v2/v3 provisioning is retired. The installed
punaro-trusted-attachment client uses the enrolled device credential after the
operator completes that separate enrollment flow.
EOF
}

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

require_safe_value() {
	case "$1" in
		''|*[!A-Za-z0-9_./:@%+=,-]*) fail "$2 contains unsupported characters" ;;
	esac
}

file_mode() {
	if stat -f %Lp "$1" >/dev/null 2>&1; then
		stat -f %Lp "$1"
	else
		stat -c %a "$1"
	fi
}

regular_private_file() {
	[ -f "$1" ] && [ ! -L "$1" ] && [ "$(file_mode "$1")" = 600 ]
}

relay_url=
machine_id=
mailbox_bin=agent-mailbox
mailbox_state_dir=
attached_group=group/punaro-attached
agent_guidance_dir=
enable=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--relay-url) [ "$#" -ge 2 ] || fail '--relay-url requires a value'; relay_url=$2; shift 2 ;;
		--machine-id) [ "$#" -ge 2 ] || fail '--machine-id requires a value'; machine_id=$2; shift 2 ;;
		--agent-mailbox-bin) [ "$#" -ge 2 ] || fail '--agent-mailbox-bin requires a value'; mailbox_bin=$2; shift 2 ;;
		--mailbox-state-dir) [ "$#" -ge 2 ] || fail '--mailbox-state-dir requires a value'; mailbox_state_dir=$2; shift 2 ;;
		--attached-group) [ "$#" -ge 2 ] || fail '--attached-group requires a value'; attached_group=$2; shift 2 ;;
		--agent-guidance-dir) [ "$#" -ge 2 ] || fail '--agent-guidance-dir requires a value'; agent_guidance_dir=$2; shift 2 ;;
		--enable) enable=1; shift ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

[ "$(id -u)" -ne 0 ] || fail 'run this installer as the unprivileged account that owns agent-mailbox'
[ -n "$HOME" ] && [ "${HOME#/}" != "$HOME" ] || fail 'HOME must be an absolute path'

case "$machine_id" in
	''|*[!A-Za-z0-9._-]*) fail 'machine ID must contain only letters, digits, dot, underscore, or hyphen' ;;
esac
case "$machine_id" in
	.*|-*) fail 'machine ID must start with a letter or digit' ;;
esac
case "$relay_url" in
	https://*) ;;
	*) fail 'relay URL must use https://' ;;
esac

if [ -z "$mailbox_state_dir" ]; then
	mailbox_state_dir="$HOME/.local/state/ai-agent/mailbox"
fi

require_safe_value "$relay_url" 'relay URL'
require_safe_value "$HOME" 'HOME'
require_safe_value "$mailbox_bin" 'agent-mailbox path'
require_safe_value "$mailbox_state_dir" 'mailbox state directory'
require_safe_value "$attached_group" 'attached group'
case "$attached_group" in group/*) ;; *) fail 'attached group must be a group/ address' ;; esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
[ -f "$repo_dir/go.mod" ] && [ -d "$repo_dir/cmd/punaro-adapter" ] && [ -d "$repo_dir/cmd/punaro-keygen" ] || fail 'run this installer from a complete Punaro source checkout'
command -v go >/dev/null 2>&1 || fail 'Go is required to build the adapter from this checkout'
if [ "$mailbox_bin" = agent-mailbox ]; then
	mailbox_bin=$(command -v agent-mailbox) || fail 'agent-mailbox is required; install it before onboarding this machine'
elif [ ! -x "$mailbox_bin" ]; then
	fail 'agent-mailbox path is not executable'
fi

config_dir="$HOME/.config/punaro"
state_dir="$HOME/.local/state/punaro-adapter"
bin_dir="$HOME/.local/bin"
key_file="$config_dir/machine.key"
enrollment_file="$config_dir/enrollment.json"
config_file="$config_dir/adapter.env"
endpoint_prefix="agent/$machine_id/"

mkdir -p "$config_dir" "$state_dir" "$bin_dir"
chmod 700 "$config_dir" "$state_dir"

for retired_path in \
	"$bin_dir/punaro-attachment" \
	"$bin_dir/punaro-directory" \
	"$bin_dir/punaro-dpapi" \
	"$bin_dir/punaro-keychain" \
	"$config_dir/attachment-v3"; do
	if [ -e "$retired_path" ] || [ -L "$retired_path" ]; then
		fail "retired attachment artifact exists at $retired_path; archive or remove it explicitly before installing the trusted client"
	fi
done

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-adapter-install.XXXXXXXX")
cleanup() { rm -rf -- "$build_dir"; }
trap cleanup EXIT HUP INT TERM

(
	cd "$repo_dir"
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-adapter" ./cmd/punaro-adapter
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-trusted-attachment" ./cmd/punaro-trusted-attachment
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-memory" ./cmd/punaro-memory
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-keygen" ./cmd/punaro-keygen
)
install -m 700 "$build_dir/punaro-adapter" "$bin_dir/punaro-adapter"
install -m 700 "$build_dir/punaro-trusted-attachment" "$bin_dir/punaro-trusted-attachment"
install -m 700 "$build_dir/punaro-memory" "$bin_dir/punaro-memory"

if [ -e "$key_file" ] || [ -L "$key_file" ]; then
	regular_private_file "$key_file" || fail 'existing machine key must be a non-symlink regular 0600 file'
	regular_private_file "$enrollment_file" || fail 'existing machine key requires its matching non-symlink 0600 enrollment.json record'
else
	[ ! -e "$enrollment_file" ] && [ ! -L "$enrollment_file" ] || fail 'enrollment.json exists without its matching machine key'
	"$build_dir/punaro-keygen" \
		--id "$machine_id" \
		--endpoint-prefix "$endpoint_prefix" \
		--private-key-file "$key_file" >"$enrollment_file"
	chmod 600 "$key_file" "$enrollment_file"
fi

grep -Fq "\"id\":\"$machine_id\"" "$enrollment_file" || fail 'enrollment.json does not match the requested machine ID'
grep -Fq "\"agent/$machine_id/\"" "$enrollment_file" || fail 'enrollment.json does not match the machine endpoint namespace'

write_config() {
	cat <<EOF
# Created by Punaro's installer. Keep this owner-only file out of backups and source control.
PUNARO_ADAPTER_RELAY_URL=$relay_url
PUNARO_MACHINE_ID=$machine_id
PUNARO_MACHINE_PRIVATE_KEY_FILE=$key_file
PUNARO_ATTACHED_GROUP=$attached_group
PUNARO_ADAPTER_DATA_DIR=$state_dir
PUNARO_MAILBOX_STATE_DIR=$mailbox_state_dir
PUNARO_ADAPTER_POLL_INTERVAL=30s
PUNARO_AGENT_MAILBOX_BIN=$mailbox_bin

# If the relay is protected by Cloudflare Access, add this machine's distinct
# client ID and secret here with an editor or secret-manager injection. Do not
# pass either value as a shell argument or copy them from another machine.
EOF
}

if [ -e "$config_file" ] || [ -L "$config_file" ]; then
	regular_private_file "$config_file" || fail 'existing adapter.env must be a non-symlink regular 0600 file'
	for expected in \
		"PUNARO_ADAPTER_RELAY_URL=$relay_url" \
		"PUNARO_MACHINE_ID=$machine_id" \
		"PUNARO_MACHINE_PRIVATE_KEY_FILE=$key_file" \
		"PUNARO_ATTACHED_GROUP=$attached_group" \
		"PUNARO_ADAPTER_DATA_DIR=$state_dir" \
		"PUNARO_MAILBOX_STATE_DIR=$mailbox_state_dir" \
		"PUNARO_AGENT_MAILBOX_BIN=$mailbox_bin"; do
		grep -Fqx "$expected" "$config_file" || fail 'existing adapter.env belongs to a different machine or relay; refusing to overwrite it'
	done
else
	( set -C; : >"$config_file" ) 2>/dev/null || fail 'could not create adapter.env without overwriting an existing file'
	write_config >"$config_file"
	chmod 600 "$config_file"
fi

group_error="$build_dir/group-create.err"
if ! "$mailbox_bin" --state-dir "$mailbox_state_dir" group create --group "$attached_group" 2>"$group_error"; then
	if ! "$mailbox_bin" --state-dir "$mailbox_state_dir" group list --json | grep -Fq "\"$attached_group\""; then
		cat "$group_error" >&2
		fail 'could not create the local Punaro attachment group'
	fi
fi

case "$(uname -s)" in
	Darwin)
		service_dir="$HOME/Library/LaunchAgents"
		service_file="$service_dir/org.punaro.adapter.plist"
		mkdir -p "$service_dir"
		install -m 600 "$repo_dir/deploy/launchd/punaro-adapter.plist" "$service_file"
		plutil -lint "$service_file" >/dev/null
if [ "$enable" -eq 1 ]; then
			launchctl bootout "gui/$(id -u)" "$service_file" >/dev/null 2>&1 || true
			launchctl bootstrap "gui/$(id -u)" "$service_file"
		fi
		service_hint="launchctl print gui/$(id -u)/org.punaro.adapter"
		;;
	Linux)
		service_dir="$HOME/.config/systemd/user"
		service_file="$service_dir/punaro-adapter.service"
		mkdir -p "$service_dir"
		if [ "$mailbox_state_dir" = "$HOME/.local/state/ai-agent/mailbox" ]; then
			install -m 600 "$repo_dir/deploy/systemd/user/punaro-adapter.service" "$service_file"
		else
			sed "s|^ReadWritePaths=%h/.local/state/punaro-adapter %h/.local/state/ai-agent/mailbox$|ReadWritePaths=%h/.local/state/punaro-adapter $mailbox_state_dir|" \
				"$repo_dir/deploy/systemd/user/punaro-adapter.service" >"$service_file"
			chmod 600 "$service_file"
			grep -Fqx "ReadWritePaths=%h/.local/state/punaro-adapter $mailbox_state_dir" "$service_file" || fail 'could not render the Linux mailbox sandbox path'
		fi
		if [ "$enable" -eq 1 ]; then
			systemctl --user daemon-reload
			systemctl --user enable --now punaro-adapter.service
		fi
		service_hint='systemctl --user status punaro-adapter.service'
		;;
	*) fail "unsupported platform: $(uname -s) (use the documented manual service setup)" ;;
esac

if [ -n "$agent_guidance_dir" ]; then
	"$repo_dir/scripts/install-agent-guidance.sh" --directory "$agent_guidance_dir"
fi

printf '%s\n' 'Punaro adapter installed. The service is not useful until this public enrollment record is added to the relay:'
cat "$enrollment_file"
printf '%s\n' '' \
	'Next: approve that record on the relay; create a distinct Cloudflare Access service token for this machine; add it to the owner-only adapter.env; bind and attach the desired agent aliases; then rerun this command with --enable.' \
	'Trusted attachments: after device-credential enrollment, use punaro-trusted-attachment with an owner-protected credential file and configured safe download root.' \
	'Memory: after device-credential enrollment, use punaro-memory with the same fixed HTTPS origin and an owner-protected credential file; every project, idempotency key, and ETag remains explicit.' \
	"Verify with: $service_hint"
if [ -z "$agent_guidance_dir" ]; then
	printf '%s\n' "Optional agent guidance: $repo_dir/scripts/install-agent-guidance.sh --directory /path/to/project"
fi
