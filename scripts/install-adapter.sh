#!/bin/sh
# Install one local Punaro adapter from a trusted source checkout. The relay
# enrollment and Cloudflare Access credentials remain separate operator steps.
set -eu

umask 077

usage() {
	cat <<'EOF'
Usage: scripts/install-adapter.sh --relay-url URL --machine-id ID [options]

Install a per-user Punaro adapter, trusted-attachment client, and stateless
memory client; generate one private machine key, create the local attachment
group, and print enrollment.

Options:
  --relay-url URL             HTTPS or explicitly acknowledged literal LAN HTTP origin (required)
  --machine-id ID             Unique machine ID; becomes agent/ID/ (required)
  --allow-lan-http            Acknowledge plaintext credentials on a trusted LAN
  --trusted-lan-cidr CIDR     Private/link-local CIDR containing the literal HTTP origin
  --waypost-bin PATH          Waypost executable (default: auto-detect waypost, then legacy agent-mailbox)
  --agent-mailbox-bin PATH    Deprecated alias for --waypost-bin
  --mailbox-state-dir PATH    Local mailbox state directory
  --attached-group ADDRESS    Local group (default: group/punaro-attached)
  --agent-guidance-dir PATH   Add Punaro guidance and skills to this project
  --keys-file PATH            Persist this release public key set into the bootstrap directory
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

require_safe_relay_url() {
	case "$1" in
		''|*[!][A-Za-z0-9_./:@%+=,-]*) fail 'relay URL contains unsupported characters' ;;
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
mailbox_bin=
mailbox_bin_explicit=0
mailbox_state_dir=
attached_group=group/punaro-attached
agent_guidance_dir=
enable=0
allow_lan_http=false
trusted_lan_cidr=
keys_file=

while [ "$#" -gt 0 ]; do
	case "$1" in
		--relay-url) [ "$#" -ge 2 ] || fail '--relay-url requires a value'; relay_url=$2; shift 2 ;;
		--machine-id) [ "$#" -ge 2 ] || fail '--machine-id requires a value'; machine_id=$2; shift 2 ;;
		--allow-lan-http) allow_lan_http=true; shift ;;
		--trusted-lan-cidr) [ "$#" -ge 2 ] || fail '--trusted-lan-cidr requires a value'; trusted_lan_cidr=$2; shift 2 ;;
		--waypost-bin|--agent-mailbox-bin)
			[ "$#" -ge 2 ] || fail "$1 requires a value"
			[ "$mailbox_bin_explicit" -eq 0 ] || fail 'specify only one Waypost executable option'
			mailbox_bin=$2
			mailbox_bin_explicit=1
			shift 2
			;;
		--mailbox-state-dir) [ "$#" -ge 2 ] || fail '--mailbox-state-dir requires a value'; mailbox_state_dir=$2; shift 2 ;;
		--attached-group) [ "$#" -ge 2 ] || fail '--attached-group requires a value'; attached_group=$2; shift 2 ;;
		--agent-guidance-dir) [ "$#" -ge 2 ] || fail '--agent-guidance-dir requires a value'; agent_guidance_dir=$2; shift 2 ;;
		--keys-file) [ "$#" -ge 2 ] || fail '--keys-file requires a value'; keys_file=$2; shift 2 ;;
		--enable) enable=1; shift ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

[ "$(id -u)" -ne 0 ] || fail 'run this installer as the unprivileged account that owns Waypost'
[ -n "$HOME" ] && [ "${HOME#/}" != "$HOME" ] || fail 'HOME must be an absolute path'

case "$machine_id" in
	''|*[!A-Za-z0-9._-]*) fail 'machine ID must contain only letters, digits, dot, underscore, or hyphen' ;;
esac
case "$machine_id" in
	.*|-*) fail 'machine ID must start with a letter or digit' ;;
esac
case "$relay_url" in
	https://*) [ "$allow_lan_http" = false ] && [ -z "$trusted_lan_cidr" ] || fail 'trusted-LAN options are valid only with an http:// relay URL' ;;
	http://*) [ "$allow_lan_http" = true ] && [ -n "$trusted_lan_cidr" ] || fail 'LAN HTTP requires --allow-lan-http and --trusted-lan-cidr together' ;;
	*) fail 'relay URL must use https:// or explicitly acknowledged trusted-LAN http://' ;;
esac

require_safe_relay_url "$relay_url"
require_safe_value "$HOME" 'HOME'
if [ -n "$mailbox_bin" ]; then require_safe_value "$mailbox_bin" 'Waypost path'; fi
if [ -n "$mailbox_state_dir" ]; then require_safe_value "$mailbox_state_dir" 'mailbox state directory'; fi
require_safe_value "$attached_group" 'attached group'
if [ -n "$trusted_lan_cidr" ]; then require_safe_value "$trusted_lan_cidr" 'trusted LAN CIDR'; fi
if [ -n "$keys_file" ]; then
	require_safe_value "$keys_file" 'release keys file'
	case "$keys_file" in /*) ;; *) fail 'keys file must be an absolute path' ;; esac
	[ -f "$keys_file" ] && [ ! -L "$keys_file" ] || fail 'keys file must be a non-symlink regular file'
fi
case "$attached_group" in group/*) ;; *) fail 'attached group must be a group/ address' ;; esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
[ -f "$repo_dir/go.mod" ] && [ -d "$repo_dir/cmd/punaro-adapter" ] && [ -d "$repo_dir/cmd/punaro-bootstrap" ] && [ -d "$repo_dir/cmd/punaro-keygen" ] || fail 'run this installer from a complete Punaro source checkout'
command -v go >/dev/null 2>&1 || fail 'Go is required to build the adapter from this checkout'
plugin_version_count=$(grep -Ec '^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"[^"]+",?[[:space:]]*$' "$repo_dir/plugin.json")
[ "$plugin_version_count" -eq 1 ] || fail 'plugin release identity is invalid'
plugin_version=$(sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)",*[[:space:]]*$/\1/p' "$repo_dir/plugin.json")
source_release="v$plugin_version"
case "$source_release" in v[0-9]*.[0-9]*.[0-9]*) ;; *) fail 'plugin release identity is invalid' ;; esac
build_facts=$(
	cd "$repo_dir"
	env -u GOOS -u GOARCH -u CGO_ENABLED go run ./cmd/punaro-release build-facts --release "$source_release" --plugin-root "$repo_dir"
) || fail 'source release build identity is invalid'
skill_sha256=$(printf '%s\n' "$build_facts" | sed -n 's/.*"skill_set_sha256":"\([0-9a-f]*\)".*/\1/p')
plugin_runtime_sha256=$(printf '%s\n' "$build_facts" | sed -n 's/.*"plugin_runtime_sha256":"\([0-9a-f]*\)".*/\1/p')
[ "${#skill_sha256}" -eq 64 ] && [ "${#plugin_runtime_sha256}" -eq 64 ] || fail 'source plugin identity is invalid'
if [ "$allow_lan_http" = true ]; then
	(
		cd "$repo_dir"
		go run ./cmd/punaro-adapter validate-relay-transport --relay-url "$relay_url" --allow-lan-http --trusted-lan-cidr "$trusted_lan_cidr" >/dev/null 2>&1
	) || fail 'relay transport policy is invalid'
else
	(
		cd "$repo_dir"
		go run ./cmd/punaro-adapter validate-relay-transport --relay-url "$relay_url" >/dev/null 2>&1
	) || fail 'relay transport policy is invalid'
fi
mailbox_bin_input=$mailbox_bin
if [ -z "$mailbox_bin" ]; then
	mailbox_bin=$(command -v waypost 2>/dev/null || command -v agent-mailbox 2>/dev/null) || fail 'Waypost is required; install it before onboarding this machine'
elif [ "$mailbox_bin" = waypost ] || [ "$mailbox_bin" = agent-mailbox ]; then
	mailbox_bin=$(command -v "$mailbox_bin") || fail 'the configured Waypost executable is unavailable'
elif [ ! -x "$mailbox_bin" ]; then
	fail 'Waypost path is not executable'
fi
mailbox_bin_dir=$(CDPATH= cd -- "$(dirname -- "$mailbox_bin")" && pwd -P) || fail 'Waypost path is unavailable'
mailbox_bin="$mailbox_bin_dir/$(basename -- "$mailbox_bin")"
if [ -z "$mailbox_state_dir" ]; then
	if [ "$(basename -- "$mailbox_bin")" = waypost ]; then
		mailbox_state_dir="$HOME/.local/state/waypost"
	else
		mailbox_state_dir="$HOME/.local/state/ai-agent/mailbox"
	fi
fi
mailbox_state_dir_input=$mailbox_state_dir

config_dir="$HOME/.config/punaro"
state_dir="$HOME/.local/state/punaro-adapter"
bootstrap_dir="$HOME/.local/state/punaro-bootstrap"
bin_dir="$HOME/.local/bin"
key_file="$config_dir/machine.key"
enrollment_file="$config_dir/enrollment.json"
config_file="$config_dir/adapter.env"
endpoint_prefix="agent/$machine_id/"

mkdir -p "$config_dir" "$state_dir" "$bootstrap_dir" "$bin_dir"
chmod 700 "$config_dir" "$state_dir" "$bootstrap_dir"

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

mkdir -p "$mailbox_state_dir" || fail 'could not create the local mailbox state directory'
mailbox_state_dir=$(CDPATH= cd -- "$mailbox_state_dir" && pwd -P) || fail 'mailbox state directory is unavailable'

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-adapter-install.XXXXXXXX")
migration_file=
cleanup() {
	if [ -n "$migration_file" ]; then rm -f -- "$migration_file"; fi
	rm -rf -- "$build_dir"
}
trap cleanup EXIT HUP INT TERM

config_exists=0
if [ -e "$config_file" ] || [ -L "$config_file" ]; then
	config_exists=1
	regular_private_file "$config_file" || fail 'existing adapter.env must be a non-symlink regular 0600 file'
	for expected in \
		"PUNARO_ADAPTER_RELAY_URL=$relay_url" \
		"PUNARO_MACHINE_ID=$machine_id" \
		"PUNARO_MACHINE_PRIVATE_KEY_FILE=$key_file" \
		"PUNARO_ATTACHED_GROUP=$attached_group" \
		"PUNARO_ADAPTER_DATA_DIR=$state_dir"; do
		grep -Fqx "$expected" "$config_file" || fail 'existing adapter.env belongs to a different machine or relay; refusing to overwrite it'
	done
	migrate_mailbox_bin=0
	if ! grep -Fqx "PUNARO_AGENT_MAILBOX_BIN=$mailbox_bin" "$config_file"; then
		[ "$mailbox_bin_input" != "$mailbox_bin" ] && grep -Fqx "PUNARO_AGENT_MAILBOX_BIN=$mailbox_bin_input" "$config_file" || fail 'existing adapter.env belongs to a different machine or relay; refusing to overwrite it'
		migrate_mailbox_bin=1
	fi
	migrate_mailbox_state=0
	if ! grep -Fqx "PUNARO_MAILBOX_STATE_DIR=$mailbox_state_dir" "$config_file"; then
		[ "$mailbox_state_dir_input" != "$mailbox_state_dir" ] && grep -Fqx "PUNARO_MAILBOX_STATE_DIR=$mailbox_state_dir_input" "$config_file" || fail 'existing adapter.env belongs to a different machine or relay; refusing to overwrite it'
		migrate_mailbox_state=1
	fi
	if [ "$allow_lan_http" = false ] && [ -z "$trusted_lan_cidr" ]; then
		if grep -q '^PUNARO_ADAPTER_ALLOW_LAN_HTTP=' "$config_file"; then
			grep -Fqx 'PUNARO_ADAPTER_ALLOW_LAN_HTTP=false' "$config_file" || fail 'existing adapter.env has a different LAN transport policy; refusing to overwrite it'
		fi
		if grep -q '^PUNARO_ADAPTER_TRUSTED_LAN_CIDR=' "$config_file"; then
			grep -Fqx 'PUNARO_ADAPTER_TRUSTED_LAN_CIDR=' "$config_file" || fail 'existing adapter.env has a different LAN transport policy; refusing to overwrite it'
		fi
	else
		grep -Fqx "PUNARO_ADAPTER_ALLOW_LAN_HTTP=$allow_lan_http" "$config_file" || fail 'existing adapter.env has a different LAN transport policy; refusing to overwrite it'
		grep -Fqx "PUNARO_ADAPTER_TRUSTED_LAN_CIDR=$trusted_lan_cidr" "$config_file" || fail 'existing adapter.env has a different LAN transport policy; refusing to overwrite it'
	fi
	if [ "$migrate_mailbox_bin" -eq 1 ] || [ "$migrate_mailbox_state" -eq 1 ]; then
		migration_file=$(mktemp "$config_dir/.adapter.env.XXXXXXXX")
		while IFS= read -r line || [ -n "$line" ]; do
			if [ "$migrate_mailbox_bin" -eq 1 ] && [ "$line" = "PUNARO_AGENT_MAILBOX_BIN=$mailbox_bin_input" ]; then
				printf '%s\n' "PUNARO_AGENT_MAILBOX_BIN=$mailbox_bin"
			elif [ "$migrate_mailbox_state" -eq 1 ] && [ "$line" = "PUNARO_MAILBOX_STATE_DIR=$mailbox_state_dir_input" ]; then
				printf '%s\n' "PUNARO_MAILBOX_STATE_DIR=$mailbox_state_dir"
			else
				printf '%s\n' "$line"
			fi
		done <"$config_file" >"$migration_file"
		chmod 600 "$migration_file"
		mv "$migration_file" "$config_file"
		migration_file=
		grep -Fqx "PUNARO_AGENT_MAILBOX_BIN=$mailbox_bin" "$config_file" || fail 'could not migrate the installed mailbox binary path'
		grep -Fqx "PUNARO_MAILBOX_STATE_DIR=$mailbox_state_dir" "$config_file" || fail 'could not migrate the installed mailbox state path'
	fi
fi

(
	cd "$repo_dir"
	go build -trimpath -buildvcs=true -ldflags "-X main.adapterBuildRelease=$source_release -X main.adapterExpectedSkillSetDigest=$skill_sha256 -X main.adapterExpectedPluginRuntimeDigest=$plugin_runtime_sha256" -o "$build_dir/punaro-adapter" ./cmd/punaro-adapter
	go build -trimpath -buildvcs=true -ldflags "-X main.bootstrapBuildRelease=$source_release" -o "$build_dir/punaro-bootstrap" ./cmd/punaro-bootstrap
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-trusted-attachment" ./cmd/punaro-trusted-attachment
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-memory" ./cmd/punaro-memory
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-enroll" ./cmd/punaro-enroll
	go build -trimpath -buildvcs=true -o "$build_dir/punaro-keygen" ./cmd/punaro-keygen
)
install -m 700 "$build_dir/punaro-adapter" "$bin_dir/punaro-adapter"
install -m 700 "$build_dir/punaro-bootstrap" "$bin_dir/punaro-bootstrap"
if [ -n "$keys_file" ]; then
	"$bin_dir/punaro-bootstrap" seed-checkout --directory "$bootstrap_dir" --adapter "$bin_dir/punaro-adapter" --keys-file "$keys_file"
else
	"$bin_dir/punaro-bootstrap" seed-checkout --directory "$bootstrap_dir" --adapter "$bin_dir/punaro-adapter"
fi
install -m 700 "$build_dir/punaro-trusted-attachment" "$bin_dir/punaro-trusted-attachment"
install -m 700 "$build_dir/punaro-memory" "$bin_dir/punaro-memory"
install -m 700 "$build_dir/punaro-enroll" "$bin_dir/punaro-enroll"

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
PUNARO_ADAPTER_ALLOW_LAN_HTTP=$allow_lan_http
PUNARO_ADAPTER_TRUSTED_LAN_CIDR=$trusted_lan_cidr

# If the relay is protected by Cloudflare Access, add this machine's distinct
# client ID and secret here with an editor or secret-manager injection. Do not
# pass either value as a shell argument or copy them from another machine.
EOF
}

if [ "$config_exists" -eq 0 ]; then
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
		service_active=0
		if launchctl print "gui/$(id -u)/org.punaro.adapter" >/dev/null 2>&1; then
			service_active=1
		fi
		if [ "$enable" -eq 1 ] || [ "$service_active" -eq 1 ]; then
			launchctl bootout "gui/$(id -u)" "$service_file" >/dev/null 2>&1 || true
			launchctl bootstrap "gui/$(id -u)" "$service_file"
		fi
		service_hint="launchctl print gui/$(id -u)/org.punaro.adapter"
		;;
	Linux)
		service_dir="$HOME/.config/systemd/user"
		service_file="$service_dir/punaro-adapter.service"
		mkdir -p "$service_dir"
		if [ "$mailbox_state_dir" = "$HOME/.local/state/waypost" ]; then
			install -m 600 "$repo_dir/deploy/systemd/user/punaro-adapter.service" "$service_file"
		else
			sed "s|^ReadWritePaths=%h/.local/state/punaro-adapter %h/.local/state/punaro-bootstrap %h/.local/state/waypost$|ReadWritePaths=%h/.local/state/punaro-adapter %h/.local/state/punaro-bootstrap $mailbox_state_dir|" \
				"$repo_dir/deploy/systemd/user/punaro-adapter.service" >"$service_file"
			chmod 600 "$service_file"
			grep -Fqx "ReadWritePaths=%h/.local/state/punaro-adapter %h/.local/state/punaro-bootstrap $mailbox_state_dir" "$service_file" || fail 'could not render the Linux mailbox sandbox path'
		fi
		service_active=0
		if systemctl --user is-active --quiet punaro-adapter.service; then
			service_active=1
		fi
		if command -v systemctl >/dev/null 2>&1; then
			if ! systemctl --user daemon-reload; then
				if [ "$enable" -eq 1 ] || [ "$service_active" -eq 1 ]; then
					fail 'could not reload the Linux user manager'
				fi
			fi
		fi
		if [ "$enable" -eq 1 ]; then
			systemctl --user enable punaro-adapter.service
			systemctl --user restart punaro-adapter.service
		elif [ "$service_active" -eq 1 ]; then
			systemctl --user restart punaro-adapter.service
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
	'Device enrollment: run punaro-enroll prepare, have the server owner issue a grant for its printed public binding, then redeem a protected transfer file with punaro-enroll. It never accepts the code as an argument.' \
	'Memory: after device-credential enrollment, use punaro-memory with the same fixed HTTPS origin and an owner-protected credential file; every project, idempotency key, and ETag remains explicit.' \
	"Verify with: $service_hint"
if [ -z "$agent_guidance_dir" ]; then
	printf '%s\n' "Optional agent guidance: $repo_dir/scripts/install-agent-guidance.sh --directory /path/to/project"
fi
