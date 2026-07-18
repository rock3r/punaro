#!/bin/sh
# Verify that first-time machine onboarding creates only private local material
# and emits a reusable public enrollment record. No relay or Access service is
# contacted by this test.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-install-test.XXXXXXXX")
# The installer deliberately uses a temporary HOME. Keep Go's shared caches
# outside that fixture so this test does not repeatedly download dependencies.
go_mod_cache=$(go env GOMODCACHE)
go_build_cache=$(go env GOCACHE)
# Go may install a read-only toolchain below the temporary HOME. Make cleanup
# resilient without ever touching a path outside this test fixture.
cleanup() { chmod -R u+w -- "$fixture_dir" 2>/dev/null || true; rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

home="$fixture_dir/home"
mailbox="$fixture_dir/agent-mailbox"
mailbox_log="$fixture_dir/mailbox.log"
guidance_project="$fixture_dir/project"
mailbox_state="$fixture_dir/custom-mailbox"
authority="$fixture_dir/authority"
mkdir -p "$home" "$guidance_project"

cat >"$mailbox" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PUNARO_TEST_MAILBOX_LOG"
case " $* " in
  *' group create '*) exit 0 ;;
  *' group list '*) printf '%s\n' '["group/punaro-attached"]'; exit 0 ;;
esac
exit 1
EOF
chmod 700 "$mailbox"

run_install() {
	HOME="$home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" PUNARO_TEST_MAILBOX_LOG="$mailbox_log" \
		sh "$repo_dir/scripts/install-client.sh" \
		--relay-url https://relay.example.test \
		--machine-id macbook \
		--agent-mailbox-bin "$mailbox" \
		--mailbox-state-dir "$mailbox_state" \
		--agent-guidance-dir "$guidance_project" \
		--attachment-authority-public "$authority/public.json" \
		--attachment-role receiver
}

HOME="$home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" sh "$repo_dir/scripts/provision-attachment-v3.sh" authority --directory "$authority" >"$fixture_dir/authority.out"
run_install >"$fixture_dir/first.out"

adapter="$home/.local/bin/punaro-adapter"
attachment="$home/.local/bin/punaro-attachment"
config="$home/.config/punaro/adapter.env"
key="$home/.config/punaro/machine.key"
enrollment="$home/.config/punaro/enrollment.json"
attachment_dir="$home/.config/punaro/attachment-v3"
plist="$home/Library/LaunchAgents/org.punaro.adapter.plist"

file_mode() {
	if stat -f %Lp "$1" >/dev/null 2>&1; then
		stat -f %Lp "$1"
	else
		stat -c %a "$1"
	fi
}

[ -x "$adapter" ] || { printf '%s\n' 'adapter binary was not installed' >&2; exit 1; }
[ -x "$attachment" ] || { printf '%s\n' 'attachment binary was not installed' >&2; exit 1; }
[ -f "$config" ] || { printf '%s\n' 'adapter environment was not installed' >&2; exit 1; }
[ -f "$key" ] || { printf '%s\n' 'machine key was not installed' >&2; exit 1; }
[ -f "$enrollment" ] || { printf '%s\n' 'public enrollment record was not retained' >&2; exit 1; }
[ -f "$attachment_dir/attachment-v3.env" ] || { printf '%s\n' 'attachment environment was not provisioned' >&2; exit 1; }
[ -f "$attachment_dir/device-enrollment.json" ] || { printf '%s\n' 'attachment enrollment was not retained' >&2; exit 1; }
[ -f "$guidance_project/AGENTS.md" ] || { printf '%s\n' 'opt-in agent guidance was not installed' >&2; exit 1; }
if [ "$(uname -s)" = Darwin ]; then
	[ -f "$plist" ] || { printf '%s\n' 'LaunchAgent was not installed' >&2; exit 1; }
else
	[ -f "$home/.config/systemd/user/punaro-adapter.service" ] || { printf '%s\n' 'user systemd unit was not installed' >&2; exit 1; }
	grep -Fqx "ReadWritePaths=%h/.local/state/punaro-adapter $mailbox_state" "$home/.config/systemd/user/punaro-adapter.service"
fi
[ "$(file_mode "$key")" = 600 ] || { printf '%s\n' 'machine key permissions are not 0600' >&2; exit 1; }
[ "$(file_mode "$config")" = 600 ] || { printf '%s\n' 'adapter environment permissions are not 0600' >&2; exit 1; }
[ "$(file_mode "$enrollment")" = 600 ] || { printf '%s\n' 'enrollment record permissions are not 0600' >&2; exit 1; }

grep -Fqx 'PUNARO_ADAPTER_RELAY_URL=https://relay.example.test' "$config"
grep -Fqx 'PUNARO_MACHINE_ID=macbook' "$config"
grep -Fqx 'PUNARO_ATTACHED_GROUP=group/punaro-attached' "$config"
grep -Fq '"endpoint_prefixes":["agent/macbook/"]' "$enrollment"
grep -Fqx 'PUNARO_ATTACHMENT_RELAY_URL=https://relay.example.test' "$attachment_dir/attachment-v3.env"
grep -Fqx 'PUNARO_ATTACHMENT_RECIPIENT_GENERATION=1' "$attachment_dir/attachment-v3.env"
grep -Fq 'group create --group group/punaro-attached' "$mailbox_log"
grep -Fq '"id":"macbook"' "$fixture_dir/first.out"
if grep -Fq 'PUNARO_CF_ACCESS_CLIENT_SECRET' "$fixture_dir/first.out"; then
	printf '%s\n' 'installer output must not solicit or print Access secrets' >&2
	exit 1
fi

cp "$enrollment" "$fixture_dir/enrollment.before"
run_install >"$fixture_dir/second.out"
cmp "$fixture_dir/enrollment.before" "$enrollment"

# A receiver-only attachment enrollment must never be presented as a completed
# sender setup on a later idempotent run.  The operator needs a new enrollment
# and authority approval for the broader role.
set +e
HOME="$home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" PUNARO_TEST_MAILBOX_LOG="$mailbox_log" \
	sh "$repo_dir/scripts/install-adapter.sh" \
		--relay-url https://relay.example.test \
		--machine-id macbook \
		--agent-mailbox-bin "$mailbox" \
		--mailbox-state-dir "$mailbox_state" \
		--attachment-authority-public "$authority/public.json" \
		--attachment-role both >"$fixture_dir/attachment-upgrade.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'receiver attachment setup was silently accepted as sender-capable' >&2; exit 1; }
grep -Fqx 'existing attachment setup is receiver-only; use a new --attachment-directory for sender or both and approve its new public enrollment' "$fixture_dir/attachment-upgrade.out"

default_home="$fixture_dir/default-home"
mkdir -p "$default_home"
PATH="$fixture_dir:$PATH" HOME="$default_home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" PUNARO_TEST_MAILBOX_LOG="$mailbox_log" \
	sh "$repo_dir/scripts/install-client.sh" \
		--relay-url https://relay.example.test \
		--machine-id default-path >"$fixture_dir/default.out"
grep -Fqx "PUNARO_AGENT_MAILBOX_BIN=$mailbox" "$default_home/.config/punaro/adapter.env"

set +e
HOME="$home" sh "$repo_dir/scripts/install-adapter.sh" --relay-url https://relay.example.test --machine-id 'bad/id' >"$fixture_dir/invalid.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'invalid machine ID was accepted' >&2; exit 1; }
grep -Fqx 'machine ID must contain only letters, digits, dot, underscore, or hyphen' "$fixture_dir/invalid.out"

printf '%s\n' install_adapter_tests_passed
