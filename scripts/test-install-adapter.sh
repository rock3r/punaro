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
		--agent-guidance-dir "$guidance_project"
}

run_install >"$fixture_dir/first.out"

adapter="$home/.local/bin/punaro-adapter"
attachment="$home/.local/bin/punaro-trusted-attachment"
memory="$home/.local/bin/punaro-memory"
enroll="$home/.local/bin/punaro-enroll"
config="$home/.config/punaro/adapter.env"
key="$home/.config/punaro/machine.key"
enrollment="$home/.config/punaro/enrollment.json"
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
[ -x "$memory" ] || { printf '%s\n' 'memory binary was not installed' >&2; exit 1; }
[ -x "$enroll" ] || { printf '%s\n' 'enrollment binary was not installed' >&2; exit 1; }
[ -f "$config" ] || { printf '%s\n' 'adapter environment was not installed' >&2; exit 1; }
[ -f "$key" ] || { printf '%s\n' 'machine key was not installed' >&2; exit 1; }
[ -f "$enrollment" ] || { printf '%s\n' 'public enrollment record was not retained' >&2; exit 1; }
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
grep -Fqx 'PUNARO_ADAPTER_ALLOW_LAN_HTTP=false' "$config"
grep -Fqx 'PUNARO_ADAPTER_TRUSTED_LAN_CIDR=' "$config"
grep -Fq '"endpoint_prefixes":["agent/macbook/"]' "$enrollment"
grep -Fq 'group create --group group/punaro-attached' "$mailbox_log"
grep -Fq '"id":"macbook"' "$fixture_dir/first.out"
if grep -Fq 'PUNARO_CF_ACCESS_CLIENT_SECRET' "$fixture_dir/first.out"; then
	printf '%s\n' 'installer output must not solicit or print Access secrets' >&2
	exit 1
fi

cp "$enrollment" "$fixture_dir/enrollment.before"
run_install >"$fixture_dir/second.out"
cmp "$fixture_dir/enrollment.before" "$enrollment"

# Profiles written by the previous installer did not contain the explicit LAN
# keys. Their absence is the safe HTTPS default and must remain upgradeable.
grep -v '^PUNARO_ADAPTER_\(ALLOW_LAN_HTTP\|TRUSTED_LAN_CIDR\)=' "$config" >"$fixture_dir/pre-policy.env"
mv "$fixture_dir/pre-policy.env" "$config"
chmod 600 "$config"
run_install >"$fixture_dir/pre-policy-upgrade.out"
if grep -q '^PUNARO_ADAPTER_\(ALLOW_LAN_HTTP\|TRUSTED_LAN_CIDR\)=' "$config"; then
	printf '%s\n' 'HTTPS compatibility upgrade unexpectedly rewrote adapter.env' >&2
	exit 1
fi

set +e
HOME="$home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" PUNARO_TEST_MAILBOX_LOG="$mailbox_log" \
	sh "$repo_dir/scripts/install-adapter.sh" \
		--relay-url https://relay.example.test \
		--machine-id macbook \
		--agent-mailbox-bin "$mailbox" \
		--attachment-role receiver >"$fixture_dir/attachment-retired.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'retired attachment-v3 installer option was accepted' >&2; exit 1; }
grep -Fqx 'unknown option: --attachment-role' "$fixture_dir/attachment-retired.out"

set +e
HOME="$home" sh "$repo_dir/scripts/install-adapter.sh" --relay-url http://192.168.1.4:8080 --machine-id lan-client --allow-lan-http >"$fixture_dir/partial-lan.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'partial trusted-LAN policy was accepted' >&2; exit 1; }
grep -Fqx 'LAN HTTP requires --allow-lan-http and --trusted-lan-cidr together' "$fixture_dir/partial-lan.out"

unsafe_url_home="$fixture_dir/unsafe-url-home"
mkdir -p "$unsafe_url_home"
set +e
PATH="$fixture_dir:$PATH" HOME="$unsafe_url_home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" PUNARO_TEST_MAILBOX_LOG="$mailbox_log" \
	sh "$repo_dir/scripts/install-client.sh" \
		--relay-url 'https://relay.example.test;touch' \
		--machine-id unsafe-url-client >"$fixture_dir/unsafe-url.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'unsafe relay URL character was accepted' >&2; exit 1; }
grep -Fqx 'relay URL contains unsupported characters' "$fixture_dir/unsafe-url.out"
[ ! -e "$unsafe_url_home/.config/punaro" ] || { printf '%s\n' 'unsafe relay URL created installation artifacts' >&2; exit 1; }

invalid_policy_home="$fixture_dir/invalid-policy-home"
mkdir -p "$invalid_policy_home"
set +e
PATH="$fixture_dir:$PATH" HOME="$invalid_policy_home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" PUNARO_TEST_MAILBOX_LOG="$mailbox_log" \
	sh "$repo_dir/scripts/install-client.sh" \
		--relay-url http://punaro.lan:8080 \
		--machine-id invalid-lan-client \
		--allow-lan-http \
		--trusted-lan-cidr 192.168.1.0/24 >"$fixture_dir/invalid-policy.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'invalid complete trusted-LAN policy was accepted' >&2; exit 1; }
grep -Fqx 'relay transport policy is invalid' "$fixture_dir/invalid-policy.out"
[ ! -e "$invalid_policy_home/.config/punaro" ] || { printf '%s\n' 'invalid trusted-LAN policy created installation artifacts' >&2; exit 1; }

lan_home="$fixture_dir/lan-home"
mkdir -p "$lan_home"
PATH="$fixture_dir:$PATH" HOME="$lan_home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" PUNARO_TEST_MAILBOX_LOG="$mailbox_log" \
	sh "$repo_dir/scripts/install-client.sh" \
		--relay-url http://192.168.1.4:8080 \
		--machine-id lan-client \
		--allow-lan-http \
		--trusted-lan-cidr 192.168.1.0/24 >"$fixture_dir/lan.out"
grep -Fqx 'PUNARO_ADAPTER_RELAY_URL=http://192.168.1.4:8080' "$lan_home/.config/punaro/adapter.env"
grep -Fqx 'PUNARO_ADAPTER_ALLOW_LAN_HTTP=true' "$lan_home/.config/punaro/adapter.env"
grep -Fqx 'PUNARO_ADAPTER_TRUSTED_LAN_CIDR=192.168.1.0/24' "$lan_home/.config/punaro/adapter.env"

ipv6_home="$fixture_dir/ipv6-home"
mkdir -p "$ipv6_home"
PATH="$fixture_dir:$PATH" HOME="$ipv6_home" GOTOOLCHAIN=local GOMODCACHE="$go_mod_cache" GOCACHE="$go_build_cache" PUNARO_TEST_MAILBOX_LOG="$mailbox_log" \
	sh "$repo_dir/scripts/install-client.sh" \
		--relay-url 'http://[fd12:3456::4]:8080' \
		--machine-id ipv6-lan-client \
		--allow-lan-http \
		--trusted-lan-cidr 'fd12:3456::/64' >"$fixture_dir/ipv6.out"
grep -Fqx 'PUNARO_ADAPTER_RELAY_URL=http://[fd12:3456::4]:8080' "$ipv6_home/.config/punaro/adapter.env"
grep -Fqx 'PUNARO_ADAPTER_TRUSTED_LAN_CIDR=fd12:3456::/64' "$ipv6_home/.config/punaro/adapter.env"

printf '%s\n' legacy >"$home/.local/bin/punaro-attachment"
set +e
run_install >"$fixture_dir/legacy-artifact.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'installer accepted an existing retired attachment binary' >&2; exit 1; }
grep -Fq 'retired attachment artifact exists at' "$fixture_dir/legacy-artifact.out"

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
