#!/bin/sh
# Install the loopback-only Punaro relay service. Run on Linux as root; --root
# is retained for package-image/staging validation and never starts a service.
set -eu

umask 077

usage() {
	cat <<'EOF'
Usage: scripts/install-server.sh [--enable] [--root ABSOLUTE_STAGING_ROOT]

Build and install punarod, its hardened systemd unit, and an owner-controlled
relay configuration. The service is not started until the enrollment set is
configured. --root stages files below an alternate root and never alters host
users or systemd.
EOF
}

fail() { printf '%s\n' "$1" >&2; exit 2; }

root_dir=/
enable=0
while [ "$#" -gt 0 ]; do
	case "$1" in
		--root) [ "$#" -ge 2 ] || fail '--root requires a value'; root_dir=$2; shift 2 ;;
		--enable) enable=1; shift ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

case "$root_dir" in /*) ;; *) fail 'root directory must be an absolute path' ;; esac
if [ "$root_dir" = / ]; then
	[ "$(uname -s)" = Linux ] || fail 'install-server supports Linux systemd hosts only'
	[ "$(id -u)" -eq 0 ] || fail 'run install-server as root on the relay host'
else
	[ "$enable" -eq 0 ] || fail '--enable is unavailable with a staging root'
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
[ -f "$repo_dir/go.mod" ] && [ -f "$repo_dir/deploy/systemd/punarod.service" ] || fail 'run this installer from a complete Punaro source checkout'
command -v go >/dev/null 2>&1 || fail 'Go is required to build the relay from this checkout'

build_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-server-install.XXXXXXXX")
cleanup() { rm -rf -- "$build_dir"; }
trap cleanup EXIT HUP INT TERM
(
	cd "$repo_dir"
	go build -trimpath -buildvcs=true -o "$build_dir/punarod" ./cmd/punarod
)

path_in_root() {
	if [ "$root_dir" = / ]; then printf '/%s\n' "$1"; else printf '%s/%s\n' "${root_dir%/}" "$1"; fi
}

bin_file=$(path_in_root usr/local/bin/punarod)
unit_file=$(path_in_root etc/systemd/system/punarod.service)
config_dir=$(path_in_root etc/punaro)
config_file="$config_dir/punaro.env"
state_dir=$(path_in_root var/lib/punaro)

if [ "$root_dir" = / ]; then
	if ! getent group punaro >/dev/null; then groupadd --system punaro; fi
	if ! id -u punaro >/dev/null 2>&1; then useradd --system --gid punaro --home-dir /nonexistent --shell /usr/sbin/nologin --no-create-home punaro; fi
	install -d -o root -g punaro -m 0750 "$config_dir"
	install -d -o punaro -g punaro -m 0700 "$state_dir"
else
	install -d -m 0700 "$config_dir" "$state_dir"
fi
install -d -m 0755 "$(dirname -- "$bin_file")" "$(dirname -- "$unit_file")"
install -m 0755 "$build_dir/punarod" "$bin_file"
install -m 0644 "$repo_dir/deploy/systemd/punarod.service" "$unit_file"

if [ -e "$config_file" ] || [ -L "$config_file" ]; then
	[ -f "$config_file" ] && [ ! -L "$config_file" ] || fail 'existing relay configuration must be a regular non-symlink file'
else
	cat >"$config_file" <<'EOF'
# Owner-managed Punaro relay configuration. Do not commit this file.
# The service unit pins the relay to loopback; use a separately configured,
# authenticated ingress such as Cloudflare Tunnel for remote clients.
PUNARO_RELAY_ENABLED=true
PUNARO_RELAY_MACHINES_JSON=
PUNARO_LOG_LEVEL=info

# For Cloudflare Access, add issuer, audience, and a protected local JWKS file.
# PUNARO_ACCESS_ISSUER=https://team.cloudflareaccess.example
# PUNARO_ACCESS_AUDIENCE=
# PUNARO_ACCESS_JWKS_FILE=/etc/punaro/jwks/current.json
EOF
	if [ "$root_dir" = / ]; then chown root:punaro "$config_file"; fi
	chmod 0640 "$config_file"
fi

if [ "$enable" -eq 1 ]; then
	grep -Eq '^PUNARO_RELAY_MACHINES_JSON=.+$' "$config_file" || fail 'add at least one public machine enrollment record before enabling the relay'
	systemctl daemon-reload
	systemctl enable --now punarod.service
fi

printf '%s\n' 'Punaro relay files installed. Add public machine enrollment records before starting it.' \
	"Configuration: $config_file" \
	"Then run: systemctl daemon-reload && systemctl enable --now punarod.service" \
	'Verify: curl --fail http://127.0.0.1:8080/readyz'
