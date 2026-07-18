#!/bin/sh
# Install the loopback-only Punaro relay service. Run on Linux as root; --root
# is retained for package-image/staging validation and never starts a service.
set -eu

umask 077

usage() {
	cat <<'EOF'
Usage: scripts/install-server.sh [options]

Build and install punarod, its hardened systemd unit, and an owner-controlled
relay configuration. The service is not started until the enrollment set is
configured. --root stages files below an alternate root and never alters host
users or systemd.

Options:
  --machines-file ABSOLUTE_JSON_FILE
                            Approved public machine enrollment array; writes
                            PUNARO_RELAY_MACHINES_JSON without shell quoting
  --access-issuer HTTPS_URL Cloudflare Access issuer (requires the other
                            --access-* options)
  --access-audience AUDIENCE
                            Cloudflare Access audience
  --access-jwks-url HTTPS_URL
                            Public Access JWKS URL; installs the local,
                            root-run snapshot refresh timer
  --enable                  Refresh JWKS when configured, then enable relay
  --root ABSOLUTE_STAGING_ROOT
                            Render a package image only; cannot use --enable

No option accepts a private key, service token, tunnel token, message body, or
other secret. A Cloudflare Tunnel credential remains a separate systemd
LoadCredential operation.
EOF
}

fail() { printf '%s\n' "$1" >&2; exit 2; }

require_safe_value() {
	case "$1" in
		''|*[!A-Za-z0-9_./:@%+=,-]*) fail "$2 contains unsupported characters" ;;
	esac
}

regular_file() { [ -f "$1" ] && [ ! -L "$1" ]; }

root_dir=/
enable=0
machines_file=
access_issuer=
access_audience=
access_jwks_url=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--root) [ "$#" -ge 2 ] || fail '--root requires a value'; root_dir=$2; shift 2 ;;
		--machines-file) [ "$#" -ge 2 ] || fail '--machines-file requires a value'; machines_file=$2; shift 2 ;;
		--access-issuer) [ "$#" -ge 2 ] || fail '--access-issuer requires a value'; access_issuer=$2; shift 2 ;;
		--access-audience) [ "$#" -ge 2 ] || fail '--access-audience requires a value'; access_audience=$2; shift 2 ;;
		--access-jwks-url) [ "$#" -ge 2 ] || fail '--access-jwks-url requires a value'; access_jwks_url=$2; shift 2 ;;
		--enable) enable=1; shift ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

case "$root_dir" in /*) ;; *) fail 'root directory must be an absolute path' ;; esac
if [ -n "$machines_file" ]; then
	case "$machines_file" in /*) ;; *) fail 'machines file must be an absolute path' ;; esac
	regular_file "$machines_file" || fail 'machines file must be a non-symlink regular file'
fi
if [ -n "$access_issuer$access_audience$access_jwks_url" ]; then
	[ -n "$access_issuer" ] && [ -n "$access_audience" ] && [ -n "$access_jwks_url" ] || fail 'Cloudflare Access setup requires --access-issuer, --access-audience, and --access-jwks-url together'
	case "$access_issuer" in https://*) ;; *) fail 'Access issuer must use https://' ;; esac
	case "$access_jwks_url" in https://*) ;; *) fail 'Access JWKS URL must use https://' ;; esac
	require_safe_value "$access_issuer" 'Access issuer'
	require_safe_value "$access_audience" 'Access audience'
	require_safe_value "$access_jwks_url" 'Access JWKS URL'
fi
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
if [ -n "$machines_file$access_issuer" ]; then command -v python3 >/dev/null 2>&1 || fail 'python3 is required to render relay configuration'; fi

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
jwks_dir=$(path_in_root etc/punaro/jwks)
jwks_env=$(path_in_root etc/punaro/jwks-refresh.env)
jwks_service=$(path_in_root etc/systemd/system/punaro-jwks-refresh.service)
jwks_timer=$(path_in_root etc/systemd/system/punaro-jwks-refresh.timer)
jwks_helper=$(path_in_root usr/local/libexec/punaro/refresh-jwks)
jwks_file=/etc/punaro/jwks/current.json

machine_json=
if [ -n "$machines_file" ]; then
	machine_json=$(python3 - "$machines_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    records = json.load(handle)
if not isinstance(records, list) or not records:
    raise SystemExit("machines file must contain a non-empty JSON array")
if not all(isinstance(record, dict) for record in records):
    raise SystemExit("machines file entries must be JSON objects")
print(json.dumps(records, sort_keys=True, separators=(",", ":")))
PY
) || fail 'machines file must contain a non-empty JSON array of public records'
fi

write_config() {
	cat <<EOF
# Owner-managed Punaro relay configuration. Do not commit this file.
# The service unit pins the relay to loopback; use a separately configured,
# authenticated ingress such as Cloudflare Tunnel for remote clients.
PUNARO_RELAY_ENABLED=true
PUNARO_RELAY_MACHINES_JSON=$machine_json
PUNARO_LOG_LEVEL=info
EOF
	if [ -n "$access_issuer" ]; then
		cat <<EOF

# Cloudflare Access admission. The local JWKS refresh service owns the snapshot.
PUNARO_ACCESS_ISSUER=$access_issuer
PUNARO_ACCESS_AUDIENCE=$access_audience
PUNARO_ACCESS_JWKS_FILE=$jwks_file
EOF
	else
		cat <<'EOF'

# For Cloudflare Access, use --access-issuer, --access-audience, and
# --access-jwks-url together so the installer creates a hardened JWKS refresh.
EOF
	fi
}

update_config() {
	[ -n "$machines_file$access_issuer" ] || return
	python3 - "$config_file" "$machine_json" "$access_issuer" "$access_audience" "$jwks_file" <<'PY'
import os
import stat
import sys
import tempfile

path, machines, issuer, audience, jwks_file = sys.argv[1:]
status = os.lstat(path)
if not stat.S_ISREG(status.st_mode):
    raise SystemExit("existing relay configuration must be a regular non-symlink file")
with open(path, encoding="utf-8") as handle:
    lines = handle.read().splitlines()
replacements = {}
if machines:
    replacements["PUNARO_RELAY_MACHINES_JSON"] = machines
if issuer:
    replacements.update({
        "PUNARO_ACCESS_ISSUER": issuer,
        "PUNARO_ACCESS_AUDIENCE": audience,
        "PUNARO_ACCESS_JWKS_FILE": jwks_file,
    })
seen = set()
updated = []
for line in lines:
    key = line.split("=", 1)[0]
    # PUNARO_ACCESS_JWKS_URL was the pre-installer online source.  The relay
    # rejects both it and the managed snapshot file, so migration removes it.
    if issuer and key == "PUNARO_ACCESS_JWKS_URL":
        continue
    if key in replacements:
        if key in seen:
            raise SystemExit(f"duplicate {key} in relay configuration")
        updated.append(f"{key}={replacements[key]}")
        seen.add(key)
    else:
        updated.append(line)
for key, value in replacements.items():
    if key not in seen:
        updated.append(f"{key}={value}")
fd, temporary = tempfile.mkstemp(prefix=".punaro.env.", dir=os.path.dirname(path))
try:
    os.fchmod(fd, stat.S_IMODE(status.st_mode))
    os.fchown(fd, status.st_uid, status.st_gid)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(updated) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
except BaseException:
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
    raise
PY
}

write_jwks_env() {
	cat <<EOF
# Public Cloudflare Access JWKS source. This file contains no credential.
PUNARO_ACCESS_JWKS_URL=$access_jwks_url
PUNARO_ACCESS_JWKS_FILE=$jwks_file
EOF
}

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
	regular_file "$config_file" || fail 'existing relay configuration must be a regular non-symlink file'
	update_config
else
	write_config >"$config_file"
	if [ "$root_dir" = / ]; then chown root:punaro "$config_file"; fi
	chmod 0640 "$config_file"
fi

if [ -n "$access_issuer" ]; then
	if [ "$root_dir" = / ]; then
		install -d -o root -g punaro -m 2750 "$jwks_dir"
	else
		install -d -m 0700 "$jwks_dir"
	fi
	install -d -m 0755 "$(dirname -- "$jwks_helper")"
	install -m 0755 "$repo_dir/deploy/systemd/refresh-jwks" "$jwks_helper"
	install -m 0644 "$repo_dir/deploy/systemd/punaro-jwks-refresh.service" "$jwks_service"
	install -m 0644 "$repo_dir/deploy/systemd/punaro-jwks-refresh.timer" "$jwks_timer"
	if [ -e "$jwks_env" ] || [ -L "$jwks_env" ]; then
		regular_file "$jwks_env" || fail 'existing JWKS refresh configuration must be a regular non-symlink file'
		grep -Fqx "PUNARO_ACCESS_JWKS_URL=$access_jwks_url" "$jwks_env" || fail 'existing JWKS refresh configuration belongs to a different URL'
		grep -Fqx "PUNARO_ACCESS_JWKS_FILE=$jwks_file" "$jwks_env" || fail 'existing JWKS refresh configuration has an unexpected snapshot path'
	else
		write_jwks_env >"$jwks_env"
		if [ "$root_dir" = / ]; then chown root:root "$jwks_env"; fi
		chmod 0600 "$jwks_env"
	fi
fi

if [ "$enable" -eq 1 ]; then
	grep -Eq '^PUNARO_RELAY_MACHINES_JSON=.+$' "$config_file" || fail 'add at least one public machine enrollment record before enabling the relay'
	systemctl daemon-reload
	if grep -Fqx "PUNARO_ACCESS_JWKS_FILE=$jwks_file" "$config_file"; then
		systemctl start punaro-jwks-refresh.service
		systemctl enable --now punaro-jwks-refresh.timer
	fi
	systemctl enable punarod.service
	systemctl restart punarod.service
fi

printf '%s\n' 'Punaro relay files installed.' \
	"Configuration: $config_file" \
	'Use --machines-file /approved/public-machines.json --enable on a fresh host to configure and start in one command.' \
	'Verify: curl --fail http://127.0.0.1:8080/readyz'
