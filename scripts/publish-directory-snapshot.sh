#!/bin/sh
# Build a short-lived directory snapshot on the root-key host and atomically
# replace the relay's private snapshot inside a Proxmox container.
set -eu

require_absolute_file() {
	case "$2" in /*) ;; *) printf '%s must be an absolute path\n' "$1" >&2; exit 2;; esac
	[ -f "$2" ] || { printf '%s must name a regular file\n' "$1" >&2; exit 2; }
}
require_value() {
	eval "value=\${$1-}"
	[ -n "$value" ] || { printf '%s is required\n' "$1" >&2; exit 2; }
}
for variable in PUNARO_DIRECTORY_BINARY PUNARO_DIRECTORY_MANIFEST PUNARO_DIRECTORY_ROOT_PRIVATE_KEY PUNARO_PVE_SSH_TARGET PUNARO_PVE_CONTAINER_ID; do require_value "$variable"; done
require_absolute_file PUNARO_DIRECTORY_BINARY "$PUNARO_DIRECTORY_BINARY"
require_absolute_file PUNARO_DIRECTORY_MANIFEST "$PUNARO_DIRECTORY_MANIFEST"
require_absolute_file PUNARO_DIRECTORY_ROOT_PRIVATE_KEY "$PUNARO_DIRECTORY_ROOT_PRIVATE_KEY"
case "$PUNARO_PVE_CONTAINER_ID" in *[!0-9]*|'') printf '%s\n' 'PUNARO_PVE_CONTAINER_ID must be numeric' >&2; exit 2;; esac

if [ -n "${PUNARO_PVE_SSH_IDENTITY_FILE-}" ]; then
	require_absolute_file PUNARO_PVE_SSH_IDENTITY_FILE "$PUNARO_PVE_SSH_IDENTITY_FILE"
	ssh_pve() { ssh -o BatchMode=yes -o ConnectTimeout=10 -o IdentityAgent=none -o IdentitiesOnly=yes -i "$PUNARO_PVE_SSH_IDENTITY_FILE" "$@"; }
	scp_pve() { scp -q -o BatchMode=yes -o ConnectTimeout=10 -o IdentityAgent=none -o IdentitiesOnly=yes -i "$PUNARO_PVE_SSH_IDENTITY_FILE" "$@"; }
else
	ssh_pve() { ssh -o BatchMode=yes -o ConnectTimeout=10 "$@"; }
	scp_pve() { scp -q -o BatchMode=yes -o ConnectTimeout=10 "$@"; }
fi

container_snapshot_file=${PUNARO_CONTAINER_SNAPSHOT_FILE:-/etc/punaro/directory/v3-directory.snapshot}
case "$container_snapshot_file" in /etc/punaro/directory/*) ;; *) printf '%s\n' 'PUNARO_CONTAINER_SNAPSHOT_FILE must be below /etc/punaro/directory' >&2; exit 2;; esac
case "$container_snapshot_file" in *[!A-Za-z0-9_./-]*) printf '%s\n' 'PUNARO_CONTAINER_SNAPSHOT_FILE contains unsafe characters' >&2; exit 2;; esac
case "$container_snapshot_file/" in *'//'*) printf '%s\n' 'PUNARO_CONTAINER_SNAPSHOT_FILE must be canonical' >&2; exit 2;; esac
case "$container_snapshot_file/" in *'/../'*) printf '%s\n' 'PUNARO_CONTAINER_SNAPSHOT_FILE must not contain parent traversal' >&2; exit 2;; esac
container_snapshot_parent=$(dirname "$container_snapshot_file")
[ "$container_snapshot_parent" = /etc/punaro/directory ] || { printf '%s\n' 'PUNARO_CONTAINER_SNAPSHOT_FILE must be directly below /etc/punaro/directory' >&2; exit 2; }

# Keep an advisory lock across exec, so the kernel releases it after a crash,
# kill -9, or reboot. The file itself may persist safely; only its live lock
# state controls publication.
lock_file="$(dirname "$PUNARO_DIRECTORY_MANIFEST")/.punaro-directory-publish.lockfile"
if [ "${PUNARO_PUBLISH_LOCK_HELD-}" != 1 ]; then
	command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'python3 is required for crash-safe publisher locking' >&2; exit 2; }
	exec python3 - "$lock_file" "$0" "$@" <<'PY'
import fcntl
import os
import subprocess
import sys

lock_path, program, *program_args = sys.argv[1:]
fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print("directory_snapshot_publish_already_running", file=sys.stderr)
    raise SystemExit(75)
environment = os.environ.copy()
environment["PUNARO_PUBLISH_LOCK_HELD"] = "1"
completed = subprocess.run([program, *program_args], env=environment, close_fds=True)
raise SystemExit(completed.returncode)
PY
fi
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-directory.XXXXXXXX")
remote_stage=
container_stage=
cleanup() {
	[ -z "$remote_stage" ] || ssh_pve "$PUNARO_PVE_SSH_TARGET" rm -f -- "$remote_stage" >/dev/null 2>&1 || true
	[ -z "$container_stage" ] || ssh_pve "$PUNARO_PVE_SSH_TARGET" "pct exec $PUNARO_PVE_CONTAINER_ID -- rm -f -- '$container_stage'" >/dev/null 2>&1 || true
	rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

snapshot="$work_dir/snapshot"
"$PUNARO_DIRECTORY_BINARY" build --config "$PUNARO_DIRECTORY_MANIFEST" --root-private-key-file "$PUNARO_DIRECTORY_ROOT_PRIVATE_KEY" --output "$snapshot" --ttl 2m >/dev/null

# The root key never leaves this host. Only its signed snapshot crosses this hop.
remote_stage=$(ssh_pve "$PUNARO_PVE_SSH_TARGET" mktemp /tmp/punaro-directory.XXXXXXXX)
case "$remote_stage" in /tmp/punaro-directory.*) ;; *) printf '%s\n' 'Proxmox returned an unsafe staging path' >&2; exit 1;; esac
case "$remote_stage" in *[!A-Za-z0-9_./-]*) printf '%s\n' 'Proxmox returned an unsafe staging path' >&2; exit 1;; esac
scp_pve "$snapshot" "$PUNARO_PVE_SSH_TARGET:$remote_stage"
# The relay account cannot write either this staging directory or the final
# snapshot parent.  Both are under the root-owned /etc/punaro hierarchy, so
# root never publishes through service-owned paths. The final same-filesystem
# rename is atomic.
ssh_pve "$PUNARO_PVE_SSH_TARGET" "pct exec $PUNARO_PVE_CONTAINER_ID -- /bin/sh -ceu 'install -d -o root -g root -m 700 /etc/punaro/.punaro-directory-stage; install -d -o root -g punaro -m 2750 /etc/punaro/directory'"
container_stage=$(ssh_pve "$PUNARO_PVE_SSH_TARGET" "pct exec $PUNARO_PVE_CONTAINER_ID -- /bin/sh -ceu 'stage=\$(mktemp /etc/punaro/.punaro-directory-stage/snapshot.XXXXXXXX); chmod 600 \"\$stage\"; printf %s \"\$stage\"'")
case "$container_stage" in /etc/punaro/.punaro-directory-stage/snapshot.*) ;; *) printf '%s\n' 'container returned an unsafe staging path' >&2; exit 1;; esac
case "$container_stage" in *[!A-Za-z0-9_./-]*) printf '%s\n' 'container returned an unsafe staging path' >&2; exit 1;; esac
ssh_pve "$PUNARO_PVE_SSH_TARGET" pct push "$PUNARO_PVE_CONTAINER_ID" "$remote_stage" "$container_stage"
ssh_pve "$PUNARO_PVE_SSH_TARGET" "pct exec $PUNARO_PVE_CONTAINER_ID -- /bin/sh -ceu 'stage=\$1; target=\$2; parent=\$(dirname \"\$target\"); [ \"\$parent\" = /etc/punaro/directory ]; [ ! -L \"\$parent\" ]; [ -f \"\$stage\" ]; [ ! -L \"\$stage\" ]; [ \"\$(stat -c %U \"\$parent\")\" = root ]; [ \"\$(stat -c %G \"\$parent\")\" = punaro ]; [ \"\$(stat -c %a \"\$parent\")\" = 2750 ]; [ \"\$(stat -c %d /etc/punaro/.punaro-directory-stage)\" = \"\$(stat -c %d \"\$parent\")\" ]; chown root:punaro \"\$stage\"; chmod 640 \"\$stage\"; mv -f -- \"\$stage\" \"\$target\"' sh '$container_stage' '$container_snapshot_file'"
container_stage=
ssh_pve "$PUNARO_PVE_SSH_TARGET" rm -f -- "$remote_stage"
remote_stage=
printf '%s\n' 'directory_snapshot_published'
