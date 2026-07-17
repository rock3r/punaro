#!/bin/sh
# Exercise validation before the publisher can contact Proxmox or build a file.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-publisher-test.XXXXXXXX")
cleanup() { rm -rf -- "$fixture_dir"; rm -f -- /tmp/punaro-publisher-lock-test.out; }
trap cleanup EXIT HUP INT TERM

for file in binary manifest root-key; do
	: > "$fixture_dir/$file"
done

assert_rejected() {
	path=$1
	expected=$2
	set +e
	output=$(env \
		PUNARO_DIRECTORY_BINARY="$fixture_dir/binary" \
		PUNARO_DIRECTORY_MANIFEST="$fixture_dir/manifest" \
		PUNARO_DIRECTORY_ROOT_PRIVATE_KEY="$fixture_dir/root-key" \
		PUNARO_PVE_SSH_TARGET=example.invalid \
		PUNARO_PVE_CONTAINER_ID=111 \
		PUNARO_CONTAINER_SNAPSHOT_FILE="$path" \
		sh "$repo_dir/scripts/publish-directory-snapshot.sh" 2>&1)
	status=$?
	set -e
	[ "$status" -eq 2 ] || { printf '%s\n' "expected validation rejection for $path" >&2; exit 1; }
	[ "$output" = "$expected" ] || { printf '%s\n' "unexpected validation result for $path: $output" >&2; exit 1; }
}

assert_rejected /etc/punaro/directory/../../etc/passwd 'PUNARO_CONTAINER_SNAPSHOT_FILE must not contain parent traversal'
assert_rejected /etc/punaro/directory//snapshot 'PUNARO_CONTAINER_SNAPSHOT_FILE must be canonical'
assert_rejected /etc/punaro/directory/nested/snapshot 'PUNARO_CONTAINER_SNAPSHOT_FILE must be directly below /etc/punaro/directory'

publisher_env() {
	env \
		PUNARO_DIRECTORY_BINARY="$fixture_dir/binary" \
		PUNARO_DIRECTORY_MANIFEST="$fixture_dir/manifest" \
		PUNARO_DIRECTORY_ROOT_PRIVATE_KEY="$fixture_dir/root-key" \
		PUNARO_PVE_SSH_TARGET=example.invalid \
		PUNARO_PVE_CONTAINER_ID=111 \
		sh "$repo_dir/scripts/publish-directory-snapshot.sh"
}

printf '%s\n' '#!/bin/sh' 'sleep 2' 'exit 1' > "$fixture_dir/binary"
chmod 700 "$fixture_dir/binary"
publisher_env >/dev/null 2>&1 &
holder=$!
lock_file="$fixture_dir/.punaro-directory-publish.lockfile"
for _ in 1 2 3 4 5 6 7 8 9 10; do
	[ -f "$lock_file" ] && break
	sleep 1
done
[ -f "$lock_file" ] || { printf '%s\n' 'publisher did not create advisory lock' >&2; exit 1; }
set +e
publisher_env >/tmp/punaro-publisher-lock-test.out 2>&1
contender_status=$?
set -e
[ "$contender_status" -eq 75 ] || { printf '%s\n' 'concurrent publisher was not rejected' >&2; exit 1; }
wait "$holder" || true

# The child kills the publisher shell exactly as a crash would while its own
# child survives briefly. That lingering child must not retain the advisory
# lock and block the next publisher.
printf '%s\n' '#!/bin/sh' 'sleep 3 &' 'kill -9 "$PPID"' 'exit 1' > "$fixture_dir/binary"
set +e
publisher_env >/dev/null 2>&1
set -e
printf '%s\n' '#!/bin/sh' 'exit 1' > "$fixture_dir/binary"
set +e
publisher_env >/dev/null 2>&1
recovery_status=$?
set -e
[ "$recovery_status" -ne 75 ] || { printf '%s\n' 'stale publisher lock blocked recovery' >&2; exit 1; }

printf '%s\n' publisher_path_rejection_tests_passed
