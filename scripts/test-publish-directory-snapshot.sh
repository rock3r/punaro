#!/bin/sh
# Exercise validation before the publisher can contact Proxmox or build a file.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-publisher-test.XXXXXXXX")
cleanup() { rm -rf -- "$fixture_dir"; }
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

assert_rejected /var/lib/punaro/private/../../etc/passwd 'PUNARO_CONTAINER_SNAPSHOT_FILE must not contain parent traversal'
assert_rejected /var/lib/punaro/private//snapshot 'PUNARO_CONTAINER_SNAPSHOT_FILE must be canonical'
assert_rejected /var/lib/punaro/private/nested/snapshot 'PUNARO_CONTAINER_SNAPSHOT_FILE must be directly below /var/lib/punaro/private'

printf '%s\n' publisher_path_rejection_tests_passed
