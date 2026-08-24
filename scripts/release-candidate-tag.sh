#!/bin/sh
set -eu

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

[ "$#" -eq 3 ] || fail 'usage: release-candidate-tag.sh GITHUB_SHA GITHUB_RUN_ID GITHUB_RUN_ATTEMPT'

sha=$1
run_id=$2
attempt=$3

[ "${#sha}" -eq 40 ] || fail 'GitHub commit SHA must contain 40 lowercase hexadecimal characters'
case "$sha" in *[!0-9a-f]*) fail 'GitHub commit SHA must contain 40 lowercase hexadecimal characters' ;; esac
case "$run_id" in '' | *[!0-9]*) fail 'GitHub workflow run ID must be numeric' ;; esac
case "$attempt" in '' | *[!0-9]*) fail 'GitHub workflow run attempt must be numeric' ;; esac

tag="candidate-$sha-$run_id-$attempt"
[ "${#tag}" -le 128 ] || fail 'release candidate tag exceeds the Docker tag limit'

printf '%s\n' "$tag"
