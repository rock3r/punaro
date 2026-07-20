#!/bin/sh
set -eu

image=${1:-punaro:ci}
status=0
output=$(docker run --rm --entrypoint /usr/local/bin/punaro-migrate "$image" 2>&1) || status=$?
if [ "$status" -ne 2 ]; then
	echo "punaro-migrate container role returned $status, want explicit configuration refusal (2)" >&2
	exit 1
fi
if ! printf '%s\n' "$output" | grep -Fq 'requires complete update authorization'; then
	echo "punaro-migrate container role did not execute the expected command" >&2
	exit 1
fi

dsn_file=$(mktemp)
cleanup() { rm -f "$dsn_file"; }
trap cleanup EXIT INT TERM
chmod 600 "$dsn_file"
printf '%s\n' 'postgres://punaro_owner@127.0.0.1:1/punaro?sslmode=disable&connect_timeout=1' >"$dsn_file"
status=0
output=$(docker run --rm --user "$(id -u):$(id -g)" \
	--entrypoint /usr/local/bin/punaro-migrate \
	--mount "type=bind,src=$dsn_file,dst=/run/secrets/owner.dsn,readonly" \
	"$image" -owner-dsn-file /run/secrets/owner.dsn \
	-update-id 019b4eb0-21f8-7d93-84df-10e6cf05ce53 \
	-backup-id 019b4eb0-5317-79a6-a0de-fd97719910fb \
	-target-release v0.7.0 \
	-target-image ghcr.io/rock3r/punaro@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
	-target-schema 6 \
	-exported-snapshot-id 00000003-0000001B-1 \
	-manifest-sha256 cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc 2>&1) || status=$?
if [ "$status" -ne 1 ] || ! printf '%s\n' "$output" | grep -Fq 'punaro-migrate failed'; then
	echo "punaro-migrate container role could not read a protected mounted DSN" >&2
	exit 1
fi
