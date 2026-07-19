#!/bin/sh
set -eu

image=${1:-punaro:ci}
status=0
output=$(docker run --rm --entrypoint /usr/local/bin/punaro-migrate "$image" 2>&1) || status=$?
if [ "$status" -ne 2 ]; then
	echo "punaro-migrate container role returned $status, want explicit configuration refusal (2)" >&2
	exit 1
fi
if ! printf '%s\n' "$output" | grep -Fq 'requires -owner-dsn-file'; then
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
	"$image" -owner-dsn-file /run/secrets/owner.dsn 2>&1) || status=$?
if [ "$status" -ne 1 ] || ! printf '%s\n' "$output" | grep -Fq 'PostgreSQL is unavailable'; then
	echo "punaro-migrate container role could not read a protected mounted DSN" >&2
	exit 1
fi
