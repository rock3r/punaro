#!/bin/sh
set -eu

compose_file=${1:-docker-compose.postgres-test.yml}

grep -Eq 'pgvector/pgvector:[^[:space:]]+@sha256:[0-9a-f]{64}' "$compose_file"
grep -Eq 'internal:[[:space:]]*true' "$compose_file"
if grep -Eq '^[[:space:]]+ports:' "$compose_file"; then
	echo "PostgreSQL integration Compose file must not publish ports" >&2
	exit 1
fi
grep -Eq 'condition:[[:space:]]*service_healthy' "$compose_file"
grep -Eq 'PUNARO_TEST_POSTGRES_OWNER_DSN:' "$compose_file"
grep -Eq 'PUNARO_TEST_POSTGRES_APP_DSN:' "$compose_file"
