#!/bin/sh
set -eu

staged_directory=/run/punaro-secrets
staged_password="$staged_directory/postgres_app_password"
install -d -m 0700 "$staged_directory"
chown postgres:postgres "$staged_directory"
cp /run/secrets/postgres_app_password "$staged_password"
chown postgres:postgres "$staged_password"
chmod 0400 "$staged_password"

exec /usr/local/bin/docker-entrypoint.sh "$@"
