#!/bin/sh
set -eu

if ! docker compose version >/dev/null 2>&1; then
	echo "Docker Compose v2 is required for PostgreSQL integration tests" >&2
	exit 1
fi

project="punaro-pgtest-${GITHUB_RUN_ID:-local}-$$"
compose_file="docker-compose.postgres-test.yml"
cleanup() {
	docker compose --project-name "$project" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose --project-name "$project" --file "$compose_file" up --build --abort-on-container-exit --exit-code-from postgres-tests
