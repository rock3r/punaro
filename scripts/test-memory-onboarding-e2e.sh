#!/bin/sh
# Exercise installed native clients against one disposable enrolled relay: memory
# CLI/MCP plus trusted-attachment transfer, authorization, restart, and revoke.
set -eu

if ! docker compose version >/dev/null 2>&1; then
	printf '%s\n' 'Docker Compose v2 is required for native memory onboarding E2E tests' >&2
	exit 1
fi

project="punaro-memory-onboarding-${GITHUB_RUN_ID:-local}-$$"
compose_file="docker-compose.memory-onboarding-e2e.yml"
cleanup() {
	docker compose --project-name "$project" --file "$compose_file" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose --project-name "$project" --file "$compose_file" up --build --abort-on-container-exit --exit-code-from memory-onboarding-e2e
