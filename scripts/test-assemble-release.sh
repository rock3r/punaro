#!/bin/sh
# Verify the public release assembler writes a catalog/manifest pair that the
# strict parser accepts, without publishing or signing.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-release-assemble.XXXXXXXX")
cleanup() { rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

artifacts="$fixture_dir/artifacts"
mkdir -p "$artifacts"
printf '%s\n' 'dummy-adapter' >"$artifacts/punaro-adapter-linux-amd64"
printf '%s\n' 'services: {}' >"$fixture_dir/compose.yaml"

go run -C "$repo_dir" ./cmd/punaro-release assemble \
	--dir "$artifacts" \
	--release v0.1.0 \
	--sequence 1 \
	--catalog-sequence 1 \
	--published-at 2026-08-16T12:00:00Z \
	--expires-at 2026-08-23T12:00:00Z \
	--compose-file "$fixture_dir/compose.yaml"

[ -f "$artifacts/punaro-release.json" ] || { printf '%s\n' 'manifest was not written' >&2; exit 1; }
[ -f "$artifacts/punaro-catalog.json" ] || { printf '%s\n' 'catalog was not written' >&2; exit 1; }

if grep -Eq 'https?://|latest' "$artifacts/punaro-release.json" "$artifacts/punaro-catalog.json"; then
	printf '%s\n' 'assembled documents contain a URL or latest pointer' >&2
	exit 1
fi

if ! "$repo_dir/scripts/build-release-artifacts.sh" --help >/dev/null; then
	printf '%s\n' 'build-release-artifacts help failed' >&2
	exit 1
fi
if ! grep -Fq 'build punaro-relay-adopt-prepare ./cmd/punaro-relay-adopt-prepare' "$repo_dir/scripts/build-release-artifacts.sh"; then
	printf '%s\n' 'linux release artifacts omit punaro-relay-adopt-prepare' >&2
	exit 1
fi
