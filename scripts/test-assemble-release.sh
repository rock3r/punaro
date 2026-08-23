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
go run -C "$repo_dir" ./cmd/punaro-release assemble \
	--dir "$artifacts" \
	--release v0.1.0 \
	--sequence 1 \
	--catalog-sequence 1 \
	--published-at 2026-08-16T12:00:00Z \
	--expires-at 2026-08-23T12:00:00Z

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
if ! grep -Fq -- '--provenance mode=max' "$repo_dir/.github/workflows/release.yml" ||
	! grep -Fq -- '--sbom true' "$repo_dir/.github/workflows/release.yml" ||
	! grep -Fq 'packages: write' "$repo_dir/.github/workflows/release.yml" ||
	! grep -Fq 'needs.image.outputs.image' "$repo_dir/.github/workflows/release.yml"; then
	printf '%s\n' 'release workflow does not publish and bind the attested GHCR image' >&2
	exit 1
fi
if ! grep -Fq 'ARG PUNARO_RELEASE' "$repo_dir/Dockerfile" ||
	! grep -Fq 'main.serverBuildRelease=${PUNARO_RELEASE}' "$repo_dir/Dockerfile" ||
	! grep -Fq 'main.telegramBuildSequence=${PUNARO_SEQUENCE}' "$repo_dir/Dockerfile" ||
	! grep -Fq 'main.telegramBuildCatalogSequence=${PUNARO_CATALOG_SEQUENCE}' "$repo_dir/Dockerfile"; then
	printf '%s\n' 'release image does not embed its build identity' >&2
	exit 1
fi
if grep -Fq 'gh release upload catalog dist/punaro-catalog.json' "$repo_dir/.github/workflows/release.yml"; then
	printf '%s\n' 'unsigned workflow still mutates the live catalog' >&2
	exit 1
fi
if ! grep -Fq -- '--previous-catalog' "$repo_dir/.github/workflows/release.yml" ||
	! grep -Fq -- '--minimum-safe-sequence' "$repo_dir/.github/workflows/release.yml" ||
	! grep -Fq -- '--critical-block' "$repo_dir/.github/workflows/release.yml" ||
	! grep -Fq -- '--supported-from' "$repo_dir/.github/workflows/release.yml"; then
	printf '%s\n' 'release workflow cannot maintain retained live catalog releases' >&2
	exit 1
fi
if grep -Eq 'inputs\.draft|DRAFT:' "$repo_dir/.github/workflows/release.yml" ||
	! grep -Fq 'gh release create "$RELEASE" --target "$GITHUB_SHA" --draft' "$repo_dir/.github/workflows/release.yml"; then
	printf '%s\n' 'unsigned workflow can publish a non-draft candidate' >&2
	exit 1
fi
if ! "$repo_dir/scripts/publish-signed-release.sh" --help >/dev/null ||
	! grep -Fq 'go run ./cmd/punaro-release verify' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'gh release edit "$release"' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'restore_previous_catalog' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'catalog_restore_required=true' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'catalog_redraft_required=true' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'redraft_catalog' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'verify-artifacts --manifest "$manifest" --dir "$draft_release_dir"' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'verify-artifacts --manifest "$verification_dir/punaro-release.json" --dir "$verification_dir"' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'publication-check --catalog "$catalog"' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq -- '--previous-catalog "$previous_catalog"' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'release_is_prerelease' "$repo_dir/scripts/publish-signed-release.sh" ||
	! grep -Fq 'gh release create catalog --repo "$repository" --draft' "$repo_dir/scripts/publish-signed-release.sh"; then
	printf '%s\n' 'verified offline release publication step is unavailable' >&2
	exit 1
fi
