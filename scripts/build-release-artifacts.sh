#!/bin/sh
# Build one platform's native Punaro artifacts for a GitHub Release.
# This does not sign, fetch, or publish.
set -eu

usage() {
	cat <<'EOF'
Usage: scripts/build-release-artifacts.sh --output-dir DIR --release RELEASE --sequence N --catalog-sequence N [--image DIGEST_PINNED_IMAGE]

Build the current GOOS/GOARCH (or GOOS/GOARCH from the environment) into DIR
using names bootstrap will later look up: component-os-arch[.exe].
EOF
}

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

output_dir=
release=
sequence=
catalog_sequence=
image=

while [ "$#" -gt 0 ]; do
	case "$1" in
		--output-dir) [ "$#" -ge 2 ] || fail '--output-dir requires a value'; output_dir=$2; shift 2 ;;
		--release) [ "$#" -ge 2 ] || fail '--release requires a value'; release=$2; shift 2 ;;
		--sequence) [ "$#" -ge 2 ] || fail '--sequence requires a value'; sequence=$2; shift 2 ;;
		--catalog-sequence) [ "$#" -ge 2 ] || fail '--catalog-sequence requires a value'; catalog_sequence=$2; shift 2 ;;
		--image) [ "$#" -ge 2 ] || fail '--image requires a value'; image=$2; shift 2 ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

[ -n "$output_dir" ] || fail '--output-dir is required'
[ -n "$release" ] || fail '--release is required'
case "$sequence" in ''|*[!0-9]*) fail '--sequence must be a positive integer' ;; esac
case "$catalog_sequence" in ''|*[!0-9]*) fail '--catalog-sequence must be a positive integer' ;; esac
[ "$sequence" -ge 1 ] || fail '--sequence must be a positive integer'
[ "$catalog_sequence" -ge 1 ] || fail '--catalog-sequence must be a positive integer'
if [ -n "$image" ]; then
	case "$image" in *@sha256:*) ;; *) fail '--image must be digest pinned' ;; esac
	image_digest=${image##*@sha256:}
	[ "${#image_digest}" -eq 64 ] || fail '--image must be digest pinned'
	case "$image_digest" in *[!0-9a-f]*) fail '--image must be digest pinned' ;; esac
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
[ -f "$repo_dir/go.mod" ] && [ -d "$repo_dir/cmd/punaro-adapter" ] || fail 'run this builder from a complete Punaro source checkout'

facts=$(
	cd "$repo_dir"
	env -u GOOS -u GOARCH -u CGO_ENABLED go run ./cmd/punaro-release build-facts --release "$release" --compose-file "$repo_dir/deploy/compose/production.yaml" --plugin-root "$repo_dir"
) || fail 'release build identity is invalid'
compose_sha256=$(printf '%s\n' "$facts" | sed -n 's/.*"compose_sha256":"\([0-9a-f]*\)".*/\1/p')
migration_sha256=$(printf '%s\n' "$facts" | sed -n 's/.*"migration_manifest_sha256":"\([0-9a-f]*\)".*/\1/p')
skill_sha256=$(printf '%s\n' "$facts" | sed -n 's/.*"skill_set_sha256":"\([0-9a-f]*\)".*/\1/p')
[ "${#compose_sha256}" -eq 64 ] && [ "${#migration_sha256}" -eq 64 ] && [ "${#skill_sha256}" -eq 64 ] || fail 'release build identity is invalid'

goos=${GOOS:-$(go env GOOS)}
goarch=${GOARCH:-$(go env GOARCH)}
cgo=${CGO_ENABLED:-}
if [ -z "$cgo" ]; then
	case "$goos" in
		darwin) cgo=1 ;;
		*) cgo=0 ;;
	esac
fi

case "$goos" in
	darwin|linux|windows) ;;
	*) fail "unsupported GOOS: $goos" ;;
esac
case "$goarch" in
	amd64|arm64) ;;
	*) fail "unsupported GOARCH: $goarch" ;;
esac

mkdir -p "$output_dir"
suffix=
if [ "$goos" = windows ]; then
	suffix=.exe
fi

build() {
	component=$1
	package=$2
	output="$output_dir/${component}-${goos}-${goarch}${suffix}"
	ldflags=
	case "$component" in
		punaro-adapter) ldflags="-X main.adapterBuildRelease=$release -X main.adapterExpectedSkillSetDigest=$skill_sha256" ;;
		punaro-bootstrap) ldflags="-X main.bootstrapBuildRelease=$release" ;;
		punaro) ldflags="-X main.serverBuildRelease=$release -X main.serverBuildSequence=$sequence -X main.serverBuildCatalogSequence=$catalog_sequence -X main.serverBuildImage=$image -X main.serverBuildComposeSHA256=$compose_sha256 -X main.serverBuildMigrationSHA256=$migration_sha256" ;;
		punaro-telegram) ldflags="-X main.telegramBuildRelease=$release -X main.telegramBuildSequence=$sequence -X main.telegramBuildCatalogSequence=$catalog_sequence" ;;
	esac
	(
		cd "$repo_dir"
		GOOS="$goos" GOARCH="$goarch" CGO_ENABLED="$cgo" go build -trimpath -buildvcs=true -ldflags "$ldflags" -o "$output" "$package"
	)
}

build punaro-adapter ./cmd/punaro-adapter
build punaro-trusted-attachment ./cmd/punaro-trusted-attachment
build punaro-memory ./cmd/punaro-memory
build punaro-enroll ./cmd/punaro-enroll
build punaro-bootstrap ./cmd/punaro-bootstrap

if [ "$goos" = linux ]; then
	build punaro ./cmd/punaro
	build punaro-telegram ./cmd/punaro-telegram
	build punaro-relay-adopt-prepare ./cmd/punaro-relay-adopt-prepare
fi
