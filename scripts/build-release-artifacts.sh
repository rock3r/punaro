#!/bin/sh
# Build one platform's native Punaro artifacts for a GitHub Release.
# This does not sign, fetch, or publish.
set -eu

usage() {
	cat <<'EOF'
Usage: scripts/build-release-artifacts.sh --output-dir DIR

Build the current GOOS/GOARCH (or GOOS/GOARCH from the environment) into DIR
using names bootstrap will later look up: component-os-arch[.exe].
EOF
}

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

output_dir=

while [ "$#" -gt 0 ]; do
	case "$1" in
		--output-dir) [ "$#" -ge 2 ] || fail '--output-dir requires a value'; output_dir=$2; shift 2 ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

[ -n "$output_dir" ] || fail '--output-dir is required'

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
[ -f "$repo_dir/go.mod" ] && [ -d "$repo_dir/cmd/punaro-adapter" ] || fail 'run this builder from a complete Punaro source checkout'

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
	(
		cd "$repo_dir"
		GOOS="$goos" GOARCH="$goarch" CGO_ENABLED="$cgo" go build -trimpath -buildvcs=true -o "$output" "$package"
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
fi
