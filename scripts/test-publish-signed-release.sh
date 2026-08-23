#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/punaro-publish-test.XXXXXXXX")
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM

prepare_case() {
	case_root=$1
	mkdir -p "$case_root/bin" "$case_root/documents" "$case_root/state/remote/v0.1.0-alpha.1"
	cp "$repo_dir/scripts/testdata/fake-publish-go.sh" "$case_root/bin/go"
	cp "$repo_dir/scripts/testdata/fake-publish-gh.sh" "$case_root/bin/gh"
	chmod +x "$case_root/bin/go" "$case_root/bin/gh"
	printf '%s\n' manifest >"$case_root/documents/punaro-release.json"
	printf '%s\n' manifest-signature >"$case_root/documents/punaro-release.sig"
	printf '%s\n' catalog >"$case_root/documents/punaro-catalog.json"
	printf '%s\n' catalog-signature >"$case_root/documents/punaro-catalog.sig"
	printf '%s\n' public-key >"$case_root/release.pub"
	cp "$case_root/documents/punaro-release.json" "$case_root/state/remote/v0.1.0-alpha.1/"
	cp "$case_root/documents/punaro-catalog.json" "$case_root/state/remote/v0.1.0-alpha.1/"
	printf '%s\n' true >"$case_root/state/release-draft"
	printf '%s\n' false >"$case_root/state/release-prerelease"
}

preflight="$temporary/preflight"
prepare_case "$preflight"
touch "$preflight/state/fail-publication-check"
if PATH="$preflight/bin:$PATH" \
	PUNARO_FAKE_GH_STATE="$preflight/state" \
	PUNARO_FAKE_GH_LOG="$preflight/gh.log" \
	PUNARO_FAKE_GO_LOG="$preflight/go.log" \
	"$repo_dir/scripts/publish-signed-release.sh" --release v0.1.0-alpha.1 --dir "$preflight/documents" --keys-file "$preflight/release.pub" >/dev/null 2>&1; then
	printf '%s\n' 'expired publication preflight unexpectedly succeeded' >&2
	exit 1
fi
if [ -s "$preflight/gh.log" ]; then
	printf '%s\n' 'publication mutated GitHub state after a failed freshness preflight' >&2
	exit 1
fi

sequence="$temporary/sequence"
prepare_case "$sequence"
mkdir -p "$sequence/state/remote/catalog"
cp "$sequence/documents/punaro-catalog.json" "$sequence/state/remote/catalog/"
cp "$sequence/documents/punaro-catalog.sig" "$sequence/state/remote/catalog/"
printf '%s\n' false >"$sequence/state/catalog-draft"
touch "$sequence/state/fail-previous-publication-check"
if PATH="$sequence/bin:$PATH" \
	PUNARO_FAKE_GH_STATE="$sequence/state" \
	PUNARO_FAKE_GH_LOG="$sequence/gh.log" \
	PUNARO_FAKE_GO_LOG="$sequence/go.log" \
	"$repo_dir/scripts/publish-signed-release.sh" --release v0.1.0-alpha.1 --dir "$sequence/documents" --keys-file "$sequence/release.pub" >/dev/null 2>&1; then
	printf '%s\n' 'non-advancing catalog sequence unexpectedly succeeded' >&2
	exit 1
fi
if grep -Eq '^release (upload|edit|create) ' "$sequence/gh.log"; then
	printf '%s\n' 'publication mutated GitHub state after a failed sequence preflight' >&2
	exit 1
fi

retry="$temporary/retry"
prepare_case "$retry"
touch "$retry/state/fail-catalog-download-once"
if PATH="$retry/bin:$PATH" \
	PUNARO_FAKE_GH_STATE="$retry/state" \
	PUNARO_FAKE_GH_LOG="$retry/gh.log" \
	PUNARO_FAKE_GO_LOG="$retry/go.log" \
	"$repo_dir/scripts/publish-signed-release.sh" --release v0.1.0-alpha.1 --dir "$retry/documents" --keys-file "$retry/release.pub" >"$retry/first.out" 2>"$retry/first.err"; then
	printf '%s\n' 'remote verification failure unexpectedly succeeded' >&2
	exit 1
fi
if [ "$(cat "$retry/state/release-draft")" != false ] || [ "$(cat "$retry/state/release-prerelease")" != true ] || [ "$(cat "$retry/state/catalog-draft")" != true ]; then
	cat "$retry/first.err" >&2
	cat "$retry/gh.log" >&2
	printf '%s\n' 'failed first publication did not preserve a retryable prerelease and hidden catalog' >&2
	exit 1
fi

PATH="$retry/bin:$PATH" \
	PUNARO_FAKE_GH_STATE="$retry/state" \
	PUNARO_FAKE_GH_LOG="$retry/gh.log" \
	PUNARO_FAKE_GO_LOG="$retry/go.log" \
	"$repo_dir/scripts/publish-signed-release.sh" --release v0.1.0-alpha.1 --dir "$retry/documents" --keys-file "$retry/release.pub" >/dev/null
if [ "$(cat "$retry/state/catalog-draft")" != false ]; then
	printf '%s\n' 'publication retry did not expose the remotely verified catalog' >&2
	exit 1
fi
if [ "$(grep -Fc 'release edit v0.1.0-alpha.1 --repo rock3r/punaro --draft=false --prerelease' "$retry/gh.log")" -ne 1 ]; then
	printf '%s\n' 'publication retry attempted to republish the already exact prerelease' >&2
	exit 1
fi

printf '%s\n' 'publish_signed_release_tests_passed'
