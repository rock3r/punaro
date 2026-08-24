#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/punaro-publish-test.XXXXXXXX")
cleanup() { rm -rf -- "$temporary"; }
trap cleanup EXIT HUP INT TERM
publisher_tmp="$temporary/publisher-tmp"
mkdir "$publisher_tmp"
export TMPDIR="$publisher_tmp/"

prepare_case() {
	case_root=$1
	mkdir -p "$case_root/bin" "$case_root/documents" "$case_root/state/remote/v0.1.0-alpha.1"
	cp "$repo_dir/scripts/testdata/fake-publish-go.sh" "$case_root/bin/go"
	cp "$repo_dir/scripts/testdata/fake-publish-gh.sh" "$case_root/bin/gh"
	chmod +x "$case_root/bin/go" "$case_root/bin/gh"
	printf '%s\n' '{"artifacts":[{"path":"v0.1.0-alpha.1/punaro-adapter-linux-amd64"}]}' >"$case_root/documents/punaro-release.json"
	printf '%s\n' manifest-signature >"$case_root/documents/punaro-release.sig"
	printf '%s\n' catalog >"$case_root/documents/punaro-catalog.json"
	printf '%s\n' catalog-signature >"$case_root/documents/punaro-catalog.sig"
	printf '%s\n' artifact >"$case_root/documents/punaro-adapter-linux-amd64"
	printf '%s\n' public-key >"$case_root/release.pub"
	cp "$case_root/documents/punaro-release.json" "$case_root/state/remote/v0.1.0-alpha.1/"
	cp "$case_root/documents/punaro-catalog.json" "$case_root/state/remote/v0.1.0-alpha.1/"
	cp "$case_root/documents/punaro-adapter-linux-amd64" "$case_root/state/remote/v0.1.0-alpha.1/"
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

replacement="$temporary/replacement"
prepare_case "$replacement"
mkdir -p "$replacement/state/remote/catalog"
printf '%s\n' previous-catalog >"$replacement/state/remote/catalog/punaro-catalog.json"
printf '%s\n' previous-signature >"$replacement/state/remote/catalog/punaro-catalog.sig"
printf '%s\n' false >"$replacement/state/catalog-draft"
PATH="$replacement/bin:$PATH" \
	PUNARO_FAKE_GH_STATE="$replacement/state" \
	PUNARO_FAKE_GH_LOG="$replacement/gh.log" \
	PUNARO_FAKE_GO_LOG="$replacement/go.log" \
	"$repo_dir/scripts/publish-signed-release.sh" --release v0.1.0-alpha.1 --dir "$replacement/documents" --keys-file "$replacement/release.pub" >/dev/null
if [ -e "$replacement/state/unsafe-live-catalog-upload" ]; then
	printf '%s\n' 'catalog assets were replaced while the release was live' >&2
	exit 1
fi
if [ "$(cat "$replacement/state/catalog-draft")" != false ] || ! cmp -s "$replacement/documents/punaro-catalog.json" "$replacement/state/remote/catalog/punaro-catalog.json" || ! cmp -s "$replacement/documents/punaro-catalog.sig" "$replacement/state/remote/catalog/punaro-catalog.sig"; then
	printf '%s\n' 'verified replacement catalog was not published as one hidden transition' >&2
	exit 1
fi
draft_line=$(grep -n 'release edit catalog --repo rock3r/punaro --draft=true --prerelease' "$replacement/gh.log" | head -n 1 | cut -d: -f1)
upload_line=$(grep -n 'release upload catalog .*punaro-catalog.json .*punaro-catalog.sig --repo rock3r/punaro --clobber' "$replacement/gh.log" | head -n 1 | cut -d: -f1)
publish_line=$(grep -n 'release edit catalog --repo rock3r/punaro --draft=false --prerelease' "$replacement/gh.log" | tail -n 1 | cut -d: -f1)
if [ -z "$draft_line" ] || [ -z "$upload_line" ] || [ -z "$publish_line" ] || [ "$draft_line" -ge "$upload_line" ] || [ "$upload_line" -ge "$publish_line" ]; then
	printf '%s\n' 'catalog replacement did not remain hidden from before upload through verification' >&2
	exit 1
fi

artifacts="$temporary/artifacts"
prepare_case "$artifacts"
printf '%s\n' tampered >"$artifacts/state/remote/v0.1.0-alpha.1/punaro-adapter-linux-amd64"
if PATH="$artifacts/bin:$PATH" \
	PUNARO_FAKE_GH_STATE="$artifacts/state" \
	PUNARO_FAKE_GH_LOG="$artifacts/gh.log" \
	PUNARO_FAKE_GO_LOG="$artifacts/go.log" \
	"$repo_dir/scripts/publish-signed-release.sh" --release v0.1.0-alpha.1 --dir "$artifacts/documents" --keys-file "$artifacts/release.pub" >/dev/null 2>&1; then
	printf '%s\n' 'tampered draft artifact unexpectedly published' >&2
	exit 1
fi
if grep -Eq '^release (upload|edit|create) ' "$artifacts/gh.log"; then
	printf '%s\n' 'publication mutated GitHub state after artifact verification failed' >&2
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

recovery="$temporary/recovery"
prepare_case "$recovery"
mkdir -p "$recovery/state/remote/catalog"
printf '%s\n' interrupted-candidate >"$recovery/state/remote/catalog/punaro-catalog.json"
printf '%s\n' interrupted-signature >"$recovery/state/remote/catalog/punaro-catalog.sig"
printf '%s\n' previous-catalog >"$recovery/state/remote/catalog/punaro-catalog.previous.json"
printf '%s\n' previous-signature >"$recovery/state/remote/catalog/punaro-catalog.previous.sig"
printf '%s\n' true >"$recovery/state/catalog-draft"
printf '%s\n' false >"$recovery/state/release-draft"
printf '%s\n' true >"$recovery/state/release-prerelease"
touch "$recovery/state/fail-previous-publication-check"
if PATH="$recovery/bin:$PATH" \
	PUNARO_FAKE_GH_STATE="$recovery/state" \
	PUNARO_FAKE_GH_LOG="$recovery/gh.log" \
	PUNARO_FAKE_GO_LOG="$recovery/go.log" \
	"$repo_dir/scripts/publish-signed-release.sh" --release v0.1.0-alpha.1 --dir "$recovery/documents" --keys-file "$recovery/release.pub" >/dev/null 2>&1; then
	printf '%s\n' 'interrupted replacement forgot the verified predecessor sequence' >&2
	exit 1
fi
if grep -Eq '^release (upload|edit|create|delete-asset) ' "$recovery/gh.log"; then
	printf '%s\n' 'interrupted replacement mutated GitHub before predecessor sequence validation' >&2
	exit 1
fi
rm "$recovery/state/fail-previous-publication-check"
PATH="$recovery/bin:$PATH" \
	PUNARO_FAKE_GH_STATE="$recovery/state" \
	PUNARO_FAKE_GH_LOG="$recovery/gh.log" \
	PUNARO_FAKE_GO_LOG="$recovery/go.log" \
	"$repo_dir/scripts/publish-signed-release.sh" --release v0.1.0-alpha.1 --dir "$recovery/documents" --keys-file "$recovery/release.pub" >/dev/null
if [ "$(cat "$recovery/state/catalog-draft")" != false ] || ! cmp -s "$recovery/documents/punaro-catalog.json" "$recovery/state/remote/catalog/punaro-catalog.json"; then
	printf '%s\n' 'interrupted replacement did not resume from its verified predecessor' >&2
	exit 1
fi
if [ "$(cat "$recovery/state/remote/catalog/punaro-catalog.previous.json")" != previous-catalog ] || [ "$(cat "$recovery/state/remote/catalog/punaro-catalog.previous.sig")" != previous-signature ]; then
	printf '%s\n' 'successful recovery discarded the durable predecessor pair' >&2
	exit 1
fi

printf '%s\n' 'publish_signed_release_tests_passed'
