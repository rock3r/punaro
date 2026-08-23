#!/bin/sh
# Publish an already-built draft only after its exact manifest and catalog have
# been verified with the offline release public key. This script never reads a
# private signing key.
set -eu

usage() {
	cat <<'EOF'
Usage: scripts/publish-signed-release.sh --release RELEASE --dir DIR --keys-file FILE [--repo OWNER/REPO]

DIR must contain punaro-release.json, punaro-release.sig,
punaro-catalog.json, and punaro-catalog.sig signed offline. The matching draft
GitHub Release must already exist.
EOF
}

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

release=
document_dir=
keys_file=
repository=rock3r/punaro
while [ "$#" -gt 0 ]; do
	case "$1" in
		--release) [ "$#" -ge 2 ] || fail '--release requires a value'; release=$2; shift 2 ;;
		--dir) [ "$#" -ge 2 ] || fail '--dir requires a value'; document_dir=$2; shift 2 ;;
		--keys-file) [ "$#" -ge 2 ] || fail '--keys-file requires a value'; keys_file=$2; shift 2 ;;
		--repo) [ "$#" -ge 2 ] || fail '--repo requires a value'; repository=$2; shift 2 ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

[ -n "$release" ] && [ -n "$document_dir" ] && [ -n "$keys_file" ] || fail 'release, dir, and keys file are required'
case "$release" in v[0-9]*.[0-9]*.[0-9]*) ;; *) fail 'release name is invalid' ;; esac
case "$repository" in */*) ;; *) fail 'repository must be OWNER/REPO' ;; esac
[ -d "$document_dir" ] && [ ! -L "$document_dir" ] || fail 'document directory is invalid'
[ -f "$keys_file" ] && [ ! -L "$keys_file" ] || fail 'public keys file is invalid'
document_dir=$(CDPATH= cd -- "$document_dir" && pwd -P) || fail 'document directory is invalid'
keys_parent=$(CDPATH= cd -- "$(dirname -- "$keys_file")" && pwd -P) || fail 'public keys file is invalid'
keys_file="$keys_parent/$(basename -- "$keys_file")"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
manifest="$document_dir/punaro-release.json"
manifest_signature="$document_dir/punaro-release.sig"
catalog="$document_dir/punaro-catalog.json"
catalog_signature="$document_dir/punaro-catalog.sig"
for file in "$manifest" "$manifest_signature" "$catalog" "$catalog_signature"; do
	[ -f "$file" ] && [ ! -L "$file" ] || fail 'signed release document set is incomplete'
done

(
	cd "$repo_dir"
	go run ./cmd/punaro-release validate --dir "$document_dir" --release "$release"
	go run ./cmd/punaro-release verify --keys-file "$keys_file" --document "$manifest" --signature "$manifest_signature"
	go run ./cmd/punaro-release verify --keys-file "$keys_file" --document "$catalog" --signature "$catalog_signature"
) || fail 'signed release documents are invalid'

command -v gh >/dev/null 2>&1 || fail 'gh is required'
command -v jq >/dev/null 2>&1 || fail 'jq is required'
draft_state=$(gh release view "$release" --repo "$repository" --json tagName,isDraft)
[ "$(printf '%s\n' "$draft_state" | jq -er .tagName)" = "$release" ] || fail 'draft release identity is invalid'
[ "$(printf '%s\n' "$draft_state" | jq -er .isDraft)" = true ] || fail 'release is not a draft'

download_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-release-publish.XXXXXXXX")
catalog_restore_required=false
previous_catalog=
previous_catalog_signature=
restore_previous_catalog() {
	attempt=1
	while [ "$attempt" -le 3 ]; do
		if gh release upload catalog "$previous_catalog_signature" "$previous_catalog" --repo "$repository" --clobber; then
			return 0
		fi
		attempt=$((attempt + 1))
	done
	return 1
}
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$catalog_restore_required" = true ]; then
		if ! restore_previous_catalog; then
			printf '%s\n' 'failed to restore the previously verified live catalog' >&2
		fi
		status=2
	fi
	rm -rf -- "$download_dir"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
gh release download "$release" --repo "$repository" --pattern punaro-release.json --pattern punaro-catalog.json --dir "$download_dir"
cmp -s "$manifest" "$download_dir/punaro-release.json" || fail 'draft manifest differs from signed bytes'
cmp -s "$catalog" "$download_dir/punaro-catalog.json" || fail 'draft catalog differs from signed bytes'

catalog_exists=false
catalog_draft=false
if catalog_state=$(gh release view catalog --repo "$repository" --json isDraft 2>/dev/null); then
	catalog_exists=true
	catalog_draft=$(printf '%s\n' "$catalog_state" | jq -er 'if .isDraft == true then "true" elif .isDraft == false then "false" else error("invalid draft state") end')
	if [ "$catalog_draft" = false ]; then
		previous_catalog_dir="$download_dir/previous-catalog"
		mkdir "$previous_catalog_dir"
		gh release download catalog --repo "$repository" --pattern punaro-catalog.json --pattern punaro-catalog.sig --dir "$previous_catalog_dir"
		previous_catalog="$previous_catalog_dir/punaro-catalog.json"
		previous_catalog_signature="$previous_catalog_dir/punaro-catalog.sig"
		(
			cd "$repo_dir"
			go run ./cmd/punaro-release verify --keys-file "$keys_file" --document "$previous_catalog" --signature "$previous_catalog_signature"
		) || fail 'existing live catalog is not a restorable verified pair'
	fi
fi

# Make the immutable release usable first. The live catalog is changed only
# after those versioned bytes and their signature are publicly available.
gh release upload "$release" "$manifest_signature" "$catalog_signature" --repo "$repository" --clobber
gh release edit "$release" --repo "$repository" --draft=false --prerelease

if [ "$catalog_exists" = true ] && [ "$catalog_draft" = false ]; then
	# GitHub replaces each asset separately. Keep the previously verified pair
	# locally and restore it on every partial upload or verification failure.
	catalog_restore_required=true
	gh release upload catalog "$catalog_signature" --repo "$repository" --clobber
	gh release upload catalog "$catalog" --repo "$repository" --clobber
elif [ "$catalog_exists" = true ]; then
	# A prior interrupted first publication remains invisible as a draft. Finish
	# both assets before exposing it.
	gh release upload catalog "$catalog" "$catalog_signature" --repo "$repository" --clobber
	gh release edit catalog --repo "$repository" --draft=false --prerelease
else
	# Initial publication is assembled as a draft so a partial asset upload is
	# never visible to bootstrap clients.
	gh release create catalog --repo "$repository" --draft \
		--title 'Punaro release catalog' \
		--notes 'Signed short-lived Punaro release catalog. Bootstrap verifies the detached signature.' \
		"$catalog" "$catalog_signature"
	gh release edit catalog --repo "$repository" --draft=false --prerelease
fi

verification_dir="$download_dir/verification"
mkdir "$verification_dir"
gh release download "$release" --repo "$repository" --pattern punaro-release.json --pattern punaro-release.sig --dir "$verification_dir"
gh release download catalog --repo "$repository" --pattern punaro-catalog.json --pattern punaro-catalog.sig --dir "$verification_dir"
cmp -s "$manifest" "$verification_dir/punaro-release.json" || fail 'published manifest verification failed'
cmp -s "$manifest_signature" "$verification_dir/punaro-release.sig" || fail 'published manifest signature verification failed'
cmp -s "$catalog" "$verification_dir/punaro-catalog.json" || fail 'published catalog verification failed'
cmp -s "$catalog_signature" "$verification_dir/punaro-catalog.sig" || fail 'published catalog signature verification failed'
(
	cd "$repo_dir"
	go run ./cmd/punaro-release verify --keys-file "$keys_file" --document "$verification_dir/punaro-release.json" --signature "$verification_dir/punaro-release.sig"
	go run ./cmd/punaro-release verify --keys-file "$keys_file" --document "$verification_dir/punaro-catalog.json" --signature "$verification_dir/punaro-catalog.sig"
) || fail 'published signature verification failed'

catalog_restore_required=false

printf '%s\n' "published signed prerelease $release and catalog sequence from verified bytes"
