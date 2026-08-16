#!/bin/sh
# Sign Darwin release binaries, wrap them in a DMG, notarize, and staple.
# Loose Mach-O files cannot be stapled; the DMG is the staple target.
set -eu

usage() {
	cat <<'EOF'
Usage: scripts/sign-notarize-macos.sh --dist-dir DIR --dmg PATH

Sign every Darwin artifact in DIR, create a UDZO DMG at PATH, submit it to
notarytool with the Apple ID + app-specific password, and staple the ticket.
EOF
}

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

dist_dir=
dmg=

while [ "$#" -gt 0 ]; do
	case "$1" in
		--dist-dir) [ "$#" -ge 2 ] || fail '--dist-dir requires a value'; dist_dir=$2; shift 2 ;;
		--dmg) [ "$#" -ge 2 ] || fail '--dmg requires a value'; dmg=$2; shift 2 ;;
		--help) usage; exit 0 ;;
		*) fail "unknown option: $1" ;;
	esac
done

[ -n "$dist_dir" ] || fail '--dist-dir is required'
[ -n "$dmg" ] || fail '--dmg is required'
[ -d "$dist_dir" ] || fail 'dist directory does not exist'
[ "$(uname -s)" = Darwin ] || fail 'sign-notarize-macos requires macOS'

[ -n "${MACOS_CODESIGN_IDENTITY:-}" ] || fail 'MACOS_CODESIGN_IDENTITY is required'
[ -n "${MACOS_BUNDLE_ID:-}" ] || fail 'MACOS_BUNDLE_ID is required'
[ -n "${APPLE_ID:-}" ] || fail 'APPLE_ID is required'
[ -n "${APPLE_APP_SPECIFIC_PASSWORD:-}" ] || fail 'APPLE_APP_SPECIFIC_PASSWORD is required'
[ -n "${APPLE_TEAM_ID:-}" ] || fail 'APPLE_TEAM_ID is required'

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
entitlements="$script_dir/../deploy/macos/hardened-runtime.entitlements"
[ -f "$entitlements" ] || fail 'hardened-runtime entitlements are missing'

signed=0
for path in "$dist_dir"/punaro-*-darwin-*; do
	[ -f "$path" ] || continue
	name=$(basename -- "$path")
	case "$name" in
		*-darwin-amd64|*-darwin-arm64) ;;
		*) fail "unexpected Darwin artifact name: $name" ;;
	esac
	component=${name%-darwin-*}
	case "$component" in
		punaro-*) identifier="$MACOS_BUNDLE_ID.${component#punaro-}" ;;
		*) fail "unexpected Darwin artifact name: $name" ;;
	esac
	codesign --force --options runtime --timestamp \
		--entitlements "$entitlements" \
		--sign "$MACOS_CODESIGN_IDENTITY" \
		--identifier "$identifier" \
		"$path"
	codesign --verify --strict "$path"
	signed=$((signed + 1))
done
[ "$signed" -gt 0 ] || fail 'no Darwin artifacts found to sign'

stage=$(mktemp -d "${TMPDIR:-/tmp}/punaro-macos-dmg.XXXXXXXX")
cleanup() { rm -rf -- "$stage"; }
trap cleanup EXIT HUP INT TERM
mkdir -p "$stage/Punaro"
cp -p "$dist_dir"/punaro-*-darwin-* "$stage/Punaro/"

mkdir -p "$(dirname -- "$dmg")"
rm -f -- "$dmg"
hdiutil create -volname Punaro -srcfolder "$stage/Punaro" -ov -format UDZO "$dmg" >/dev/null
codesign --force --timestamp --sign "$MACOS_CODESIGN_IDENTITY" "$dmg"
codesign --verify --strict "$dmg"

xcrun notarytool submit "$dmg" \
	--apple-id "$APPLE_ID" \
	--password "$APPLE_APP_SPECIFIC_PASSWORD" \
	--team-id "$APPLE_TEAM_ID" \
	--wait

xcrun stapler staple "$dmg"
xcrun stapler validate "$dmg"
