#!/bin/sh
# Import the Developer ID Application PKCS#12 into a throwaway keychain.
# Never prints certificate bytes or passwords.
set -eu

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

[ -n "${MACOS_DEVELOPER_ID_APPLICATION_P12:-}" ] || fail 'MACOS_DEVELOPER_ID_APPLICATION_P12 is required'
[ -n "${MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD:-}" ] || fail 'MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD is required'
[ -n "${MACOS_KEYCHAIN_PATH:-}" ] || fail 'MACOS_KEYCHAIN_PATH is required'
[ -n "${MACOS_KEYCHAIN_PASSWORD:-}" ] || fail 'MACOS_KEYCHAIN_PASSWORD is required'

p12=$(mktemp)
cleanup() { rm -f -- "$p12"; }
trap cleanup EXIT HUP INT TERM

printf '%s' "$MACOS_DEVELOPER_ID_APPLICATION_P12" | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.standard_b64decode(sys.stdin.read()))' >"$p12"
[ -s "$p12" ] || fail 'Developer ID PKCS#12 decoded to an empty file'

security create-keychain -p "$MACOS_KEYCHAIN_PASSWORD" "$MACOS_KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$MACOS_KEYCHAIN_PATH"
security unlock-keychain -p "$MACOS_KEYCHAIN_PASSWORD" "$MACOS_KEYCHAIN_PATH"
security import "$p12" -k "$MACOS_KEYCHAIN_PATH" -P "$MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$MACOS_KEYCHAIN_PASSWORD" "$MACOS_KEYCHAIN_PATH" >/dev/null
security list-keychains -d user -s "$MACOS_KEYCHAIN_PATH" $(security list-keychains -d user | sed 's/"//g')

if ! security find-identity -v -p codesigning "$MACOS_KEYCHAIN_PATH" | grep -Fq 'Developer ID Application:'; then
	fail 'imported keychain has no Developer ID Application identity'
fi
