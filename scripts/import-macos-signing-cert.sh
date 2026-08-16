#!/bin/sh
# Import the Developer ID Application identity into a throwaway keychain.
# Never prints certificate bytes or passwords.
#
# GitHub-hosted macOS rejects many modern PKCS#12 encodings as "Unknown format".
# Rebuild a 3DES/SHA1 bag that security(1) will accept, from either the stored
# p12 or the stored cer+key pair.
set -eu

fail() {
	printf '%s\n' "$1" >&2
	exit 2
}

[ -n "${MACOS_DEVELOPER_ID_APPLICATION_P12:-}" ] || fail 'MACOS_DEVELOPER_ID_APPLICATION_P12 is required'
[ -n "${MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD:-}" ] || fail 'MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD is required'
[ -n "${MACOS_KEYCHAIN_PATH:-}" ] || fail 'MACOS_KEYCHAIN_PATH is required'
[ -n "${MACOS_KEYCHAIN_PASSWORD:-}" ] || fail 'MACOS_KEYCHAIN_PASSWORD is required'

work=$(mktemp -d "${TMPDIR:-/tmp}/punaro-signing-import.XXXXXXXX")
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

decode_b64() {
	python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.standard_b64decode(sys.stdin.read()))'
}

printf '%s' "$MACOS_DEVELOPER_ID_APPLICATION_P12" | decode_b64 >"$work/source.p12"
[ -s "$work/source.p12" ] || fail 'Developer ID PKCS#12 decoded to an empty file'
file -b "$work/source.p12" >/dev/null

export MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD
export MACOS_KEYCHAIN_PASSWORD

# Prefer rebuilding from cer+key when present: that avoids an unreadable p12 bag.
if [ -n "${MACOS_DEVELOPER_ID_APPLICATION_CER:-}" ] && [ -n "${MACOS_DEVELOPER_ID_APPLICATION_KEY:-}" ]; then
	printf '%s' "$MACOS_DEVELOPER_ID_APPLICATION_CER" | decode_b64 >"$work/cert.bin"
	printf '%s' "$MACOS_DEVELOPER_ID_APPLICATION_KEY" | decode_b64 >"$work/key.bin"
	if grep -q -- '-----BEGIN' "$work/cert.bin"; then
		cp "$work/cert.bin" "$work/cert.pem"
	else
		openssl x509 -inform DER -in "$work/cert.bin" -out "$work/cert.pem"
	fi
	if grep -q -- '-----BEGIN' "$work/key.bin"; then
		cp "$work/key.bin" "$work/key.pem"
	else
		openssl pkcs8 -inform DER -in "$work/key.bin" -nocrypt -out "$work/key.pem" 2>/dev/null ||
			openssl rsa -inform DER -in "$work/key.bin" -out "$work/key.pem"
	fi
	openssl pkcs12 -export \
		-inkey "$work/key.pem" \
		-in "$work/cert.pem" \
		-out "$work/import.p12" \
		-passout env:MACOS_KEYCHAIN_PASSWORD \
		-keypbe PBE-SHA1-3DES \
		-certpbe PBE-SHA1-3DES
	import_pass=$MACOS_KEYCHAIN_PASSWORD
else
	# Convert the stored p12 into a bag security(1) accepts.
	if ! openssl pkcs12 -in "$work/source.p12" -passin env:MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD -nodes -out "$work/bundle.pem" 2>"$work/openssl.err"; then
		fail 'could not read the stored Developer ID PKCS#12'
	fi
	openssl pkcs12 -export \
		-in "$work/bundle.pem" \
		-out "$work/import.p12" \
		-passout env:MACOS_KEYCHAIN_PASSWORD \
		-keypbe PBE-SHA1-3DES \
		-certpbe PBE-SHA1-3DES
	import_pass=$MACOS_KEYCHAIN_PASSWORD
fi

security create-keychain -p "$MACOS_KEYCHAIN_PASSWORD" "$MACOS_KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$MACOS_KEYCHAIN_PATH"
security unlock-keychain -p "$MACOS_KEYCHAIN_PASSWORD" "$MACOS_KEYCHAIN_PATH"
security import "$work/import.p12" -k "$MACOS_KEYCHAIN_PATH" -P "$import_pass" -T /usr/bin/codesign -T /usr/bin/security
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$MACOS_KEYCHAIN_PASSWORD" "$MACOS_KEYCHAIN_PATH" >/dev/null

# Developer ID Application G2 intermediate, required for a valid identity chain.
curl -fsS https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer -o "$work/DeveloperIDG2CA.cer"
security import "$work/DeveloperIDG2CA.cer" -k "$MACOS_KEYCHAIN_PATH" -T /usr/bin/codesign >/dev/null || true

user_keychains=$(security list-keychains -d user | tr -d '"')
# shellcheck disable=SC2086
security list-keychains -d user -s "$MACOS_KEYCHAIN_PATH" $user_keychains

if ! security find-identity -v -p codesigning "$MACOS_KEYCHAIN_PATH" | grep -Fq 'Developer ID Application:'; then
	fail 'imported keychain has no Developer ID Application identity'
fi
