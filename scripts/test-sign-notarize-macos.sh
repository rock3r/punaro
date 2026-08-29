#!/bin/sh
# Fail-closed checks for the macOS sign/notarize helper. Does not call Apple.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
script="$repo_dir/scripts/sign-notarize-macos.sh"
import_script="$repo_dir/scripts/import-macos-signing-cert.sh"
workflow="$repo_dir/.github/workflows/macos-notarize.yml"

[ -x "$script" ] || { printf '%s\n' 'sign-notarize-macos.sh is not executable' >&2; exit 1; }
[ -x "$import_script" ] || { printf '%s\n' 'import-macos-signing-cert.sh is not executable' >&2; exit 1; }
[ -f "$workflow" ] || { printf '%s\n' 'macOS notarization workflow missing' >&2; exit 1; }
[ -f "$repo_dir/deploy/macos/hardened-runtime.entitlements" ] || { printf '%s\n' 'hardened-runtime entitlements missing' >&2; exit 1; }

"$script" --help >/dev/null

if "$script" >/dev/null 2>&1; then
	printf '%s\n' 'sign-notarize-macos accepted missing arguments' >&2
	exit 1
fi

if "$script" --dist-dir /no-such-punaro-dist --dmg /tmp/punaro-test.dmg >/dev/null 2>&1; then
	printf '%s\n' 'sign-notarize-macos accepted a missing dist directory' >&2
	exit 1
fi

if MACOS_DEVELOPER_ID_APPLICATION_P12= MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD= MACOS_KEYCHAIN_PATH= MACOS_KEYCHAIN_PASSWORD= \
	"$import_script" >/dev/null 2>&1; then
	printf '%s\n' 'import-macos-signing-cert accepted empty credentials' >&2
	exit 1
fi

if grep -Fq 'base64 --decode' "$import_script"; then
	printf '%s\n' 'import-macos-signing-cert uses GNU base64 --decode' >&2
	exit 1
fi

for input in RELEASE SEQUENCE CATALOG_SEQUENCE IMAGE; do
	if ! grep -Fq "INPUT_$input:" "$workflow"; then
		printf '%s\n' "macOS notarization workflow does not pass $input through the environment" >&2
		exit 1
	fi
done
for argument in \
	'--release "$INPUT_RELEASE"' \
	'--sequence "$INPUT_SEQUENCE"' \
	'--catalog-sequence "$INPUT_CATALOG_SEQUENCE"' \
	'--image "$INPUT_IMAGE"'; do
	if ! grep -Fq -- "$argument" "$workflow"; then
		printf '%s\n' 'macOS notarization workflow does not quote environment-backed build inputs' >&2
		exit 1
	fi
done
if grep -Eq -- '--(release|sequence|catalog-sequence|image) "?\$\{\{ inputs\.' "$workflow" ||
	! grep -Fq 'punaro-release validate-request' "$workflow" ||
	! grep -Fq "'^ghcr\\.io/rock3r/punaro@sha256:[0-9a-f]{64}$'" "$workflow"; then
	printf '%s\n' 'macOS notarization workflow interpolates or fails to validate dispatcher input' >&2
	exit 1
fi
