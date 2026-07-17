#!/bin/sh
# Exercise v3 authority/client provisioning without enabling a relay or
# exposing private material.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/punaro-attachment-provision-test.XXXXXXXX")
cleanup() { chmod -R u+w -- "$fixture_dir" 2>/dev/null || true; rm -rf -- "$fixture_dir"; }
trap cleanup EXIT HUP INT TERM

authority="$fixture_dir/authority"
client="$fixture_dir/client"

file_mode() {
	if stat -f %Lp "$1" >/dev/null 2>&1; then stat -f %Lp "$1"; else stat -c %a "$1"; fi
}

sh "$repo_dir/scripts/provision-attachment-v3.sh" authority --directory "$authority" >"$fixture_dir/authority.out"
[ "$(file_mode "$authority")" = 700 ] || { printf '%s\n' 'authority directory is not private' >&2; exit 1; }
for key in root.private issuer.private; do
	[ -f "$authority/$key" ] || { printf '%s\n' "missing authority key: $key" >&2; exit 1; }
	[ "$(file_mode "$authority/$key")" = 600 ] || { printf '%s\n' "authority key is not private: $key" >&2; exit 1; }
done
[ -f "$authority/public.json" ] || { printf '%s\n' 'missing public authority record' >&2; exit 1; }
[ -f "$authority/directory-manifest.json" ] || { printf '%s\n' 'missing initial directory manifest' >&2; exit 1; }
if grep -Fq -- "$(cat "$authority/root.private")" "$authority/public.json" "$authority/directory-manifest.json"; then
	printf '%s\n' 'authority output leaked the root private key' >&2; exit 1
fi
grep -Fq '"issuer"' "$authority/directory-manifest.json"

case "$(uname -s)" in
	Darwin)
		sh "$repo_dir/scripts/provision-attachment-v3.sh" client \
			--directory "$client" --authority-public "$authority/public.json" --machine-id macbook \
			--role both --host-key-service punaro.test --host-key-account macbook >"$fixture_dir/client.out"
		grep -Fqx 'PUNARO_ATTACHMENT_HOST_KEY_SERVICE=punaro.test' "$client/attachment-v3.env"
		grep -Fqx 'PUNARO_ATTACHMENT_HOST_KEY_ACCOUNT=macbook' "$client/attachment-v3.env"
		;;
	*)
		sh "$repo_dir/scripts/provision-attachment-v3.sh" client \
			--directory "$client" --authority-public "$authority/public.json" --machine-id macbook \
			--role both --host-credential-directory /run/credentials/punaro --host-credential-name sender-key >"$fixture_dir/client.out"
		grep -Fqx 'PUNARO_ATTACHMENT_HOST_CREDENTIAL_DIRECTORY=/run/credentials/punaro' "$client/attachment-v3.env"
		grep -Fqx 'PUNARO_ATTACHMENT_HOST_CREDENTIAL_NAME=sender-key' "$client/attachment-v3.env"
		;;
esac
for key in device-signing.private device-hpke.private; do
	[ -f "$client/$key" ] || { printf '%s\n' "missing client key: $key" >&2; exit 1; }
	[ "$(file_mode "$client/$key")" = 600 ] || { printf '%s\n' "client key is not private: $key" >&2; exit 1; }
done
[ -f "$client/attachment-v3.env" ] || { printf '%s\n' 'missing attachment environment' >&2; exit 1; }
[ -f "$client/device-enrollment.json" ] || { printf '%s\n' 'missing public device enrollment' >&2; exit 1; }
[ "$(file_mode "$client/attachment-v3.env")" = 600 ] || { printf '%s\n' 'attachment environment is not private' >&2; exit 1; }
grep -Fq '"attachment_device_id"' "$client/device-enrollment.json"
if grep -Fq -- "$(cat "$client/device-signing.private")" "$client/device-enrollment.json"; then
	printf '%s\n' 'client enrollment leaked the signing private key' >&2; exit 1
fi

sh "$repo_dir/scripts/provision-attachment-v3.sh" authority-add-device \
	--directory "$authority" --device-enrollment "$client/device-enrollment.json" >"$fixture_dir/add-device.out"
grep -Fq '"device"' "$authority/directory-manifest.json"
grep -Fq '"sequence":2' "$authority/directory-manifest.json"

fake_bin="$fixture_dir/fake-bin"
mkdir "$fake_bin"
printf '%s\n' '#!/bin/sh' 'printf "%s\\n" Linux' >"$fake_bin/uname"
chmod 700 "$fake_bin/uname"
linux_client="$fixture_dir/linux-client"
PATH="$fake_bin:$PATH" sh "$repo_dir/scripts/provision-attachment-v3.sh" client \
	--directory "$linux_client" --authority-public "$authority/public.json" --machine-id linuxbox \
	--role sender --host-credential-directory /run/credentials/punaro --host-credential-name sender-key >"$fixture_dir/linux-client.out"
grep -Fqx 'PUNARO_ATTACHMENT_HOST_CREDENTIAL_DIRECTORY=/run/credentials/punaro' "$linux_client/attachment-v3.env"
grep -Fqx 'PUNARO_ATTACHMENT_HOST_CREDENTIAL_NAME=sender-key' "$linux_client/attachment-v3.env"

set +e
sh "$repo_dir/scripts/provision-attachment-v3.sh" client --directory "$fixture_dir/insecure" \
	--authority-public "$authority/public.json" --machine-id macbook --role sender >"$fixture_dir/sender-without-host-key.out" 2>&1
status=$?
set -e
[ "$status" -eq 2 ] || { printf '%s\n' 'sender provisioning accepted a missing host key reference' >&2; exit 1; }
case "$(uname -s)" in
	Darwin) grep -Fqx 'sender provisioning requires --host-key-service and --host-key-account' "$fixture_dir/sender-without-host-key.out" ;;
	*) grep -Fqx 'sender provisioning requires --host-credential-directory and --host-credential-name' "$fixture_dir/sender-without-host-key.out" ;;
esac

printf '%s\n' attachment_v3_provisioning_tests_passed
