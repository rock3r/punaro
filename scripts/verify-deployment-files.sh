#!/bin/sh
set -eu

unit=deploy/systemd/user/punaro-adapter.service
example=deploy/systemd/user/punaro-adapter.env.example

for path in "$unit" "$example"; do
	if [ ! -f "$path" ]; then
		printf '%s\n' "missing adapter deployment artifact: $path" >&2
		exit 1
	fi
done

for expected in \
	'NoNewPrivileges=yes' \
	'ProtectSystem=strict' \
	'PrivateTmp=yes' \
	'PrivateDevices=yes' \
	'CapabilityBoundingSet=' \
	'UMask=0077'; do
	if ! grep -Fqx "$expected" "$unit"; then
		printf '%s\n' "adapter unit is missing required setting: $expected" >&2
		exit 1
	fi
done

if ! grep -Fqx 'EnvironmentFile=%h/.config/punaro/adapter.env' "$unit"; then
	printf '%s\n' 'adapter user unit must read the owner-only adapter environment file' >&2
	exit 1
fi

if ! grep -Fqx 'ExecStart=%h/.local/bin/punaro-adapter' "$unit"; then
	printf '%s\n' 'adapter user unit must exec the owner-reviewed adapter binary' >&2
	exit 1
fi

if ! grep -Fqx 'ProtectHome=read-only' "$unit"; then
	printf '%s\n' 'adapter user unit must make the home directory read-only by default' >&2
	exit 1
fi

if ! grep -Fqx 'ReadWritePaths=%h/.local/state/punaro-adapter %h/.local/state/ai-agent/mailbox' "$unit"; then
	printf '%s\n' 'adapter user unit must limit writable state to its journals and mailbox store' >&2
	exit 1
fi

if grep -Eq 'PUNARO_CF_ACCESS_CLIENT_(ID|SECRET)=' "$example"; then
	printf '%s\n' 'adapter environment example must not contain Access credentials' >&2
	exit 1
fi
