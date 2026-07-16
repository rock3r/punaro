#!/bin/sh
set -eu

unit=deploy/systemd/user/punaro-adapter.service
example=deploy/systemd/user/punaro-adapter.env.example
launch_agent=deploy/launchd/punaro-adapter.plist
snapshot_publisher=scripts/publish-directory-snapshot.sh
snapshot_publisher_test=scripts/test-publish-directory-snapshot.sh

for path in "$unit" "$example" "$launch_agent" "$snapshot_publisher" "$snapshot_publisher_test"; do
	if [ ! -f "$path" ]; then
		printf '%s\n' "missing adapter deployment artifact: $path" >&2
		exit 1
	fi
done

for expected in \
	'<key>Label</key>' \
	'<string>org.punaro.adapter</string>' \
	'<key>KeepAlive</key>' \
	'<true/>' \
	'<string>set -a; . "$HOME/.config/punaro/adapter.env"; set +a; exec "$HOME/.local/bin/punaro-adapter"</string>'; do
	if ! grep -Fq "$expected" "$launch_agent"; then
		printf '%s\n' "adapter LaunchAgent is missing required setting: $expected" >&2
		exit 1
	fi
done

if grep -Eq 'PUNARO_CF_ACCESS_CLIENT_(ID|SECRET)=' "$launch_agent"; then
	printf '%s\n' 'adapter LaunchAgent must not contain Access credentials' >&2
	exit 1
fi

"$snapshot_publisher_test"

for expected in \
	'PUNARO_DIRECTORY_ROOT_PRIVATE_KEY' \
	'PUNARO_PVE_SSH_TARGET' \
	'PUNARO_PVE_CONTAINER_ID' \
	'PUNARO_PVE_SSH_IDENTITY_FILE' \
	'BatchMode=yes' \
	'.punaro-directory-publish.lockfile' \
	'directory_snapshot_publish_already_running' \
	'PUNARO_PUBLISH_LOCK_HELD' \
	'fcntl.flock' \
	'subprocess.run' \
	'close_fds=True' \
	'PUNARO_CONTAINER_SNAPSHOT_FILE must be canonical' \
	'PUNARO_CONTAINER_SNAPSHOT_FILE must not contain parent traversal' \
	'PUNARO_CONTAINER_SNAPSHOT_FILE must be directly below /var/lib/punaro/private' \
	'/root/.punaro-directory-stage' \
	'install -d -o root -g punaro -m 2750 /var/lib/punaro/private' \
	'chown root:punaro' \
	'[ ! -L' \
	'[ ! -L \"\$parent\" ]' \
	'stat -c %d' \
	'--ttl 30s' \
	'PUNARO_CONTAINER_SNAPSHOT_FILE must be below /var/lib/punaro/private' \
	'PUNARO_CONTAINER_SNAPSHOT_FILE contains unsafe characters' \
	'directory_snapshot_published'; do
	if ! grep -Fq -- "$expected" "$snapshot_publisher"; then
		printf '%s\n' "snapshot publisher is missing required safety setting: $expected" >&2
		exit 1
	fi
done

if grep -Fq 'PUNARO_DIRECTORY_ROOT_PRIVATE_KEY=' "$snapshot_publisher"; then
	printf '%s\n' 'snapshot publisher must not embed a root key value' >&2
	exit 1
fi

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
