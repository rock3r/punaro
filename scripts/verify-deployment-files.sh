#!/bin/sh
set -eu

unit=deploy/systemd/user/punaro-adapter.service
example=deploy/systemd/user/punaro-adapter.env.example
launch_agent=deploy/launchd/punaro-adapter.plist
adapter_installer=scripts/install-adapter.sh
client_installer=scripts/install-client.sh
adapter_installer_test=scripts/test-install-adapter.sh
server_installer=scripts/install-server.sh
server_installer_test=scripts/test-install-server.sh
attachment_relay_configurer=scripts/configure-attachment-v3-relay.sh
attachment_relay_configurer_test=scripts/test-configure-attachment-v3-relay.sh
agent_guidance_installer=scripts/install-agent-guidance.sh
agent_guidance_installer_test=scripts/test-install-agent-guidance.sh
windows_client_installer=scripts/install-client.ps1
windows_guidance_installer=scripts/install-agent-guidance.ps1
windows_client_installer_test=scripts/test-install-client-windows.sh
windows_adapter_runner=deploy/windows/Run-PunaroAdapter.ps1
windows_environment_importer=deploy/windows/Import-PunaroEnvironment.ps1
production_compose_verifier=scripts/verify-production-compose.sh
production_compose_test=scripts/test-production-compose.sh
production_compose_bootstrap_test=scripts/test-production-compose-bootstrap.sh
memory_onboarding_e2e_test=scripts/test-memory-onboarding-e2e.sh
release_artifact_builder=scripts/build-release-artifacts.sh
release_assemble_test=scripts/test-assemble-release.sh

for path in "$unit" "$example" "$launch_agent" "$adapter_installer" "$client_installer" "$adapter_installer_test" "$server_installer" "$server_installer_test" "$attachment_relay_configurer" "$attachment_relay_configurer_test" "$agent_guidance_installer" "$agent_guidance_installer_test" "$windows_client_installer" "$windows_guidance_installer" "$windows_client_installer_test" "$windows_adapter_runner" "$windows_environment_importer" "$production_compose_verifier" "$production_compose_test" "$production_compose_bootstrap_test" "$memory_onboarding_e2e_test" "$release_artifact_builder" "$release_assemble_test" scripts/production-compose deploy/compose/postgres-bootstrap.sh deploy/compose/postgres-entrypoint.sh docker-compose.memory-onboarding-e2e.yml .github/workflows/release.yml; do
	if [ ! -f "$path" ]; then
		printf '%s\n' "missing adapter deployment artifact: $path" >&2
		exit 1
	fi
done

for executable in "$adapter_installer" "$client_installer" "$adapter_installer_test" "$server_installer" "$server_installer_test" "$attachment_relay_configurer" "$attachment_relay_configurer_test" "$agent_guidance_installer" "$agent_guidance_installer_test" "$windows_client_installer_test" "$production_compose_verifier" "$production_compose_test" "$production_compose_bootstrap_test" "$memory_onboarding_e2e_test" "$release_artifact_builder" "$release_assemble_test" scripts/production-compose deploy/compose/postgres-bootstrap.sh deploy/compose/postgres-entrypoint.sh; do
	if [ ! -x "$executable" ]; then
		printf '%s\n' "deployment helper is not executable: $executable" >&2
		exit 1
	fi
done

for expected in \
	'<key>Label</key>' \
	'<string>org.punaro.adapter</string>' \
	'<key>KeepAlive</key>' \
	'<true/>' \
	'<key>ProcessType</key>' \
	'<string>Background</string>' \
	'<string>exec "$HOME/.local/bin/punaro-adapter"</string>'; do
	if ! grep -Fq "$expected" "$launch_agent"; then
		printf '%s\n' "adapter LaunchAgent is missing required setting: $expected" >&2
		exit 1
	fi
done

if grep -Eq 'PUNARO_CF_ACCESS_CLIENT_(ID|SECRET)=' "$launch_agent"; then
	printf '%s\n' 'adapter LaunchAgent must not contain Access credentials' >&2
	exit 1
fi

"$adapter_installer_test"
"$server_installer_test"
"$attachment_relay_configurer_test"
"$agent_guidance_installer_test"
"$windows_client_installer_test"
"$production_compose_test"
"$production_compose_verifier"
if command -v docker >/dev/null 2>&1; then
	docker compose -f docker-compose.memory-onboarding-e2e.yml config --quiet
else
	echo "memory onboarding Compose structure verified; Docker Compose validation requires Docker" >&2
fi

for expected in \
	'NoNewPrivileges=yes' \
	'ProtectSystem=strict' \
	'PrivateTmp=yes' \
	'PrivateDevices=yes' \
	'StandardInput=null' \
	'StandardOutput=journal' \
	'StandardError=journal' \
	'CapabilityBoundingSet=' \
	'UMask=0077'; do
	if ! grep -Fqx "$expected" "$unit"; then
		printf '%s\n' "adapter unit is missing required setting: $expected" >&2
		exit 1
	fi
done

if grep -Fqx 'EnvironmentFile=%h/.config/punaro/adapter.env' "$unit"; then
	printf '%s\n' 'adapter user unit must let punaro-adapter validate and load its own profile' >&2
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

if ! grep -Fq 'https://github.com/rock3r/punaro/releases/download' .github/workflows/release.yml; then
	printf '%s\n' 'release workflow must name the fixed GitHub Releases origin' >&2
	exit 1
fi
"$release_assemble_test"
