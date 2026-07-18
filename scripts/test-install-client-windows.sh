#!/bin/sh
# Verify that the Windows client path remains a native, per-user deployment.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
installer="$repo_dir/scripts/install-client.ps1"
guidance_installer="$repo_dir/scripts/install-agent-guidance.ps1"
runner="$repo_dir/deploy/windows/Run-PunaroAdapter.ps1"
dpapi_command="$repo_dir/cmd/punaro-dpapi/main_windows.go"
dpapi_provider="$repo_dir/internal/attachment/v3/controller/keycredential_windows.go"

for path in "$installer" "$guidance_installer" "$runner" "$dpapi_command" "$dpapi_provider"; do
	[ -f "$path" ] || { printf '%s\n' "missing Windows client artifact: $path" >&2; exit 1; }
done

for expected in \
	'LogonType Interactive' \
	'ExecutionTimeLimit ([TimeSpan]::Zero)' \
	'SetAccessRuleProtection($true, $false)' \
	'PUNARO_ATTACHMENT_HOST_DPAPI_FILE' \
	'punaro-dpapi.exe' \
	'agent-mailbox' \
	'attachment setup is receiver-only' \
	'AgentGuidanceDir'; do
	grep -Fq "$expected" "$installer" || { printf '%s\n' "Windows installer is missing required safety behavior: $expected" >&2; exit 1; }
done

if grep -Eq '(^|[^A-Za-z])\.\s*\$config|Invoke-Expression|PUNARO_CF_ACCESS_CLIENT_SECRET=' "$installer" "$runner"; then
	printf '%s\n' 'Windows client scripts must not execute configuration or embed Access credentials' >&2
	exit 1
fi

printf '%s\n' install_client_windows_tests_passed
