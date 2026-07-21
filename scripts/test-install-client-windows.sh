#!/bin/sh
# Verify that the Windows client path remains a native, per-user deployment.
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
installer="$repo_dir/scripts/install-client.ps1"
guidance_installer="$repo_dir/scripts/install-agent-guidance.ps1"
runner="$repo_dir/deploy/windows/Run-PunaroAdapter.ps1"
trusted_command="$repo_dir/cmd/punaro-trusted-attachment/main.go"

for path in "$installer" "$guidance_installer" "$runner" "$trusted_command"; do
	[ -f "$path" ] || { printf '%s\n' "missing Windows client artifact: $path" >&2; exit 1; }
done

for expected in \
	'LogonType Interactive' \
	'ExecutionTimeLimit ([TimeSpan]::Zero)' \
	'SetAccessRuleProtection($true, $false)' \
	'punaro-trusted-attachment.exe' \
	'retired attachment artifact exists at' \
	'agent-mailbox' \
	'AgentGuidanceDir'; do
	grep -Fq "$expected" "$installer" || { printf '%s\n' "Windows installer is missing required safety behavior: $expected" >&2; exit 1; }
done

for retired_package in 'cmd\punaro-dpapi' 'cmd\punaro-directory' 'cmd\punaro-attachment' 'cmd\punaro-keychain'; do
	if grep -F "Build-PunaroBinary" "$installer" | grep -Fq "$retired_package"; then
		printf '%s\n' "Windows installer still builds retired attachment package: $retired_package" >&2
		exit 1
	fi
done
grep -Fq "foreach (\$name in @('Run-PunaroAdapter.ps1', 'Import-PunaroEnvironment.ps1'))" "$installer" || {
	printf '%s\n' 'Windows installer copies an unexpected runner set' >&2
	exit 1
}

if grep -Eq '(^|[^A-Za-z])\.\s*\$config|Invoke-Expression|PUNARO_CF_ACCESS_CLIENT_SECRET=' "$installer" "$runner"; then
	printf '%s\n' 'Windows client scripts must not execute configuration or embed Access credentials' >&2
	exit 1
fi

printf '%s\n' install_client_windows_tests_passed
