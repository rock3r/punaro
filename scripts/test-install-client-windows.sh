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
	'RestartCount = 255' \
	'RepetitionInterval' \
	'RepetitionDuration' \
	'Do not attach it until -Enable' \
	'-WindowStyle Hidden' \
	'-Hidden' \
	'SetAccessRuleProtection($true, $false)' \
	'punaro-trusted-attachment.exe' \
	'punaro-bootstrap.exe' \
	'punaro-enroll.exe' \
	'retired attachment artifact exists at' \
	'agent-mailbox' \
	'AgentGuidanceDir' \
	'AllowLanHttp' \
	'PUNARO_ADAPTER_TRUSTED_LAN_CIDR' \
	'Push-Location -LiteralPath $repoDir' \
	'seed-checkout' \
	'KeysFile' \
	'--keys-file' \
	'Stop-ScheduledTask' \
	'Get-ScheduledTask' \
	'could not stop the running Punaro Adapter task' \
	'Wait-PunaroReplaceableBinary' \
	'Stop-PunaroOrphanAdapter' \
	'run.pid is invalid' \
	'PathType Leaf' \
	'starting marker' \
	'could not enumerate processes to recover run.pid' \
	'run.pid image is unverifiable' \
	'could not stop a matching Punaro adapter' \
	'run.pid' \
	'FileShare]::None' \
	'adapterTaskRestored'; do
	grep -Fq -- "$expected" "$installer" || { printf '%s\n' "Windows installer is missing required safety behavior: $expected" >&2; exit 1; }
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
if grep -Eq 'attempt -lt 3|RestartCount = 3|RestartCount = 999' "$installer" "$runner"; then
	printf '%s\n' 'Windows adapter supervision must not exhaust a 3-attempt restart budget' >&2
	exit 1
fi

printf '%s\n' install_client_windows_tests_passed
