Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoDir = Split-Path -Parent $PSScriptRoot
$paths = @(
    (Join-Path $repoDir 'scripts\install-client.ps1'),
    (Join-Path $repoDir 'scripts\install-agent-guidance.ps1'),
    (Join-Path $repoDir 'deploy\windows\Run-PunaroAdapter.ps1'),
    (Join-Path $repoDir 'deploy\windows\Import-PunaroEnvironment.ps1')
)
foreach ($path in $paths) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
    if ($null -ne $errors -and $errors.Count -ne 0) { throw "PowerShell parse failure in ${path}: $($errors[0].Message)" }
}

$installer = [System.IO.File]::ReadAllText((Join-Path $repoDir 'scripts\install-client.ps1'))
foreach ($expected in @('LogonType Interactive', 'ExecutionTimeLimit ([TimeSpan]::Zero)', 'RestartCount', 'RepetitionInterval', 'RepetitionDuration', '-WindowStyle Hidden', '-Hidden', 'SetAccessRuleProtection($true, $false)', '-ExecutionPolicy Bypass', 'ForEach-Object { $_.address }', 'punaro-trusted-attachment.exe', 'punaro-memory.exe', 'punaro-enroll.exe', 'agent-mailbox', 'AgentGuidanceDir', 'AllowLanHttp', 'PUNARO_ADAPTER_TRUSTED_LAN_CIDR')) {
    if (-not $installer.Contains($expected)) { throw "Windows installer is missing required behavior: $expected" }
}
$allScripts = ($paths | ForEach-Object { [System.IO.File]::ReadAllText($_) }) -join "`n"
if (-not $allScripts.Contains('existing Punaro guidance predates trusted attachments')) {
    throw 'Windows guidance installer does not fail closed on retired guidance'
}
if (-not $allScripts.Contains('existing Punaro guidance predates user-telegram send')) {
    throw 'Windows guidance installer does not fail closed on pre-user-telegram send guidance'
}
if (-not $allScripts.Contains('existing Punaro guidance predates telegram-origin-only send')) {
    throw 'Windows guidance installer does not fail closed on claimed-topic user-telegram send guidance'
}
if (-not $allScripts.Contains('--to user-telegram')) {
    throw 'Windows guidance installer does not teach --to user-telegram'
}
if ($allScripts -match 'Invoke-Expression|PUNARO_CF_ACCESS_CLIENT_SECRET=|\.\s*\$config') {
    throw 'Windows client scripts must not execute configuration or embed Access credentials'
}

$originalLocalAppData = $env:LOCALAPPDATA
# Keep the fixture under the real per-user LOCALAPPDATA so seed ancestor walks succeed.
$fixture = Join-Path $originalLocalAppData ("punaro-windows-install-test-" + [Guid]::NewGuid())
try {
    [System.IO.Directory]::CreateDirectory($fixture) | Out-Null
    $env:LOCALAPPDATA = Join-Path $fixture 'localappdata'
    $mailbox = Join-Path $fixture 'agent-mailbox.cmd'
    [System.IO.File]::WriteAllText($mailbox, "@echo off`r`nexit /b 0`r`n", [System.Text.Encoding]::ASCII)
    $project = Join-Path $fixture 'project'
    [System.IO.Directory]::CreateDirectory($project) | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $project 'CLAUDE.md'), '# Existing guidance', [System.Text.Encoding]::UTF8)

    $global:punaroRegisteredTask = $null
    $global:punaroRegisteredSettings = $null
    $global:punaroRegisteredAction = $null
    $global:punaroRegisteredTriggers = $null
    $global:punaroExistingTask = $null
    $global:punaroDisableTaskCalled = $false
    $global:punaroStartTaskCalled = $false
    function Get-ScheduledTask { param([string]$TaskName) return $global:punaroExistingTask }
    function Disable-ScheduledTask { param([string]$TaskName) $global:punaroDisableTaskCalled = $true }
    function Start-ScheduledTask { param([string]$TaskName) $global:punaroStartTaskCalled = $true }
    function Stop-ScheduledTask { param([string]$TaskName) }
    function New-ScheduledTaskAction { param([string]$Execute, [string]$Argument) return [pscustomobject]@{ Execute = $Execute; Argument = $Argument } }
    function New-ScheduledTaskTrigger {
        param(
            [switch]$AtLogOn,
            [string]$User,
            [switch]$Once,
            [datetime]$At,
            [TimeSpan]$RepetitionInterval,
            [TimeSpan]$RepetitionDuration
        )
        return [pscustomobject]@{
            User = $User
            AtLogOn = [bool]$AtLogOn
            Once = [bool]$Once
            Repetition = [pscustomobject]@{
                Interval = if ($null -eq $RepetitionInterval) { $null } else { $RepetitionInterval.ToString() }
                Duration = if ($null -eq $RepetitionDuration) { $null } else { $RepetitionDuration.ToString() }
                StopAtDurationEnd = $true
            }
        }
    }
    function New-ScheduledTaskPrincipal { param([string]$UserId, [string]$LogonType, [string]$RunLevel) return [pscustomobject]@{ UserId = $UserId } }
    function New-ScheduledTaskSettingsSet { param([switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [switch]$Hidden, [TimeSpan]$ExecutionTimeLimit) return [pscustomobject]@{ ExecutionTimeLimit = $ExecutionTimeLimit; Hidden = $Hidden; RestartCount = 0; RestartInterval = [TimeSpan]::Zero } }
    function Register-ScheduledTask {
        param([string]$TaskName, $Action, $Trigger, $Principal, $Settings, [string]$Description, [switch]$Force)
        $global:punaroRegisteredTask = $TaskName
        $global:punaroRegisteredSettings = $Settings
        $global:punaroRegisteredAction = $Action
        $global:punaroRegisteredTriggers = @($Trigger)
        return [pscustomobject]@{}
    }

    $invalidLocalAppData = Join-Path $fixture 'invalid-localappdata'
    $env:LOCALAPPDATA = $invalidLocalAppData
    $invalidPolicyBlocked = $false
    try {
        & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'http://192.168.2.4:8080' -MachineId 'invalid-lan-client' -AgentMailboxBin $mailbox -AllowLanHttp -TrustedLanCidr '192.168.1.0/24'
    } catch {
        if ($_.Exception.Message.Contains('relay transport policy is invalid')) { $invalidPolicyBlocked = $true } else { throw }
    }
    if (-not $invalidPolicyBlocked) { throw 'Windows client installer accepted an invalid complete trusted-LAN policy' }
    if (Test-Path -LiteralPath (Join-Path $invalidLocalAppData 'Punaro')) { throw 'invalid trusted-LAN policy created Windows installation artifacts' }
    $env:LOCALAPPDATA = Join-Path $fixture 'localappdata'

    Push-Location -LiteralPath $fixture
    try {
        & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'https://relay.example.test' -MachineId 'windows-test' -AgentMailboxBin $mailbox -AgentGuidanceDir $project
    } finally {
        Pop-Location
    }
    if ($LASTEXITCODE -ne 0) { throw 'Windows client installer failed' }
    $root = Join-Path $env:LOCALAPPDATA 'Punaro'
    foreach ($path in @((Join-Path $root 'config\machine.key'), (Join-Path $root 'config\enrollment.json'), (Join-Path $root 'config\adapter.env'), (Join-Path $root 'bin\punaro-trusted-attachment.exe'), (Join-Path $root 'bin\punaro-memory.exe'), (Join-Path $root 'bin\punaro-enroll.exe'), (Join-Path $project '.agents\skills\punaro-mailbox\SKILL.md'))) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Windows client installer did not create $path" }
    }
    & (Join-Path $repoDir 'scripts\punaro-plugin-mcp.cmd')
    if ($LASTEXITCODE -ne 0) { throw 'Windows plugin launcher could not start the installer-owned adapter' }
    foreach ($path in @((Join-Path $root 'bin\punaro-attachment.exe'), (Join-Path $root 'bin\punaro-directory.exe'), (Join-Path $root 'bin\punaro-dpapi.exe'), (Join-Path $root 'Run-PunaroAttachment.ps1'))) {
        if (Test-Path -LiteralPath $path) { throw "Windows client installer must not create retired attachment artifact $path" }
    }
    if ($global:punaroRegisteredTask -ne 'Punaro Adapter') { throw 'Windows client installer did not register the expected per-user task' }
    if (@($global:punaroRegisteredTriggers | Where-Object { $_.Once }).Count -ne 0 -or $global:punaroStartTaskCalled) {
        throw 'Windows client installer armed or started a fresh adapter without -Enable'
    }
    $global:punaroRegisteredTriggers = $null
    $global:punaroStartTaskCalled = $false
    & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'https://relay.example.test' -MachineId 'windows-test' -AgentMailboxBin $mailbox -AgentGuidanceDir $project -Enable
    if ($LASTEXITCODE -ne 0) { throw 'Windows client installer failed to enable the adapter task' }
    $registeredRepeat = @($global:punaroRegisteredTriggers | Where-Object { $_.Once })
    if (-not $global:punaroStartTaskCalled -or $registeredRepeat.Count -ne 1 -or $registeredRepeat[0].Repetition.Interval -ne 'PT1M' -or $registeredRepeat[0].Repetition.Duration -ne 'P3650D' -or $registeredRepeat[0].Repetition.StopAtDurationEnd) {
        throw 'Windows client installer did not register an ISO 8601 repeating trigger'
    }
    $global:punaroDisableTaskCalled = $false
    $global:punaroStartTaskCalled = $false
    $global:punaroRegisteredTriggers = $null
    $repeat = [pscustomobject]@{ Repetition = [pscustomobject]@{ Interval = 'PT1M' } }
    $global:punaroExistingTask = [pscustomobject]@{ State = 'Disabled'; Triggers = @($repeat) }
    & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'https://relay.example.test' -MachineId 'windows-test' -AgentMailboxBin $mailbox -AgentGuidanceDir $project
    if ($LASTEXITCODE -ne 0) { throw 'Windows client installer failed to reinstall over a disabled task' }
    if ($global:punaroStartTaskCalled) { throw 'Windows client installer started a deliberately disabled adapter task' }
    if (-not $global:punaroDisableTaskCalled) { throw 'Windows client installer did not keep a disabled adapter task disabled' }
    if (@($global:punaroRegisteredTriggers | Where-Object { $_.Once }).Count -ne 0) {
        throw 'Windows client installer re-armed a disabled adapter task with the repeating trigger'
    }
    $global:punaroExistingTask = $null
    if ($global:punaroRegisteredSettings.ExecutionTimeLimit -ne [TimeSpan]::Zero) { throw 'Windows client adapter task must have no execution time limit' }
    if (-not $global:punaroRegisteredSettings.Hidden) { throw 'Windows client adapter task must be hidden from the task scheduler UI' }
    if (-not ([string]$global:punaroRegisteredAction.Argument -match '(^|\s)-ExecutionPolicy\s+Bypass(\s|$)')) { throw 'Windows client adapter task must use only process-scoped ExecutionPolicy Bypass' }
    if (-not ([string]$global:punaroRegisteredAction.Argument -match '(^|\s)-WindowStyle\s+Hidden(\s|$)')) { throw 'Windows client adapter task must hide its PowerShell console window' }
    $existingGroupMailbox = @'
@echo off
echo %* | findstr /C:"group create" >nul
if not errorlevel 1 (
  echo group already exists 1>&2
  exit /b 1
)
echo %* | findstr /C:"group list --json" >nul
if not errorlevel 1 (
  echo [{"group_id":"grp_test","address":"group/punaro-attached","created_at":"2026-01-01T00:00:00Z"}]
  exit /b 0
)
exit /b 0
'@
    [System.IO.File]::WriteAllText($mailbox, $existingGroupMailbox, [System.Text.Encoding]::ASCII)
    & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'https://relay.example.test' -MachineId 'windows-test' -AgentMailboxBin $mailbox -AgentGuidanceDir $project
    if ($LASTEXITCODE -ne 0) { throw 'Windows client installer was not idempotent' }
    $adapterEnvironment = Join-Path $root 'config\adapter.env'
    $prePolicyProfile = @([System.IO.File]::ReadAllLines($adapterEnvironment) | Where-Object { $_ -notmatch '^PUNARO_ADAPTER_(ALLOW_LAN_HTTP|TRUSTED_LAN_CIDR)=' })
    [System.IO.File]::WriteAllLines($adapterEnvironment, $prePolicyProfile, [System.Text.Encoding]::UTF8)
    & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'https://relay.example.test' -MachineId 'windows-test' -AgentMailboxBin $mailbox -AgentGuidanceDir $project
    if ($LASTEXITCODE -ne 0) { throw 'Windows client installer rejected a safe pre-policy HTTPS profile' }
    [System.IO.File]::WriteAllText((Join-Path $root 'bin\punaro-attachment.exe'), 'legacy', [System.Text.Encoding]::ASCII)
    $legacyBlocked = $false
    try {
        & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'https://relay.example.test' -MachineId 'windows-test' -AgentMailboxBin $mailbox -AgentGuidanceDir $project
    } catch {
        if ($_.Exception.Message.Contains('retired attachment artifact exists at')) { $legacyBlocked = $true } else { throw }
    }
    if (-not $legacyBlocked) { throw 'Windows client installer accepted an existing retired attachment binary' }
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
Write-Output 'install_client_windows_powershell_tests_passed'
