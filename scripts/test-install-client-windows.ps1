Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoDir = Split-Path -Parent $PSScriptRoot
$paths = @(
    (Join-Path $repoDir 'scripts\install-client.ps1'),
    (Join-Path $repoDir 'scripts\install-agent-guidance.ps1'),
    (Join-Path $repoDir 'deploy\windows\Run-PunaroAdapter.ps1'),
    (Join-Path $repoDir 'deploy\windows\Run-PunaroAttachment.ps1'),
    (Join-Path $repoDir 'deploy\windows\Import-PunaroEnvironment.ps1')
)
foreach ($path in $paths) {
    $tokens = $null
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
    if ($null -ne $errors -and $errors.Count -ne 0) { throw "PowerShell parse failure in ${path}: $($errors[0].Message)" }
}

$installer = [System.IO.File]::ReadAllText((Join-Path $repoDir 'scripts\install-client.ps1'))
foreach ($expected in @('LogonType Interactive', 'ExecutionTimeLimit ([TimeSpan]::Zero)', 'SetAccessRuleProtection($true, $false)', 'PUNARO_ATTACHMENT_HOST_DPAPI_FILE', 'punaro-dpapi.exe', 'agent-mailbox', 'AgentGuidanceDir')) {
    if (-not $installer.Contains($expected)) { throw "Windows installer is missing required behavior: $expected" }
}
$allScripts = ($paths | ForEach-Object { [System.IO.File]::ReadAllText($_) }) -join "`n"
if ($allScripts -match 'Invoke-Expression|PUNARO_CF_ACCESS_CLIENT_SECRET=|\.\s*\$config') {
    throw 'Windows client scripts must not execute configuration or embed Access credentials'
}

$fixture = Join-Path ([System.IO.Path]::GetTempPath()) ("punaro-windows-install-test-" + [Guid]::NewGuid())
$originalLocalAppData = $env:LOCALAPPDATA
try {
    [System.IO.Directory]::CreateDirectory($fixture) | Out-Null
    $env:LOCALAPPDATA = Join-Path $fixture 'localappdata'
    $mailbox = Join-Path $fixture 'agent-mailbox.cmd'
    [System.IO.File]::WriteAllText($mailbox, "@echo off`r`nexit /b 0`r`n", [System.Text.Encoding]::ASCII)
    $project = Join-Path $fixture 'project'
    [System.IO.Directory]::CreateDirectory($project) | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $project 'CLAUDE.md'), '# Existing guidance', [System.Text.Encoding]::UTF8)

    $script:registeredTask = $null
    function New-ScheduledTaskAction { param([string]$Execute, [string]$Argument) return [pscustomobject]@{ Execute = $Execute; Argument = $Argument } }
    function New-ScheduledTaskTrigger { param([switch]$AtLogOn, [string]$User) return [pscustomobject]@{ User = $User } }
    function New-ScheduledTaskPrincipal { param([string]$UserId, [string]$LogonType, [string]$RunLevel) return [pscustomobject]@{ UserId = $UserId } }
    function New-ScheduledTaskSettingsSet { param([switch]$AllowStartIfOnBatteries, [switch]$DontStopIfGoingOnBatteries, [TimeSpan]$ExecutionTimeLimit) return [pscustomobject]@{ ExecutionTimeLimit = $ExecutionTimeLimit } }
    function Register-ScheduledTask {
        param([string]$TaskName, $Action, $Trigger, $Principal, $Settings, [string]$Description, [switch]$Force)
        $script:registeredTask = $TaskName
        $script:registeredSettings = $Settings
        return [pscustomobject]@{}
    }

    & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'https://relay.example.test' -MachineId 'windows-test' -AgentMailboxBin $mailbox -AgentGuidanceDir $project
    if ($LASTEXITCODE -ne 0) { throw 'Windows client installer failed' }
    $root = Join-Path $env:LOCALAPPDATA 'Punaro'
    foreach ($path in @((Join-Path $root 'config\machine.key'), (Join-Path $root 'config\enrollment.json'), (Join-Path $root 'config\adapter.env'), (Join-Path $project '.agents\skills\punaro-mailbox\SKILL.md'))) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Windows client installer did not create $path" }
    }
    if ($script:registeredTask -ne 'Punaro Adapter') { throw 'Windows client installer did not register the expected per-user task' }
    if ($script:registeredSettings.ExecutionTimeLimit -ne [TimeSpan]::Zero) { throw 'Windows client adapter task must have no execution time limit' }
    & (Join-Path $repoDir 'scripts\install-client.ps1') -RelayUrl 'https://relay.example.test' -MachineId 'windows-test' -AgentMailboxBin $mailbox -AgentGuidanceDir $project
    if ($LASTEXITCODE -ne 0) { throw 'Windows client installer was not idempotent' }
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
Write-Output 'install_client_windows_powershell_tests_passed'
