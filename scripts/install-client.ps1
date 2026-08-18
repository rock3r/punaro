[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RelayUrl,
    [Parameter(Mandatory = $true)][string]$MachineId,
    [string]$AgentMailboxBin = 'agent-mailbox.exe',
    [string]$MailboxStateDir = (Join-Path $env:LOCALAPPDATA 'ai-agent\mailbox'),
    [string]$AttachedGroup = 'group/punaro-attached',
    [string]$AgentGuidanceDir,
    [switch]$AllowLanHttp,
    [string]$TrustedLanCidr,
    [switch]$Enable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Install([string]$Message) { throw "punaro installer: $Message" }

function Stop-PunaroOrphanAdapter([string]$BootstrapDirectory) {
    $pidFile = Join-Path $BootstrapDirectory 'run.pid'
    if (-not (Test-Path -LiteralPath $pidFile -PathType Leaf)) { return }
    $raw = Get-Content -LiteralPath $pidFile -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrWhiteSpace($raw)) { return }
    try { $record = $raw | ConvertFrom-Json } catch { return }
    $schema = $null
    $orphanPid = 0
    $orphanPath = ''
    try {
        $schemaProp = $record.PSObject.Properties['schema']
        $pidProp = $record.PSObject.Properties['pid']
        $pathProp = $record.PSObject.Properties['path']
        if ($null -eq $schemaProp -or $null -eq $pidProp -or $null -eq $pathProp) { return }
        $schema = $schemaProp.Value
        $orphanPid = [int]$pidProp.Value
        $orphanPath = [string]$pathProp.Value
    } catch { return }
    if ($schema -ne 1 -or $orphanPid -le 0 -or [string]::IsNullOrWhiteSpace($orphanPath)) { return }
    $proc = Get-Process -Id $orphanPid -ErrorAction SilentlyContinue
    if ($null -eq $proc) { return }
    $image = $null
    try { $image = $proc.Path } catch { }
    if ([string]::IsNullOrWhiteSpace($image)) {
        try { $image = $proc.MainModule.FileName } catch { }
    }
    if ([string]::IsNullOrWhiteSpace($image)) { return }
    $want = [System.IO.Path]::GetFullPath($orphanPath)
    $got = [System.IO.Path]::GetFullPath($image)
    if (-not $want.Equals($got, [System.StringComparison]::OrdinalIgnoreCase)) { return }
    Stop-Process -Id $orphanPid -Force -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(5)
    do {
        Start-Sleep -Milliseconds 200
        $proc = Get-Process -Id $orphanPid -ErrorAction SilentlyContinue
    } while ($null -ne $proc -and (Get-Date) -lt $deadline)
}

function Wait-PunaroReplaceableBinary([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $deadline = (Get-Date).AddSeconds(30)
    do {
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
            $stream.Dispose()
            return
        } catch {
            Start-Sleep -Milliseconds 200
        }
    } while ((Get-Date) -lt $deadline)
    Stop-Install "could not replace a still-running Punaro binary at $Path"
}

function Get-FullPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Stop-Install 'path is required' }
    return [System.IO.Path]::GetFullPath($Path)
}

function Test-ReparsePoint([System.IO.FileSystemInfo]$Item) {
    return (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Get-RegularFile([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { Stop-Install "$Label is unavailable" }
    $item = Get-Item -LiteralPath $Path -Force
    if (Test-ReparsePoint $item) { Stop-Install "$Label must not be a symlink or junction" }
    return $item
}

function Ensure-PrivateDirectory([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or (Test-ReparsePoint $item)) { Stop-Install "private directory is unsafe: $Path" }
    } else {
        [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    }
    Protect-PunaroPath -Path $Path -Directory
}

function Protect-PunaroPath {
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$Directory)

    $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $sid) { Stop-Install 'could not identify the current Windows user' }
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($sid)
    if ($Directory) {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
    }
    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Write-NewPrivateText([string]$Path, [string]$Text) {
    if (Test-Path -LiteralPath $Path) { Stop-Install "refusing to overwrite existing file: $Path" }
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
    Protect-PunaroPath -Path $Path
}

function Read-PunaroEnvironment([string]$Path) {
    Get-RegularFile -Path $Path -Label 'existing configuration' | Out-Null
    $values = @{}
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -le 0) { Stop-Install 'existing configuration contains an invalid line' }
        $name = $line.Substring(0, $separator)
        if ($name -notmatch '^PUNARO_[A-Z0-9_]+$' -or $values.ContainsKey($name)) { Stop-Install 'existing configuration is unsafe' }
        $values[$name] = $line.Substring($separator + 1)
    }
    return $values
}

function Assert-Configuration([string]$Path, [hashtable]$Expected, [hashtable]$MissingDefaults) {
    $existing = Read-PunaroEnvironment -Path $Path
    foreach ($name in $Expected.Keys) {
        if (-not $existing.ContainsKey($name)) {
            if ($MissingDefaults.ContainsKey($name) -and $Expected[$name] -eq $MissingDefaults[$name]) { continue }
            Stop-Install 'existing adapter.env belongs to a different machine or relay; refusing to overwrite it'
        }
        if ($existing[$name] -ne $Expected[$name]) {
            Stop-Install 'existing adapter.env belongs to a different machine or relay; refusing to overwrite it'
        }
    }
}

function Invoke-NativeProgramRaw([string]$Program, [string[]]$Arguments) {
    # Windows PowerShell turns a native program's stderr into PowerShell error
    # records. The installer must decide success from the native exit code so
    # expected diagnostics (for example, "group already exists") can be
    # handled by the idempotence path below.
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $Program @Arguments
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    return [pscustomobject]@{ Output = $output; ExitCode = $exitCode }
}

function Build-PunaroBinary([string]$Package, [string]$Output) {
    # `go build` discovers go.mod from the working directory, not from the
    # package argument. Keep the installer usable when invoked by an absolute
    # path from PowerShell's default directory.
    Push-Location -LiteralPath $repoDir
    try {
        $result = Invoke-NativeProgramRaw -Program 'go' -Arguments @('build', '-trimpath', '-buildvcs=true', '-o', $Output, $Package)
        if ($result.ExitCode -ne 0) { Stop-Install "could not build $Package" }
    } finally {
        Pop-Location
    }
    Protect-PunaroPath -Path $Output
}

function Invoke-Program([string]$Program, [string[]]$Arguments, [string]$Description) {
    $result = Invoke-NativeProgramRaw -Program $Program -Arguments $Arguments
    if ($result.ExitCode -ne 0) { Stop-Install "$Description failed" }
    return (($result.Output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

if ($env:OS -ne 'Windows_NT') { Stop-Install 'Windows client installation must run on Windows' }
if ($MachineId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { Stop-Install 'machine ID must start with a letter or digit and contain only letters, digits, dot, underscore, or hyphen' }
if ($AttachedGroup -notmatch '^group/[A-Za-z0-9._/-]+$') { Stop-Install 'attached group must be a group/ address' }
try { $relay = [Uri]$RelayUrl } catch { Stop-Install 'relay URL is invalid' }
if (-not $relay.IsAbsoluteUri) { Stop-Install 'relay URL is invalid' }
if ($relay.Scheme -eq 'https') {
    if ($AllowLanHttp -or -not [string]::IsNullOrWhiteSpace($TrustedLanCidr)) { Stop-Install 'trusted-LAN options are valid only with an http:// relay URL' }
} elseif ($relay.Scheme -eq 'http') {
    $literalAddress = $null
    if (-not $AllowLanHttp -or [string]::IsNullOrWhiteSpace($TrustedLanCidr) -or -not [System.Net.IPAddress]::TryParse($relay.DnsSafeHost, [ref]$literalAddress)) {
        Stop-Install 'LAN HTTP requires -AllowLanHttp, -TrustedLanCidr, and a literal IP origin'
    }
} else {
    Stop-Install 'relay URL must use https:// or explicitly acknowledged trusted-LAN http://'
}

$repoDir = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath (Join-Path $repoDir 'go.mod') -PathType Leaf) -or -not (Test-Path -LiteralPath (Join-Path $repoDir 'cmd\punaro-adapter') -PathType Container)) {
    Stop-Install 'run this installer from a complete Punaro source checkout'
}
try { Get-Command 'go' -CommandType Application -ErrorAction Stop | Out-Null } catch { Stop-Install 'Go is required to build the adapter from this checkout' }
$validationArguments = @('run', './cmd/punaro-adapter', 'validate-relay-transport', '--relay-url', $RelayUrl)
if ($AllowLanHttp) { $validationArguments += @('--allow-lan-http', '--trusted-lan-cidr', $TrustedLanCidr) }
Push-Location -LiteralPath $repoDir
try {
    $validation = Invoke-NativeProgramRaw -Program 'go' -Arguments $validationArguments
} finally {
    Pop-Location
}
if ($validation.ExitCode -ne 0) { Stop-Install 'relay transport policy is invalid' }

$root = Join-Path $env:LOCALAPPDATA 'Punaro'
$binDir = Join-Path $root 'bin'
$configDir = Join-Path $root 'config'
$stateDir = Join-Path $root 'state'
$bootstrapDir = Join-Path $root 'bootstrap'
$configFile = Join-Path $configDir 'adapter.env'
$keyFile = Join-Path $configDir 'machine.key'
$enrollmentFile = Join-Path $configDir 'enrollment.json'
$runner = Join-Path $root 'Run-PunaroAdapter.ps1'
foreach ($directory in @($root, $binDir, $configDir, $stateDir, $bootstrapDir)) { Ensure-PrivateDirectory -Path $directory }
foreach ($retiredPath in @(
    (Join-Path $binDir 'punaro-attachment.exe'),
    (Join-Path $binDir 'punaro-directory.exe'),
    (Join-Path $binDir 'punaro-dpapi.exe'),
    (Join-Path $binDir 'punaro-keychain.exe'),
    (Join-Path $root 'Run-PunaroAttachment.ps1'),
    (Join-Path $configDir 'attachment-v3')
)) {
    if (Test-Path -LiteralPath $retiredPath) { Stop-Install "retired attachment artifact exists at $retiredPath; archive or remove it explicitly before installing the trusted client" }
}

try {
    $mailboxCommand = Get-Command $AgentMailboxBin -CommandType Application -ErrorAction Stop
    $mailbox = if (-not [string]::IsNullOrWhiteSpace($mailboxCommand.Path)) { $mailboxCommand.Path } else { $mailboxCommand.Source }
    if ([string]::IsNullOrWhiteSpace($mailbox)) { Stop-Install 'agent-mailbox is required; install it before onboarding this machine' }
} catch { Stop-Install 'agent-mailbox is required; install it before onboarding this machine' }
$MailboxStateDir = Get-FullPath $MailboxStateDir

$adapterTaskName = 'Punaro Adapter'
$adapterTaskWasRunning = $false
$adapterTaskRestored = $false
$existingAdapterTask = Get-ScheduledTask -TaskName $adapterTaskName -ErrorAction SilentlyContinue
if ($null -ne $existingAdapterTask -and $existingAdapterTask.State -eq 'Running') {
    $adapterTaskWasRunning = $true
    Stop-ScheduledTask -TaskName $adapterTaskName
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 200
        $existingAdapterTask = Get-ScheduledTask -TaskName $adapterTaskName -ErrorAction SilentlyContinue
    } while ($null -ne $existingAdapterTask -and $existingAdapterTask.State -eq 'Running' -and (Get-Date) -lt $deadline)
    if ($null -ne $existingAdapterTask -and $existingAdapterTask.State -eq 'Running') {
        Stop-Install 'could not stop the running Punaro Adapter task before replacing bootstrap'
    }
}

try {
Stop-PunaroOrphanAdapter -BootstrapDirectory $bootstrapDir
Wait-PunaroReplaceableBinary -Path (Join-Path $binDir 'punaro-adapter.exe')
Wait-PunaroReplaceableBinary -Path (Join-Path $binDir 'punaro-bootstrap.exe')
Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-adapter') -Output (Join-Path $binDir 'punaro-adapter.exe')
Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-bootstrap') -Output (Join-Path $binDir 'punaro-bootstrap.exe')
Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-trusted-attachment') -Output (Join-Path $binDir 'punaro-trusted-attachment.exe')
Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-memory') -Output (Join-Path $binDir 'punaro-memory.exe')
Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-enroll') -Output (Join-Path $binDir 'punaro-enroll.exe')
Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-keygen') -Output (Join-Path $binDir 'punaro-keygen.exe')
Invoke-Program -Program (Join-Path $binDir 'punaro-bootstrap.exe') -Arguments @('seed-checkout', '--directory', $bootstrapDir, '--adapter', (Join-Path $binDir 'punaro-adapter.exe')) -Description 'bootstrap checkout seed'
foreach ($name in @('Run-PunaroAdapter.ps1', 'Import-PunaroEnvironment.ps1')) {
    $source = Join-Path $repoDir "deploy\windows\$name"
    $destination = Join-Path $root $name
    Get-RegularFile -Path $source -Label 'Windows runner template' | Out-Null
    if (Test-Path -LiteralPath $destination) {
        Get-RegularFile -Path $destination -Label 'installed Windows runner' | Out-Null
    }
    [System.IO.File]::Copy($source, $destination, $true)
    Protect-PunaroPath -Path $destination
}

if (Test-Path -LiteralPath $keyFile) {
    Get-RegularFile -Path $keyFile -Label 'existing machine key' | Out-Null
    Get-RegularFile -Path $enrollmentFile -Label 'existing machine enrollment' | Out-Null
} else {
    if (Test-Path -LiteralPath $enrollmentFile) { Stop-Install 'enrollment.json exists without its matching machine key' }
    $record = Invoke-Program -Program (Join-Path $binDir 'punaro-keygen.exe') -Arguments @('--id', $MachineId, '--endpoint-prefix', "agent/$MachineId/", '--private-key-file', $keyFile) -Description 'machine key creation'
    Write-NewPrivateText -Path $enrollmentFile -Text ($record + "`n")
    Protect-PunaroPath -Path $keyFile
}

$expected = @{ PUNARO_ADAPTER_RELAY_URL = $RelayUrl; PUNARO_MACHINE_ID = $MachineId; PUNARO_MACHINE_PRIVATE_KEY_FILE = $keyFile; PUNARO_ATTACHED_GROUP = $AttachedGroup; PUNARO_ADAPTER_DATA_DIR = $stateDir; PUNARO_MAILBOX_STATE_DIR = $MailboxStateDir; PUNARO_AGENT_MAILBOX_BIN = $mailbox; PUNARO_ADAPTER_ALLOW_LAN_HTTP = $AllowLanHttp.ToString().ToLowerInvariant(); PUNARO_ADAPTER_TRUSTED_LAN_CIDR = [string]$TrustedLanCidr }
$missingDefaults = @{ PUNARO_ADAPTER_ALLOW_LAN_HTTP = 'false'; PUNARO_ADAPTER_TRUSTED_LAN_CIDR = '' }
if (Test-Path -LiteralPath $configFile) {
    Assert-Configuration -Path $configFile -Expected $expected -MissingDefaults $missingDefaults
} else {
    $config = @(
        '# Created by Punaro. Keep this current-user-only file out of source control and backups.',
        "PUNARO_ADAPTER_RELAY_URL=$RelayUrl",
        "PUNARO_MACHINE_ID=$MachineId",
        "PUNARO_MACHINE_PRIVATE_KEY_FILE=$keyFile",
        "PUNARO_ATTACHED_GROUP=$AttachedGroup",
        "PUNARO_ADAPTER_DATA_DIR=$stateDir",
        "PUNARO_MAILBOX_STATE_DIR=$MailboxStateDir",
        'PUNARO_ADAPTER_POLL_INTERVAL=30s',
        "PUNARO_AGENT_MAILBOX_BIN=$mailbox",
        "PUNARO_ADAPTER_ALLOW_LAN_HTTP=$($AllowLanHttp.ToString().ToLowerInvariant())",
        "PUNARO_ADAPTER_TRUSTED_LAN_CIDR=$TrustedLanCidr",
        '',
        '# Add this machine''s distinct Cloudflare Access client ID and secret here with a secret manager or editor.',
        '# Do not pass them as installer arguments or reuse another machine''s token.'
    ) -join "`n"
    Write-NewPrivateText -Path $configFile -Text ($config + "`n")
}

$groupCreate = Invoke-NativeProgramRaw -Program $mailbox -Arguments @('--state-dir', $MailboxStateDir, 'group', 'create', '--group', $AttachedGroup)
if ($groupCreate.ExitCode -ne 0) {
    $groups = Invoke-Program -Program $mailbox -Arguments @('--state-dir', $MailboxStateDir, 'group', 'list', '--json') -Description 'attachment group lookup' | ConvertFrom-Json
    $groupAddresses = @($groups | ForEach-Object { $_.address })
    if ($groupAddresses -notcontains $AttachedGroup) { Stop-Install 'could not create the local Punaro attachment group' }
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
try {
    $powerShellCommand = Get-Command 'powershell.exe' -CommandType Application -ErrorAction Stop
    $windowsPowerShell = if (-not [string]::IsNullOrWhiteSpace($powerShellCommand.Path)) { $powerShellCommand.Path } else { $powerShellCommand.Source }
    if ([string]::IsNullOrWhiteSpace($windowsPowerShell)) { Stop-Install 'Windows PowerShell is required to register the adapter task' }
} catch { Stop-Install 'Windows PowerShell is required to register the adapter task' }
$action = New-ScheduledTaskAction -Execute $windowsPowerShell -Argument ('-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "{0}"' -f $runner)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden -ExecutionTimeLimit ([TimeSpan]::Zero)
$settings.RestartCount = 3
$settings.RestartInterval = [TimeSpan]::FromMinutes(1)
Register-ScheduledTask -TaskName $adapterTaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Punaro local mailbox adapter' -Force | Out-Null
if ($Enable -or $adapterTaskWasRunning) {
    Start-ScheduledTask -TaskName $adapterTaskName
    $adapterTaskRestored = $true
}

if (-not [string]::IsNullOrWhiteSpace($AgentGuidanceDir)) {
    & (Join-Path $repoDir 'scripts\install-agent-guidance.ps1') -Directory $AgentGuidanceDir
    if ($LASTEXITCODE -ne 0) { Stop-Install 'could not install agent guidance' }
}

Write-Output 'Punaro Windows client installed. Approve this public machine enrollment on the relay:'
Get-Content -LiteralPath $enrollmentFile
Write-Output 'Next: add this machine''s distinct Access token pair to adapter.env; bind and attach desired aliases; then rerun with -Enable.'
Write-Output 'After device-credential enrollment, use punaro-trusted-attachment.exe with a protected credential file and safe download root.'
Write-Output 'Run punaro-enroll.exe prepare before the server owner issues the one-time enrollment for this device; redeem only a protected enrollment-material file.'
} finally {
    if ($adapterTaskWasRunning -and -not $adapterTaskRestored) {
        Start-ScheduledTask -TaskName $adapterTaskName -ErrorAction SilentlyContinue
    }
}
