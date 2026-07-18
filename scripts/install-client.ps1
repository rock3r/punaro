[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RelayUrl,
    [Parameter(Mandatory = $true)][string]$MachineId,
    [string]$AgentMailboxBin = 'agent-mailbox.exe',
    [string]$MailboxStateDir = (Join-Path $env:LOCALAPPDATA 'ai-agent\mailbox'),
    [string]$AttachedGroup = 'group/punaro-attached',
    [string]$AgentGuidanceDir,
    [string]$AttachmentAuthorityPublic,
    [ValidateSet('receiver', 'sender', 'both')][string]$AttachmentRole,
    [string]$AttachmentDirectory,
    [switch]$Enable
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Stop-Install([string]$Message) { throw "punaro installer: $Message" }

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

function Assert-Configuration([string]$Path, [hashtable]$Expected) {
    $existing = Read-PunaroEnvironment -Path $Path
    foreach ($name in $Expected.Keys) {
        if (-not $existing.ContainsKey($name) -or $existing[$name] -ne $Expected[$name]) {
            Stop-Install 'existing adapter.env belongs to a different machine or relay; refusing to overwrite it'
        }
    }
}

function Build-PunaroBinary([string]$Package, [string]$Output) {
    & go build -trimpath -buildvcs=true -o $Output $Package
    if ($LASTEXITCODE -ne 0) { Stop-Install "could not build $Package" }
    Protect-PunaroPath -Path $Output
}

function Invoke-Program([string]$Program, [string[]]$Arguments, [string]$Description) {
    $output = & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { Stop-Install "$Description failed" }
    return (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
}

function New-Base64UrlId([int]$Bytes) {
    $raw = New-Object byte[] $Bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($raw)
    return [Convert]::ToBase64String($raw).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Assert-Authority([string]$Path) {
    Get-RegularFile -Path $Path -Label 'attachment authority public record' | Out-Null
    try { $authority = [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json } catch { Stop-Install 'attachment authority public record is invalid JSON' }
    if ($authority.version -ne 3) { Stop-Install 'attachment authority public record must be version 3' }
    foreach ($name in @('audience', 'root_key_id', 'root_public_key')) {
        if ([string]$authority.$name -notmatch '^[A-Za-z0-9_-]{43}$') { Stop-Install "attachment authority public record has invalid $name" }
    }
    return $authority
}

function Install-AttachmentClient {
    param(
        [string]$Directory,
        [string]$AuthorityPublic,
        [string]$Role,
        [string]$Machine,
        [string]$Relay,
        [string]$AdapterState,
        [string]$Bin
    )

    if ([string]::IsNullOrWhiteSpace($Directory)) { $Directory = Join-Path $configDir 'attachment-v3' }
    $Directory = Get-FullPath $Directory
    $environmentFile = Join-Path $Directory 'attachment-v3.env'
    $enrollmentFile = Join-Path $Directory 'device-enrollment.json'
    if (Test-Path -LiteralPath $Directory) {
        Get-RegularFile -Path $environmentFile -Label 'existing attachment environment' | Out-Null
        Get-RegularFile -Path $enrollmentFile -Label 'existing attachment enrollment' | Out-Null
        try { $existing = [System.IO.File]::ReadAllText($enrollmentFile) | ConvertFrom-Json } catch { Stop-Install 'existing attachment enrollment is invalid JSON' }
        $environment = Read-PunaroEnvironment -Path $environmentFile
        if ($existing.machine_id -ne $Machine -or $environment['PUNARO_ATTACHMENT_RELAY_URL'] -ne $Relay) { Stop-Install 'existing attachment setup belongs to a different machine or relay' }
        if ($existing.role -ne $Role) {
            if ($existing.role -eq 'receiver' -and ($Role -eq 'sender' -or $Role -eq 'both')) {
                Stop-Install 'existing attachment setup is receiver-only; use a new -AttachmentDirectory for sender or both and approve its new public enrollment'
            }
            Stop-Install 'existing attachment setup role does not match -AttachmentRole; use a new -AttachmentDirectory and approve its new public enrollment'
        }
        return
    }

    $authority = Assert-Authority -Path $AuthorityPublic
    Ensure-PrivateDirectory -Path $Directory
    $directoryBinary = Join-Path $Bin 'punaro-directory.exe'
    Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-directory') -Output $directoryBinary
    $signingPublic = Invoke-Program -Program $directoryBinary -Arguments @('keygen', '--algorithm', 'ed25519', '--private-key-file', (Join-Path $Directory 'device-signing.private')) -Description 'attachment signing-key creation' | ConvertFrom-Json
    $hpkePublic = Invoke-Program -Program $directoryBinary -Arguments @('keygen', '--algorithm', 'x25519', '--private-key-file', (Join-Path $Directory 'device-hpke.private')) -Description 'attachment HPKE-key creation' | ConvertFrom-Json
    Protect-PunaroPath -Path (Join-Path $Directory 'device-signing.private')
    Protect-PunaroPath -Path (Join-Path $Directory 'device-hpke.private')
    $deviceId = New-Base64UrlId 16
    $device = [ordered]@{ device_id = $deviceId; generation = 1; signing_key_id = (New-Base64UrlId 32); signing_public_key = $signingPublic.public_key; hpke_key_id = (New-Base64UrlId 32); hpke_public_key = $hpkePublic.public_key; revoked = $false }
    $enrollment = [ordered]@{ version = 3; machine_id = $Machine; role = $Role; attachment_device_id = $deviceId; directory_entry = [ordered]@{ device = $device } }
    Write-NewPrivateText -Path $enrollmentFile -Text (($enrollment | ConvertTo-Json -Compress -Depth 8) + "`n")

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('# Created by Punaro attachment-v3 provisioning. This owner-only file contains paths, not credentials.')
    $lines.Add("PUNARO_ATTACHMENT_RELAY_URL=$Relay")
    $lines.Add("PUNARO_ATTACHMENT_DIRECTORY_CHECKPOINT_FILE=$(Join-Path $Directory 'directory-checkpoints.db')")
    $lines.Add("PUNARO_DIRECTORY_AUDIENCE=$($authority.audience)")
    $lines.Add("PUNARO_DIRECTORY_ROOT_KEY_ID=$($authority.root_key_id)")
    $lines.Add("PUNARO_DIRECTORY_ROOT_PUBLIC_KEY=$($authority.root_public_key)")
    if ($Role -eq 'receiver' -or $Role -eq 'both') {
        $lines.Add("PUNARO_ATTACHMENT_RECIPIENT_SIGNING_PRIVATE_KEY_FILE=$(Join-Path $Directory 'device-signing.private')")
        $lines.Add("PUNARO_ATTACHMENT_RECIPIENT_HPKE_PRIVATE_KEY_FILE=$(Join-Path $Directory 'device-hpke.private')")
        $lines.Add("PUNARO_ATTACHMENT_RECIPIENT_ID=$deviceId")
        $lines.Add('PUNARO_ATTACHMENT_RECIPIENT_GENERATION=1')
        $lines.Add("PUNARO_ATTACHMENT_CONTROLLER_JOURNAL=$(Join-Path $Directory 'controller.db')")
    }
    if ($Role -eq 'sender' -or $Role -eq 'both') {
        $dpapiBinary = Join-Path $Bin 'punaro-dpapi.exe'
        Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-dpapi') -Output $dpapiBinary
        $hostKeyFile = Join-Path $Directory 'sender-host-key.dpapi'
        Invoke-Program -Program $dpapiBinary -Arguments @('--file', $hostKeyFile) -Description 'Windows DPAPI sender-key creation' | Out-Null
        Protect-PunaroPath -Path $hostKeyFile
        $lines.Add("PUNARO_ATTACHMENT_SENDER_SIGNING_PRIVATE_KEY_FILE=$(Join-Path $Directory 'device-signing.private')")
        $lines.Add("PUNARO_ATTACHMENT_SENDER_ID=$deviceId")
        $lines.Add('PUNARO_ATTACHMENT_SENDER_GENERATION=1')
        $lines.Add("PUNARO_ATTACHMENT_SENDER_JOURNAL=$(Join-Path $Directory 'sender.db')")
        $lines.Add("PUNARO_ATTACHMENT_ARTIFACT_STORE=$(Join-Path $Directory 'artifacts.db')")
        $lines.Add("PUNARO_ATTACHMENT_OFFER_OUTBOX=$(Join-Path $AdapterState 'attachment-offers.db')")
        $lines.Add("PUNARO_ATTACHMENT_HOST_DPAPI_FILE=$hostKeyFile")
    }
    Write-NewPrivateText -Path $environmentFile -Text (($lines -join "`n") + "`n")
}

if ($env:OS -ne 'Windows_NT') { Stop-Install 'Windows client installation must run on Windows' }
if ($MachineId -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { Stop-Install 'machine ID must start with a letter or digit and contain only letters, digits, dot, underscore, or hyphen' }
if ($AttachedGroup -notmatch '^group/[A-Za-z0-9._/-]+$') { Stop-Install 'attached group must be a group/ address' }
try { $relay = [Uri]$RelayUrl } catch { Stop-Install 'relay URL must use https://' }
if (-not $relay.IsAbsoluteUri -or $relay.Scheme -ne 'https') { Stop-Install 'relay URL must use https://' }
if (([string]::IsNullOrWhiteSpace($AttachmentAuthorityPublic)) -ne ([string]::IsNullOrWhiteSpace($AttachmentRole))) { Stop-Install 'attachment setup requires both -AttachmentAuthorityPublic and -AttachmentRole' }

$repoDir = Split-Path -Parent $PSScriptRoot
$root = Join-Path $env:LOCALAPPDATA 'Punaro'
$binDir = Join-Path $root 'bin'
$configDir = Join-Path $root 'config'
$stateDir = Join-Path $root 'state'
$configFile = Join-Path $configDir 'adapter.env'
$keyFile = Join-Path $configDir 'machine.key'
$enrollmentFile = Join-Path $configDir 'enrollment.json'
$runner = Join-Path $root 'Run-PunaroAdapter.ps1'
foreach ($directory in @($root, $binDir, $configDir, $stateDir)) { Ensure-PrivateDirectory -Path $directory }

try {
    $mailboxCommand = Get-Command $AgentMailboxBin -CommandType Application -ErrorAction Stop
    $mailbox = if (-not [string]::IsNullOrWhiteSpace($mailboxCommand.Path)) { $mailboxCommand.Path } else { $mailboxCommand.Source }
    if ([string]::IsNullOrWhiteSpace($mailbox)) { Stop-Install 'agent-mailbox is required; install it before onboarding this machine' }
} catch { Stop-Install 'agent-mailbox is required; install it before onboarding this machine' }
$MailboxStateDir = Get-FullPath $MailboxStateDir

Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-adapter') -Output (Join-Path $binDir 'punaro-adapter.exe')
Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-attachment') -Output (Join-Path $binDir 'punaro-attachment.exe')
Build-PunaroBinary -Package (Join-Path $repoDir 'cmd\punaro-keygen') -Output (Join-Path $binDir 'punaro-keygen.exe')
foreach ($name in @('Run-PunaroAdapter.ps1', 'Run-PunaroAttachment.ps1', 'Import-PunaroEnvironment.ps1')) {
    $source = Join-Path $repoDir "deploy\windows\$name"
    $destination = Join-Path $root $name
    if (-not (Test-Path -LiteralPath $destination)) { [System.IO.File]::Copy($source, $destination) }
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

$expected = @{ PUNARO_ADAPTER_RELAY_URL = $RelayUrl; PUNARO_MACHINE_ID = $MachineId; PUNARO_MACHINE_PRIVATE_KEY_FILE = $keyFile; PUNARO_ATTACHED_GROUP = $AttachedGroup; PUNARO_ADAPTER_DATA_DIR = $stateDir; PUNARO_MAILBOX_STATE_DIR = $MailboxStateDir; PUNARO_AGENT_MAILBOX_BIN = $mailbox }
if (Test-Path -LiteralPath $configFile) {
    Assert-Configuration -Path $configFile -Expected $expected
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
        '',
        '# Add this machine''s distinct Cloudflare Access client ID and secret here with a secret manager or editor.',
        '# Do not pass them as installer arguments or reuse another machine''s token.'
    ) -join "`n"
    Write-NewPrivateText -Path $configFile -Text ($config + "`n")
}

& $mailbox '--state-dir' $MailboxStateDir 'group' 'create' '--group' $AttachedGroup
if ($LASTEXITCODE -ne 0) {
    $groups = Invoke-Program -Program $mailbox -Arguments @('--state-dir', $MailboxStateDir, 'group', 'list', '--json') -Description 'attachment group lookup' | ConvertFrom-Json
    if ($groups -notcontains $AttachedGroup) { Stop-Install 'could not create the local Punaro attachment group' }
}

if (-not [string]::IsNullOrWhiteSpace($AttachmentRole)) {
    Install-AttachmentClient -Directory $AttachmentDirectory -AuthorityPublic (Get-FullPath $AttachmentAuthorityPublic) -Role $AttachmentRole -Machine $MachineId -Relay $RelayUrl -AdapterState $stateDir -Bin $binDir
}

$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
try {
    $powerShellCommand = Get-Command 'powershell.exe' -CommandType Application -ErrorAction Stop
    $windowsPowerShell = if (-not [string]::IsNullOrWhiteSpace($powerShellCommand.Path)) { $powerShellCommand.Path } else { $powerShellCommand.Source }
    if ([string]::IsNullOrWhiteSpace($windowsPowerShell)) { Stop-Install 'Windows PowerShell is required to register the adapter task' }
} catch { Stop-Install 'Windows PowerShell is required to register the adapter task' }
$action = New-ScheduledTaskAction -Execute $windowsPowerShell -Argument ('-NoProfile -NonInteractive -File "{0}"' -f $runner)
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName 'Punaro Adapter' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Punaro local mailbox adapter' -Force | Out-Null
if ($Enable) { Start-ScheduledTask -TaskName 'Punaro Adapter' }

if (-not [string]::IsNullOrWhiteSpace($AgentGuidanceDir)) {
    & (Join-Path $repoDir 'scripts\install-agent-guidance.ps1') -Directory $AgentGuidanceDir
    if ($LASTEXITCODE -ne 0) { Stop-Install 'could not install agent guidance' }
}

Write-Output 'Punaro Windows client installed. Approve this public machine enrollment on the relay:'
Get-Content -LiteralPath $enrollmentFile
Write-Output 'Next: add this machine''s distinct Access token pair to adapter.env; bind and attach desired aliases; then rerun with -Enable.'
if (-not [string]::IsNullOrWhiteSpace($AttachmentRole)) { Write-Output 'The public attachment enrollment requires offline authority approval before transfer is possible.' }
