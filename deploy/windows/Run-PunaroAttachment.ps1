param(
    [Parameter(Mandatory = $true)][string]$AttachmentConfig,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$AttachmentArguments
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
. (Join-Path $PSScriptRoot 'Import-PunaroEnvironment.ps1')
Import-PunaroEnvironment -Path (Join-Path $root 'config\adapter.env')
Import-PunaroEnvironment -Path $AttachmentConfig
& (Join-Path $root 'bin\punaro-attachment.exe') @AttachmentArguments
exit $LASTEXITCODE
