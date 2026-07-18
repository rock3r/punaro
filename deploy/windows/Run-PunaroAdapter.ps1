Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
. (Join-Path $PSScriptRoot 'Import-PunaroEnvironment.ps1')
Import-PunaroEnvironment -Path (Join-Path $root 'config\adapter.env')
& (Join-Path $root 'bin\punaro-adapter.exe')
exit $LASTEXITCODE
