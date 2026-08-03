Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
& (Join-Path $root 'bin\punaro-adapter.exe')
exit $LASTEXITCODE
