Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$bootstrap = Join-Path $root 'bootstrap'
& (Join-Path $root 'bin\punaro-bootstrap.exe') run --directory $bootstrap
exit $LASTEXITCODE
