Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$bootstrap = Join-Path $root 'bootstrap'
$bin = Join-Path $root 'bin\punaro-bootstrap.exe'
& $bin run --directory $bootstrap
exit $LASTEXITCODE
