Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$bootstrap = Join-Path $root 'bootstrap'
$bin = Join-Path $root 'bin\punaro-bootstrap.exe'
for ($attempt = 0; $attempt -lt 3; $attempt++) {
    & $bin run --directory $bootstrap
    if ($LASTEXITCODE -eq 0) {
        exit 0
    }
    Start-Sleep -Seconds 3
}
exit $LASTEXITCODE
