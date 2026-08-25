@echo off
setlocal
if "%LOCALAPPDATA%"=="" (
  echo punaro plugin: LOCALAPPDATA is unavailable 1>&2
  exit /b 1
)
if /I "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "PUNARO_PLUGIN_ARCH=amd64"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "PUNARO_PLUGIN_ARCH=arm64"
if not defined PUNARO_PLUGIN_ARCH (
  echo punaro plugin: this launcher does not support the current architecture 1>&2
  exit /b 1
)
set "PUNARO_PLUGIN_ADAPTER=%LOCALAPPDATA%\Punaro\bootstrap\current\punaro-adapter-windows-%PUNARO_PLUGIN_ARCH%.exe"
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$item = Get-Item -LiteralPath $env:PUNARO_PLUGIN_ADAPTER -Force -ErrorAction Stop; if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 1 }" >nul 2>&1
if errorlevel 1 (
  echo punaro plugin: selected adapter is unavailable; run the Punaro client installer or bootstrap doctor 1>&2
  exit /b 1
)
"%PUNARO_PLUGIN_ADAPTER%" mailbox-mcp
exit /b %ERRORLEVEL%
