@echo off
setlocal
if "%LOCALAPPDATA%"=="" (
  echo punaro mailbox skill: LOCALAPPDATA is unavailable 1>&2
  exit /b 1
)
if /I "%PROCESSOR_ARCHITECTURE%"=="AMD64" set "PUNARO_SKILL_ARCH=amd64"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "PUNARO_SKILL_ARCH=arm64"
if not defined PUNARO_SKILL_ARCH (
  echo punaro mailbox skill: this launcher does not support the current architecture 1>&2
  exit /b 1
)
set "PUNARO_SKILL_ADAPTER=%LOCALAPPDATA%\Punaro\bootstrap\current\punaro-adapter-windows-%PUNARO_SKILL_ARCH%.exe"
powershell.exe -NoLogo -NoProfile -NonInteractive -Command "$item = Get-Item -LiteralPath $env:PUNARO_SKILL_ADAPTER -Force -ErrorAction Stop; if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 1 }" >nul 2>&1
if errorlevel 1 (
  echo punaro mailbox skill: selected adapter is unavailable; run the Punaro client installer or bootstrap doctor 1>&2
  exit /b 1
)
"%PUNARO_SKILL_ADAPTER%" %*
exit /b %ERRORLEVEL%
