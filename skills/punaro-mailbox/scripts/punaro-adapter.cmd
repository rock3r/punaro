@echo off
setlocal
if "%LOCALAPPDATA%"=="" (
  echo punaro mailbox skill: LOCALAPPDATA is unavailable 1>&2
  exit /b 1
)
set "PUNARO_SKILL_ADAPTER=%LOCALAPPDATA%\Punaro\bin\punaro-adapter.exe"
if not exist "%PUNARO_SKILL_ADAPTER%" (
  echo punaro mailbox skill: selected adapter is unavailable; run the Punaro client installer or bootstrap doctor 1>&2
  exit /b 1
)
"%PUNARO_SKILL_ADAPTER%" %*
exit /b %ERRORLEVEL%
