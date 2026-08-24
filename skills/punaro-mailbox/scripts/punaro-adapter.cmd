@echo off
setlocal
if "%LOCALAPPDATA%"=="" (
  echo punaro mailbox skill: LOCALAPPDATA is unavailable 1>&2
  exit /b 1
)
set "PUNARO_SKILL_ADAPTER=%LOCALAPPDATA%\Punaro\bin\punaro-adapter.exe"
if not exist "%PUNARO_SKILL_ADAPTER%" (
  echo punaro mailbox skill: installed adapter is unavailable at "%PUNARO_SKILL_ADAPTER%"; run the Punaro client installer first 1>&2
  exit /b 1
)
"%PUNARO_SKILL_ADAPTER%" %*
exit /b %ERRORLEVEL%
