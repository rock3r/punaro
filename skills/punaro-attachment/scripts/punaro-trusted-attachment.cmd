@echo off
setlocal
if "%LOCALAPPDATA%"=="" (
  echo punaro attachment skill: LOCALAPPDATA is unavailable 1>&2
  exit /b 1
)
set "PUNARO_SKILL_ATTACHMENT=%LOCALAPPDATA%\Punaro\bin\punaro-trusted-attachment.exe"
if not exist "%PUNARO_SKILL_ATTACHMENT%" (
  echo punaro attachment skill: selected trusted-attachment client is unavailable; run the Punaro client installer or bootstrap doctor 1>&2
  exit /b 1
)
"%PUNARO_SKILL_ATTACHMENT%" %*
exit /b %ERRORLEVEL%
