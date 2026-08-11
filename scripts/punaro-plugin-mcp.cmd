@echo off
setlocal
if "%LOCALAPPDATA%"=="" (
  echo punaro plugin: LOCALAPPDATA is unavailable 1>&2
  exit /b 1
)
set "PUNARO_PLUGIN_ADAPTER=%LOCALAPPDATA%\Punaro\bin\punaro-adapter.exe"
if not exist "%PUNARO_PLUGIN_ADAPTER%" (
  echo punaro plugin: installed adapter is unavailable at "%PUNARO_PLUGIN_ADAPTER%"; run the Punaro client installer first 1>&2
  exit /b 1
)
"%PUNARO_PLUGIN_ADAPTER%" mailbox-mcp
exit /b %ERRORLEVEL%
