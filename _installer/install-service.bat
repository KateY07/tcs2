@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-service.ps1"
set "RESULT=%ERRORLEVEL%"
if not "%RESULT%"=="0" (
  echo TCS installation FAILED. Read the error and install.log before retrying.
  pause
  exit /b %RESULT%
)
echo TCS system service installed and verified successfully.
pause
exit /b 0
