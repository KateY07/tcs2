@echo off
setlocal EnableExtensions
if not exist "%~dp0install-user.bat" (
  echo This historical payload cannot install the current version. Use the latest manual installer.
  exit /b 1
)
call "%~dp0install-user.bat"
exit /b %errorlevel%
