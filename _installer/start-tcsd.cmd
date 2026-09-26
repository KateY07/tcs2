@echo off
setlocal EnableExtensions

set "TCS_DIR=%~dp0"
if not exist "%TCS_DIR%authorized_keys" copy /Y "%TCS_DIR%controller.pub" "%TCS_DIR%authorized_keys" >nul
if not exist "%TCS_DIR%tcs_host_key" (
  where.exe ssh-keygen >nul 2>&1
  if errorlevel 1 (
    echo ssh-keygen.exe was not found. Install the Windows OpenSSH client first.
    exit /b 2
  )
  ssh-keygen.exe -q -t ed25519 -N "" -f "%TCS_DIR%tcs_host_key"
  if errorlevel 1 exit /b 1
)

echo TCS daemon listening on IPv4/IPv6 port 10122. Press Ctrl+C to stop.
"%TCS_DIR%tcsd.exe" --authorized-keys "%TCS_DIR%authorized_keys" --host-key "%TCS_DIR%tcs_host_key" --port 10122 --data "%TCS_DIR%data"
