@echo off
setlocal

set "TARGET=%LOCALAPPDATA%\tcs"
if not defined LOCALAPPDATA set "TARGET=%USERPROFILE%\tcs"

echo Installing tcs to "%TARGET%" ...
if not exist "%TARGET%" mkdir "%TARGET%"
robocopy "%~dp0" "%TARGET%" /E /R:2 /W:1 /XD "keys" "uploads" "test-logs" /XF "install.bat" "tcs-server.log"
if errorlevel 8 (
    echo ERROR: failed to copy tcs files.
    exit /b 1
)

if not exist "%TARGET%\keys\tcs\server.crt" (
    echo Generating the local mTLS certificate pair ...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%TARGET%\gen-certs.ps1" -OutDir "%TARGET%\keys\tcs" -SanList "DNS:localhost","DNS:%COMPUTERNAME%"
    if errorlevel 1 (
        echo ERROR: certificate generation failed. Ensure OpenSSL is installed and on PATH.
        exit /b 1
    )
)

if not exist "%TARGET%\uploads" mkdir "%TARGET%\uploads"
echo Starting tcs on port 10122 ...
start "tcs-server" /D "%TARGET%" "%TARGET%\run-server.bat" "%TARGET%\keys\tcs" 10122 "%TARGET%\tcs-server.log"
echo tcs is running. Files are installed under "%TARGET%".
exit /b 0
