@echo off
setlocal EnableExtensions
set "TARGET=%LOCALAPPDATA%\TCS"
if not defined LOCALAPPDATA exit /b 1
if not exist "%~dp0tcs.exe" exit /b 1
if not exist "%~dp0tcsd.exe" exit /b 1
if not exist "%TARGET%" mkdir "%TARGET%"
if errorlevel 1 exit /b 1
copy /Y "%~dp0tcs.exe" "%TARGET%\tcs.exe" >nul
if errorlevel 1 goto failed
copy /Y "%~dp0tcsd.exe" "%TARGET%\tcsd.exe" >nul
if errorlevel 1 goto failed
copy /Y "%~dp0README.md" "%TARGET%\README.md" >nul
if errorlevel 1 goto failed
echo Installed to "%TARGET%".
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0set-user-path.ps1" -InstallDirectory "%TARGET%"
if errorlevel 1 goto failed
echo No keys created or copied. No service or firewall changes.
echo Read "%TARGET%\README.md" to configure keys and start manually.
echo Close all terminal windows, then open a new terminal to use tcs and tcsd.
exit /b 0
:failed
echo Installation failed. Stop running TCS programs and retry.
exit /b 1
