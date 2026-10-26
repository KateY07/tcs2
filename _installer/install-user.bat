@echo off
setlocal EnableExtensions
rem TCS user installer. Runs in a plain console and inside the onesetup UI shell: lines printed as ".command text"
rem drive the window (.title .info .warn .error .progress .ask .choose); everything else goes to its Details log.
rem Keep this file ASCII. The UI shell answers .ask on stdin, so "pause" is skipped when ONESETUP_SHELL is set.
set "TARGET=%LOCALAPPDATA%\TCS"
echo .title TCS Setup
if not defined LOCALAPPDATA goto missing_profile
if not exist "%~dp0tcs.exe" goto missing_files
if not exist "%~dp0tcsd.exe" goto missing_files

if defined TCS_ROLE set "ROLE_PRESET=1"
if defined TCS_ROLE goto role_known
echo .info Choosing this computer's role
echo .progress 5
echo .choose Which role is this computer?; Controller - you type tcs commands; Controlled server - runs tcsd
set "PICK="
set /p PICK=
if "%PICK%"=="1" set "TCS_ROLE=controller"
if "%PICK%"=="2" set "TCS_ROLE=server"
if not defined TCS_ROLE goto bad_role
:role_known
if /i "%TCS_ROLE%"=="controller" goto role_ok
if /i "%TCS_ROLE%"=="server" goto role_ok
goto bad_role
:role_ok

echo .info Checking the SSH key for the %TCS_ROLE% role
echo .progress 15
"%~dp0tcs.exe" --check-install %TCS_ROLE%
if errorlevel 1 goto prerequisites
echo .info Copying program files
echo .progress 40
if not exist "%TARGET%" mkdir "%TARGET%"
if errorlevel 1 goto failed
copy /Y "%~dp0tcs.exe" "%TARGET%\tcs.exe" >nul
if errorlevel 1 goto failed
echo .progress 55
copy /Y "%~dp0tcsd.exe" "%TARGET%\tcsd.exe" >nul
if errorlevel 1 goto failed
copy /Y "%~dp0README.md" "%TARGET%\README.md" >nul
if errorlevel 1 goto failed
echo Installed to "%TARGET%".
echo .info Adding TCS to your user PATH
echo .progress 75
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0set-user-path.ps1" -InstallDirectory "%TARGET%"
if errorlevel 1 goto failed
echo No keys created or copied. No service or firewall changes.
echo Read "%TARGET%\README.md" to configure keys and start manually.
if /i "%TCS_ROLE%"=="controller" goto controller_hint
echo .info To pair: run  tcsd pair  here, then  tcs pair THIS-PC CODE  on the controller
goto finished
:controller_hint
echo .info To pair: run tcsd pair on the controlled PC, then tcs pair HOST CODE here
:finished
echo .progress 100
echo .info Done. Open a new terminal to use tcs and tcsd.
exit /b 0

:missing_profile
echo .error Your profile folder (LOCALAPPDATA) is not available.
exit /b 1
:missing_files
echo .error tcs.exe or tcsd.exe is missing from the installer. Download it again.
exit /b 1
:bad_role
echo .error Pick 1 for the controller or 2 for the controlled server (or set TCS_ROLE to controller or server).
exit /b 1
:prerequisites
echo .error No usable private key was found for this role. Open Details for the PowerShell script that creates one.
echo Installation stopped. No application files or PATH were changed.
echo Copy the PowerShell script above, prepare your keys, then run this installer again.
if not defined ONESETUP_SHELL pause
exit /b 1
:failed
echo .error Installation failed. Stop running TCS programs and retry.
if not defined ONESETUP_SHELL pause
exit /b 1
