@echo off
setlocal EnableExtensions

set "INSTALL_DIR=%LOCALAPPDATA%\TCS"
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if errorlevel 1 exit /b 1

copy /Y "%~dp0tcsd.exe" "%INSTALL_DIR%\tcsd.exe" >nul
if errorlevel 1 exit /b 1
copy /Y "%~dp0controller.pub" "%INSTALL_DIR%\controller.pub" >nul
if errorlevel 1 exit /b 1
copy /Y "%~dp0start-tcsd.cmd" "%INSTALL_DIR%\start-tcsd.cmd" >nul
if errorlevel 1 exit /b 1

echo TCS files copied to:
echo %INSTALL_DIR%
echo.
echo To start the controlled endpoint manually, run:
echo %INSTALL_DIR%\start-tcsd.cmd
exit /b 0
