@echo off
setlocal EnableExtensions
rem Interactive start uses the current account's fixed .ssh identity.
"%ProgramData%\TCS\tcsd.exe"
exit /b %errorlevel%
