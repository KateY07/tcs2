@echo off
rem Internal helper used by test.bat -- runs tcs.exe with its stdout/stderr
rem redirected to a log file. Not meant to be run by hand (though it's
rem harmless to: run-server.bat <keydir> <port> <logfile>).
"%~dp0bin\Release\net10.0\tcs.exe" -i "%~1" -p %2 > "%~3" 2>&1
