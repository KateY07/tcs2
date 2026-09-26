@echo off
setlocal enabledelayedexpansion

rem test.bat -- one-shot build + run + full regression for tcs.
rem
rem Does, in order: dotnet build, generates trusted + untrusted cert pairs
rem (once, reused on later runs), starts tcs.exe in the background, waits
rem for it to accept connections, runs regression_test.py (security /
rem latency / bandwidth / concurrency), stops tcs.exe, and writes
rem everything to test-logs\ next to this script.
rem
rem Usage: just double-click it, or run it from a shell:  test.bat

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "LOGDIR=%SCRIPT_DIR%test-logs"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"') do set "TIMESTAMP=%%i"
set "LOGFILE=%LOGDIR%\regression_%TIMESTAMP%.log"
set "SERVERLOG=%LOGDIR%\server_%TIMESTAMP%.log"
set "PORT=10122"
set "KEYDIR=%SCRIPT_DIR%keys\tcs"
set "UNTRUSTED_KEYDIR=%SCRIPT_DIR%keys\tcs-untrusted"

echo ==== tcs regression run %TIMESTAMP% ==== > "%LOGFILE%"
echo Full log: %LOGFILE%
echo.

rem ---- 0. find python -------------------------------------------------
where python >nul 2>&1
if not errorlevel 1 (
    set "PY=python"
) else (
    where python3 >nul 2>&1
    if not errorlevel 1 (
        set "PY=python3"
    ) else (
        echo [FATAL] no "python" or "python3" found on PATH >> "%LOGFILE%"
        type "%LOGFILE%"
        exit /b 1
    )
)
echo [0/6] using interpreter: !PY! >> "%LOGFILE%"

rem ---- 1. build ---------------------------------------------------------
echo [1/6] dotnet build -c Release >> "%LOGFILE%"
dotnet build -c Release >> "%LOGFILE%" 2>&1
if errorlevel 1 (
    echo [FATAL] build failed >> "%LOGFILE%"
    type "%LOGFILE%"
    exit /b 1
)

if not exist "%SCRIPT_DIR%bin\Release\net10.0\tcs.exe" (
    echo [FATAL] build reported success but tcs.exe is missing >> "%LOGFILE%"
    type "%LOGFILE%"
    exit /b 1
)

rem ---- 2. trusted cert/key pair ------------------------------------------
if not exist "%KEYDIR%\server.crt" (
    echo [2/6] generating trusted cert/key pair at %KEYDIR% >> "%LOGFILE%"
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%gen-certs.ps1" -OutDir "%KEYDIR%" >> "%LOGFILE%" 2>&1
    if errorlevel 1 (
        echo [FATAL] gen-certs.ps1 failed for %KEYDIR% >> "%LOGFILE%"
        type "%LOGFILE%"
        exit /b 1
    )
) else (
    echo [2/6] reusing existing trusted certs at %KEYDIR% >> "%LOGFILE%"
)

rem ---- 3. untrusted cert/key pair (for the negative security test) -------
if not exist "%UNTRUSTED_KEYDIR%\client.crt" (
    echo [3/6] generating untrusted cert/key pair at %UNTRUSTED_KEYDIR% >> "%LOGFILE%"
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%gen-certs.ps1" -OutDir "%UNTRUSTED_KEYDIR%" >> "%LOGFILE%" 2>&1
    if errorlevel 1 (
        echo [FATAL] gen-certs.ps1 failed for %UNTRUSTED_KEYDIR% >> "%LOGFILE%"
        type "%LOGFILE%"
        exit /b 1
    )
) else (
    echo [3/6] reusing existing untrusted certs at %UNTRUSTED_KEYDIR% >> "%LOGFILE%"
)

rem ---- 4. start the server in the background ------------------------------
echo [4/6] starting tcs.exe on port %PORT% (log: %SERVERLOG%) >> "%LOGFILE%"
set "TCS_PYTHON_EXE=!PY!"
start "tcs-server" /min "%SCRIPT_DIR%run-server.bat" "%KEYDIR%" %PORT% "%SERVERLOG%"

set "READY=0"
for /L %%i in (1,1,30) do (
    powershell -NoProfile -Command "try { $c = New-Object Net.Sockets.TcpClient; $c.Connect('localhost', %PORT%); $c.Close(); exit 0 } catch { exit 1 }" >nul 2>&1
    if not errorlevel 1 (
        set "READY=1"
        goto :server_ready
    )
    timeout /t 1 >nul
)
:server_ready
if "!READY!"=="0" (
    echo [FATAL] server did not start accepting connections within 30s >> "%LOGFILE%"
    echo ---- server log ---- >> "%LOGFILE%"
    type "%SERVERLOG%" >> "%LOGFILE%" 2>nul
    type "%LOGFILE%"
    taskkill /FI "WINDOWTITLE eq tcs-server*" /T /F >nul 2>&1
    exit /b 1
)
echo server is accepting connections >> "%LOGFILE%"

rem ---- 5. make sure `requests` is installed -------------------------------
echo [5/6] pip install requests >> "%LOGFILE%"
!PY! -m pip install --quiet requests >> "%LOGFILE%" 2>&1

rem ---- 6. run the regression suite -----------------------------------------
echo [6/6] running regression_test.py >> "%LOGFILE%"
echo. >> "%LOGFILE%"
!PY! "%SCRIPT_DIR%regression_test.py" --host localhost --port %PORT% ^
    --cacert "%KEYDIR%\server.crt" ^
    --client-cert "%KEYDIR%\client.crt" --client-key "%KEYDIR%\client.key" ^
    --untrusted-cert "%UNTRUSTED_KEYDIR%\client.crt" --untrusted-key "%UNTRUSTED_KEYDIR%\client.key" >> "%LOGFILE%" 2>&1
set "TESTRESULT=%errorlevel%"

echo. >> "%LOGFILE%"
echo stopping tcs.exe >> "%LOGFILE%"
taskkill /FI "WINDOWTITLE eq tcs-server*" /T /F >nul 2>&1

echo ==== done, exit code %TESTRESULT% ==== >> "%LOGFILE%"

type "%LOGFILE%"
echo.
echo Full log:        %LOGFILE%
echo Server-side log: %SERVERLOG%

exit /b %TESTRESULT%
