@echo off
setlocal
cd /d "%~dp0"
dotnet publish tcs.csproj -c Release -o _package\fixed-build
if errorlevel 1 exit /b 1
dotnet build tests\TransportHarness.csproj -c Release -o _package\test-harness
if errorlevel 1 exit /b 1
"_package\test-harness\tcs-test.exe" --audit-production "bin\Release\net10.0\win-x64\tcs.dll"
if errorlevel 1 exit /b 1
python deployment_regression_test.py _package\fixed-build\tcs.exe _package\test-harness\tcs-test.exe
if errorlevel 1 exit /b 1
python pairing_regression_test.py _package\test-harness\tcs-test.exe
if errorlevel 1 exit /b 1
python crash_regression_test.py _package\test-harness\tcs-test.exe
exit /b %errorlevel%
