@echo off
"%ProgramData%\TCS\tcsd.exe" --authorized-keys "%ProgramData%\TCS\authorized_keys" --host-key "%ProgramData%\TCS\tcs_host_key" --port 10122 --data "%ProgramData%\TCS\data"
