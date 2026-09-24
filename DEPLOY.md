# tcs deployment

1. Install the .NET 10 runtime and Python 3 on the controlled machine.
2. Extract this archive to a deployment directory.
3. Run `powershell -ExecutionPolicy Bypass -File gen-certs.ps1 -OutDir .\keys\tcs`.
4. Start the service with `run-server.bat .\keys\tcs 10122 .\tcs-server.log`.

The generated `client.crt` and `client.key` are the client credentials for
the controlling machine. Keep the private key confidential. The service
accepts only client certificates listed in `authorized-clients.json`.

This package is framework-dependent and requires the .NET 10 runtime. The
`/v1/exec` endpoint requires Python to be available as `python`, or the
`TCS_PYTHON_EXE` environment variable can point to another interpreter.
