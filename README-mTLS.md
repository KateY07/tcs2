# tcs — legacy mTLS HTTP mode

A small mTLS-authenticated HTTP ops endpoint: `POST /v1/exec` runs a Python
script (passed as source text, executed via argv -- never a shell string,
so there's no PowerShell quoting/encoding to fight), `POST /v1/upload`
accepts file uploads. Trust is pure certificate pinning, the same model as
SSH's `authorized_keys`: no CA, no bearer token -- a client is trusted
because its exact certificate's SHA-256 thumbprint is listed in
`authorized-clients.json`, nothing else gets in.

This has been built and run end to end (a cloud sandbox got its own .NET
10 SDK via `apt install dotnet-sdk-10.0` -- Microsoft's own install
domain is blocked there, but Ubuntu ships the SDK in its own repo) and
the full regression suite below passes against it over loopback. Real
LAN/dual-machine numbers, and IPv6 reachability specifically, still need
to be checked on your machine -- the build sandbox has no IPv6 stack at
all to verify that against.

Listening is dual-stack (`ListenAnyIP`): both IPv4 and IPv6 clients are
accepted on the same port, so link-local/ULA/GUA IPv6 addresses work the
same way LAN IPv4 addresses do. There's no size cap on `/v1/upload` (a
150MB upload was tested); the framework's stock 30MB/128MB defaults were
removed since they existed to protect a public server, not a cert-pinned
ops channel.

## Build and run

This machine already has the .NET 10 SDK, so this is framework-dependent
by design -- no `dotnet publish`, no `--self-contained`, just:

```powershell
cd D:\2\tcs
dotnet build -c Release
```

That produces `bin\Release\net10.0\tcs.exe` (plus `tcs.dll` and friends),
running against the installed .NET 10 runtime.

## Key material

`-i` points at a directory that must contain three files:

```
<keydir>\server.crt              PEM server certificate (presented to clients)
<keydir>\server.key              PEM server private key
<keydir>\authorized-clients.json JSON array of SHA-256 client-cert thumbprints
```

For a first test, generate a throwaway server + client certificate pair
with the included script (needs OpenSSL on PATH -- Git for Windows ships
one):

```powershell
.\gen-certs.ps1 -OutDir D:\keys\tcs
```

This writes `server.crt`/`server.key`/`authorized-clients.json` (already
populated with the client certificate's thumbprint) plus a `client.crt`/
`client.key` pair for testing.

For real LAN/dual-machine testing (not just `localhost`), pass every
address a client will actually connect through via `-SanList` -- a TLS
client validates the server certificate against the address it dialed,
so an address missing here fails the handshake even though the cert is
otherwise trusted:

```powershell
.\gen-certs.ps1 -OutDir D:\keys\tcs -SanList `
    "DNS:localhost","IP:127.0.0.1","IP:::1", `
    "DNS:alipc","IP:192.168.100.6","IP:fd00::60f7:4d5d:f5bf:c778"
```

## Run it

```powershell
bin\Release\net10.0\tcs.exe -i D:\keys\tcs -p 10122
```

## Try it (from anywhere with curl and the client cert/key)

```powershell
# Health check (still requires the client certificate -- mTLS is enforced
# for every request, there's no unauthenticated endpoint).
curl.exe --cacert D:\keys\tcs\server.crt `
         --cert D:\keys\tcs\client.crt --key D:\keys\tcs\client.key `
         https://localhost:10122/v1/health

# Run a Python script.
curl.exe --cacert D:\keys\tcs\server.crt `
         --cert D:\keys\tcs\client.crt --key D:\keys\tcs\client.key `
         -H "Content-Type: application/json" `
         -d '{"script":"print(1+1)","timeoutSeconds":10}' `
         https://localhost:10122/v1/exec

# Upload a file.
curl.exe --cacert D:\keys\tcs\server.crt `
         --cert D:\keys\tcs\client.crt --key D:\keys\tcs\client.key `
         -F "file=@C:\path\to\some.txt" `
         https://localhost:10122/v1/upload
```

A request from any certificate not listed in `authorized-clients.json`
fails at the TLS handshake -- it never reaches `/v1/exec` or `/v1/upload`
at all, the same way an unrecognized SSH key gets refused before a shell
is ever spawned.

## What ends up on disk next to tcs.exe

- `uploads\` -- everything received through `/v1/upload`, saved under a
  timestamp + random prefix so nothing overwrites anything else.
- `tcs-audit.log` -- one JSON line per request: timestamp, the calling
  client certificate's thumbprint, the endpoint, and for `/v1/exec` the
  full script text, exit code and duration. This is intentionally
  complete, not redacted: the point of an ops channel is that what went
  through it is fully reconstructable afterwards.

## Configuration knobs

- `TCS_PYTHON_EXE` environment variable: overrides which interpreter
  `/v1/exec` invokes (defaults to `python` resolved via PATH). Set this if
  the machine's interpreter is named `python3` or lives somewhere not on
  PATH.
- Per-request `timeoutSeconds` in the `/v1/exec` body (default 30):
  the script's process (and its whole process tree) is killed if it runs
  longer than this.

## Regression suite (security / latency / bandwidth / concurrency)

`regression_test.py` exercises the running server end to end. It was
written and reviewed but **not executed anywhere** -- there's no .NET SDK
and no reachable client in the environment that wrote it, so it needs to
be run against a live `tcs.exe` on a machine that can actually connect to
it (the same box, or another one on the LAN).

```powershell
pip install requests

# Trusted identity (the one that will be allowed in):
.\gen-certs.ps1 -OutDir D:\keys\tcs
# A second, deliberately UNTRUSTED identity for the negative security test
# -- its client cert is never added to D:\keys\tcs\authorized-clients.json:
.\gen-certs.ps1 -OutDir D:\keys\tcs-untrusted

bin\Release\net10.0\tcs.exe -i D:\keys\tcs -p 10122
```

In another shell:

```powershell
python regression_test.py --host localhost --port 10122 `
    --cacert D:\keys\tcs\server.crt `
    --client-cert D:\keys\tcs\client.crt --client-key D:\keys\tcs\client.key `
    --untrusted-cert D:\keys\tcs-untrusted\client.crt --untrusted-key D:\keys\tcs-untrusted\client.key
```

What it checks:

- **Security**: no client cert is refused at the TLS handshake; an
  untrusted (unpinned) client cert is refused the same way; a pinned
  client cert is accepted; plaintext HTTP on the same port is refused;
  `/v1/upload` strips directory components from filenames (no path
  traversal out of `uploads\`); `/v1/exec` treats the script body as
  Python source, never a shell string.
- **Latency**: p50/p95/p99 for `/v1/health` over 50 requests (default),
  plus `/v1/exec` round-trip time including process spawn.
- **Bandwidth**: `/v1/upload` throughput at 1/10/50 MB (configurable via
  `--bandwidth-sizes-mb`).
- **Concurrency**: fires 16 (configurable via `--concurrency`)
  simultaneous `/v1/exec` calls that each sleep 2s, confirms all return
  correct, non-cross-talked output, and confirms wall time is close to
  2s rather than `16 * 2s` -- i.e. that there really is no concurrency
  cap. Also confirms a per-request `timeoutSeconds` is still honored
  while other requests are in flight.

It exits non-zero and lists every failing check if anything doesn't pass.
Run it, then send me the output (or just the failing lines) and I'll fix
whatever's broken.

## Things intentionally left out of this first version

- No concurrency cap -- Kestrel's own async pipeline handles concurrent
  requests; nothing here throttles how many `/v1/exec` calls run at once.
  Add a `SemaphoreSlim` around the exec handler if that turns out to
  matter in practice.
- No log rotation on `tcs-audit.log` -- it grows unbounded. Fine for a
  test box, worth revisiting before this runs unattended for a long time.
- No certificate expiry/rotation story -- `gen-certs.ps1` mints 10-year
  certificates for convenience; a real deployment should think about
  renewal the same way it would for any other TLS certificate.
