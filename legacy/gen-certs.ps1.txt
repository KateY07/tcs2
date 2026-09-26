<#
.SYNOPSIS
  Generates a self-signed server certificate and one client certificate for
  tcs's mTLS setup, and writes authorized-clients.json pre-populated with
  the client certificate's SHA-256 thumbprint.

.DESCRIPTION
  This is dev/test tooling, not a CA. Each certificate is self-signed and
  trust is established purely by pinning: the server trusts exactly the
  client certificate(s) listed in authorized-clients.json (by thumbprint),
  the same way SSH trusts exactly the keys listed in authorized_keys.

  Requires OpenSSL on PATH (Git for Windows ships one at
  "C:\Program Files\Git\usr\bin\openssl.exe" if it isn't already on PATH).

.EXAMPLE
  .\gen-certs.ps1 -OutDir D:\keys\tcs
#>
param(
    [string]$OutDir = ".\keys",
    [string]$CommonName = "tcs",
    # Every hostname/IP a client might connect through -- localhost/127.0.0.1
    # by default, but for real LAN/dual-machine testing add every address in
    # play (e.g. "DNS:myhost,IP:192.168.1.10,IP:fd00::1,IP:fe80::1%5"). A
    # client validates the server cert's SAN against whatever address it
    # dialed, so an address missing here fails the handshake with a
    # hostname-mismatch error even though the cert is otherwise trusted.
    [string[]]$SanList = @("DNS:localhost", "IP:127.0.0.1", "IP:::1")
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    throw "openssl not found on PATH. Git for Windows ships one under <git-install>\usr\bin\openssl.exe."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$serverKey = Join-Path $OutDir "server.key"
$serverCrt = Join-Path $OutDir "server.crt"
$clientKey = Join-Path $OutDir "client.key"
$clientCrt = Join-Path $OutDir "client.crt"

$sanExt = "subjectAltName=" + ($SanList -join ",")

Write-Host "Generating server certificate ($serverCrt) ..."
# -addext basicConstraints/keyUsage matter: without CA:TRUE, OpenSSL 3.x's
# (and therefore most modern TLS clients') strict chain validation refuses
# to treat this self-signed cert as a trust anchor at all, even when it's
# the exact file handed to --cacert / verify=. Without a subjectAltName,
# clients that enforce SAN-only hostname checking (Python's ssl module,
# modern browsers, curl with recent OpenSSL) refuse to match it against
# any hostname regardless of the CN. Both failures look identical to "the
# server rejected my connection" from the client side, which makes them
# easy to misdiagnose as a tcs bug instead of a cert-generation gap.
& openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes `
    -keyout $serverKey -out $serverCrt `
    -subj "/CN=$CommonName-server" `
    -addext "basicConstraints=critical,CA:TRUE" `
    -addext "keyUsage=critical,digitalSignature,keyCertSign" `
    -addext $sanExt
if ($LASTEXITCODE -ne 0) { throw "openssl failed generating the server certificate" }

Write-Host "Generating client certificate ($clientCrt) ..."
& openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes `
    -keyout $clientKey -out $clientCrt `
    -subj "/CN=$CommonName-client"
if ($LASTEXITCODE -ne 0) { throw "openssl failed generating the client certificate" }

$fingerprintLine = & openssl x509 -in $clientCrt -noout -fingerprint -sha256
if ($LASTEXITCODE -ne 0) { throw "openssl failed reading the client certificate fingerprint" }

# $fingerprintLine looks like: "sha256 Fingerprint=AA:BB:CC:...:FF"
$thumbprint = ($fingerprintLine -split "=")[1] -replace ":", ""

# Built by hand rather than ConvertTo-Json, whose single-element-array
# behaviour differs across PowerShell versions.
$authorizedClientsPath = Join-Path $OutDir "authorized-clients.json"
"[`"$thumbprint`"]" | Set-Content -Encoding utf8 $authorizedClientsPath

Write-Host ""
Write-Host "Done. $OutDir now contains:"
Write-Host "  server.crt / server.key      -- pass this directory as tcs.exe -i $OutDir"
Write-Host "  client.crt / client.key      -- use these with curl/your test client"
Write-Host "  authorized-clients.json      -- pre-populated with the client's SHA-256 thumbprint"
Write-Host ""
Write-Host "Client certificate SHA-256 thumbprint: $thumbprint"
