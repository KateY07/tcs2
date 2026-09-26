param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9._-]+$')][string]$Version)
$ErrorActionPreference = 'Stop'
$destination = 'D:\pub\tcs'
$archive = Join-Path $destination ($Version+'.zip')
$checksum = $archive+'.sha256'
if ((Test-Path -LiteralPath $archive) -or (Test-Path -LiteralPath $checksum)) { throw "Release already exists: $archive" }
$repo = Split-Path $PSScriptRoot -Parent
$installer = Join-Path $repo ("_package\tcsd-service-$Version.exe")
$readme = Join-Path $PSScriptRoot '系统服务安装说明.md'
if (-not (Test-Path -LiteralPath $installer)) { throw "Installer missing: $installer" }
$null = New-Item -ItemType Directory -Path $destination -Force
Compress-Archive -LiteralPath $installer,$readme -DestinationPath $archive -CompressionLevel Optimal
$hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
$bytes = [Text.Encoding]::ASCII.GetBytes("$hash *$Version.zip`r`n")
$stream = [IO.File]::Open($checksum,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
Write-Output $archive
Write-Output $checksum
Write-Output $hash
