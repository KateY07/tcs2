param([string]$Version='2026.09.24.2')
$ErrorActionPreference='Stop'
if (-not $PSBoundParameters.ContainsKey('Version')) { $Version='2026.09.26.6' }
if ($Version -notmatch '^[A-Za-z0-9._-]+$') { throw 'Invalid version' }
$repo=Split-Path $PSScriptRoot -Parent
$release="D:\pub\tcs\$Version.zip"
if ((Test-Path -LiteralPath $release) -or (Test-Path -LiteralPath ($release+'.sha256'))) { throw "Release already exists: $release" }
$payload=Join-Path $repo "_package\tcs-manual-$Version"
$installer=$payload+'.exe'
if ((Test-Path -LiteralPath $payload) -or (Test-Path -LiteralPath $installer)) { throw 'Build destination exists' }
$null=New-Item -ItemType Directory -Path $payload
$binary=Join-Path $repo '_package\fixed-build\tcs.exe'
Copy-Item -LiteralPath $binary -Destination (Join-Path $payload 'tcs.exe')
Copy-Item -LiteralPath $binary -Destination (Join-Path $payload 'tcsd.exe')
Copy-Item -LiteralPath (Join-Path $repo 'README.md') -Destination $payload
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install-user.bat') -Destination (Join-Path $payload 'install.bat')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'set-user-path.ps1') -Destination $payload
$names=@(Get-ChildItem -LiteralPath $payload -Force | Select-Object -ExpandProperty Name)
if ($names.Count -ne 5 -or @($names | Where-Object { $_ -notin @('tcs.exe','tcsd.exe','README.md','install.bat','set-user-path.ps1') }).Count) { throw 'Unexpected package contents' }
& dotnet (Join-Path $repo '_package\onesetup.dll') $payload -o $installer
if ($LASTEXITCODE) { throw 'OneSetup packaging failed' }
$null=New-Item -ItemType Directory -Path (Split-Path $release -Parent) -Force
Compress-Archive -LiteralPath $installer,(Join-Path $repo 'README.md') -DestinationPath $release
$hash=(Get-FileHash -LiteralPath $release -Algorithm SHA256).Hash.ToLowerInvariant()
$bytes=[Text.Encoding]::ASCII.GetBytes("$hash *$Version.zip`r`n")
$stream=[IO.File]::Open($release+'.sha256',[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
Write-Output $installer
Write-Output $release
Write-Output $hash
