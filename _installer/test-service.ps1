$ErrorActionPreference = 'Stop'
$source = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'install-service.ps1') -Raw
$tokens = $null
$errors = $null
$null = [Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($forbidden in @('--host-key','--authorized-keys','--data','--generate-host-key','--verify-install','LegacyDirectory')) {
    if ($source.Contains($forbidden)) { throw "Service script still contains: $forbidden" }
}
if (-not $source.Contains("Join-Path " + '$serviceProfile' + " '.ssh'")) { throw 'Fixed service profile missing.' }
Write-Output 'PASS service installer static syntax and fixed-key-path checks; no SCM/firewall changes made.'
