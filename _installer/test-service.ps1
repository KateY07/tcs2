param([Parameter(Mandatory=$true)][string]$Fixture, [Parameter(Mandatory=$true)][string]$PythonPath)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$serviceName = 'TcsInstallerValidation'
$port = 19122
$root = Join-Path $Fixture 'installed'
$legacy = Join-Path $Fixture 'legacy'
$report = Join-Path $Fixture 'verification.log'
$utf8 = New-Object Text.UTF8Encoding($true)
$owned = $false
$passed = $false
Start-Transcript -Path $report | Out-Host
try {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Validation service already exists; refusing to alter it' }
    if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) { throw 'Validation port is already occupied' }
    if (Test-Path -LiteralPath $root) { throw 'Validation install directory already exists; use a new fixture' }
    $null = New-Item -ItemType Directory -Path $root,$legacy
    $exe = Join-Path $Fixture 'tcsd.exe'
    & $exe --generate-host-key (Join-Path $legacy 'tcs_host_key')
    if ($LASTEXITCODE) { throw 'Legacy key generation failed' }
    & $exe --generate-host-key (Join-Path $root 'tcs_host_key')
    if ($LASTEXITCODE) { throw 'Stale key generation failed' }
    $expectedKey = [IO.File]::ReadAllText((Join-Path $legacy 'tcs_host_key.pub'))
    $owned = $true
    for ($attempt=1; $attempt -le 2; $attempt++) {
        & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Fixture 'install-service.ps1') -InstallRoot $root -ServiceName $serviceName -Port $port -LegacyDirectory $legacy -PythonPath $PythonPath
        if ($LASTEXITCODE -ne 0) { throw "Installer attempt $attempt failed with $LASTEXITCODE" }
        $actualKey = [IO.File]::ReadAllText((Join-Path $root 'tcs_host_key.pub'))
        if ($actualKey -ne $expectedKey) { throw 'Trusted legacy host identity changed' }
        $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
        if ($service.State -ne 'Running' -or $service.StartMode -ne 'Auto' -or $service.StartName -ne 'LocalSystem') { throw 'Incorrect service configuration' }
        $auth = [IO.File]::ReadAllText((Join-Path $root 'authorized_keys')).Trim()
        if ($auth -ne [IO.File]::ReadAllText((Join-Path $Fixture 'controller.pub')).Trim()) { throw 'Temporary authorization was not revoked' }
        if (@(Get-ChildItem -LiteralPath $root -Filter 'installation-check-*').Count) { throw 'Temporary private keys were not removed' }
        foreach ($path in @($root,(Join-Path $root 'tcs_host_key'),(Join-Path $root 'authorized_keys'))) {
            foreach ($entry in (Get-Acl -LiteralPath $path).Access) {
                $sid = $entry.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                if ($sid -notin @('S-1-5-18','S-1-5-32-544')) { throw "Unexpected ACL on $path : $sid" }
            }
        }
        Write-Host "PASS install attempt $attempt : service, identity preservation, temporary-key revocation and private ACLs"
    }
    & sc.exe qfailure $serviceName
    if ($LASTEXITCODE) { throw 'Unable to verify recovery configuration' }
    $passed = $true
} catch {
    Write-Host "VALIDATION FAILED: $_"
    Write-Host $_.ScriptStackTrace
} finally {
    if ($owned) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                if ($service.Status -ne 'Stopped') { Stop-Service -Name $serviceName; $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
                & sc.exe delete $serviceName
                if ($LASTEXITCODE) { throw 'Test service cleanup failed' }
            }
            Get-NetFirewallRule -Name "TCS-$serviceName-TCP-$port" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        } catch { Write-Host "CLEANUP FAILED: $_"; $passed=$false }
    }
    Stop-Transcript | Out-Host
    [IO.File]::WriteAllText((Join-Path $Fixture 'result.txt'), $(if ($passed) { 'PASS' } else { 'FAIL' }),$utf8)
}
if (-not $passed) { exit 1 }
