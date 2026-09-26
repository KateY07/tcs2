param(
    [string]$ServiceName = 'tcsd',
    [ValidateRange(1,65535)][int]$Port = 10122,
    [string]$PythonPath = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($ServiceName -notmatch '^[A-Za-z][A-Za-z0-9_]{0,63}$') { throw 'Invalid service name' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Service installation requires an administrator. Manual installation does not.'
}
# LocalSystem is the service account; these are its fixed profile locations.
$serviceProfile = Join-Path $env:SystemRoot 'System32\config\systemprofile'
$sshDirectory = Join-Path $serviceProfile '.ssh'
$hostKey = Join-Path $sshDirectory 'tcs_host_key'
$authorized = Join-Path $sshDirectory 'authorized_keys'
$data = Join-Path $serviceProfile 'AppData\Local\TCS\data'
$installRoot = Join-Path $env:ProgramData 'TCS'
$exe = Join-Path $installRoot 'tcsd.exe'
$payload = Join-Path $PSScriptRoot 'tcsd.exe'
foreach ($required in @($hostKey,$authorized,$payload)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required file missing: $required. Prepare the service account's fixed .ssh identity and authorizations first. Nothing has been installed; keys are never generated or copied."
    }
}
# Derive only in memory; no .pub requirement, no key creation or modification.
$keyProbe = New-Object Diagnostics.Process
$keyProbe.StartInfo = New-Object Diagnostics.ProcessStartInfo
$keyProbe.StartInfo.FileName = 'ssh-keygen.exe'
$keyProbe.StartInfo.Arguments = '-y -P "" -f "{0}"' -f $hostKey
$keyProbe.StartInfo.UseShellExecute = $false
$keyProbe.StartInfo.CreateNoWindow = $true
$keyProbe.StartInfo.RedirectStandardOutput = $true
$keyProbe.StartInfo.RedirectStandardError = $true
try {
    $null = $keyProbe.Start()
    $publicTask = $keyProbe.StandardOutput.ReadToEndAsync()
    $errorTask = $keyProbe.StandardError.ReadToEndAsync()
    if (-not $keyProbe.WaitForExit(15000)) {
        $keyProbe.Kill()
        throw 'Private-key validation timed out; nothing has been installed.'
    }
    if ($keyProbe.ExitCode -ne 0) { throw ('Invalid service private key: ' + $errorTask.Result) }
    if (-not $publicTask.Result) { throw 'No public key could be derived from the service private key.' }
} finally { $keyProbe.Dispose() }
if (-not ([IO.File]::ReadAllText($authorized).Trim())) { throw 'The fixed authorized_keys file is empty.' }
if (-not $PythonPath) {
    $PythonPath = (Get-Command python.exe -ErrorAction Stop).Source
}
$PythonPath = (Get-Item -LiteralPath $PythonPath -ErrorAction Stop).FullName
$existing = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($existing -and $existing.PathName -notlike "*$exe*") { throw 'Service name belongs to another installation.' }
foreach ($listener in @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) {
    if (-not $existing -or $listener.OwningProcess -ne $existing.ProcessId) {
        throw "TCP $Port is occupied by an unrelated process. Stop it explicitly before installation."
    }
}
$null = New-Item -ItemType Directory -Path $installRoot -Force
if ((Get-Item -LiteralPath $installRoot).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Installation directory cannot be a reparse point.' }
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
        (New-Object Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
Set-Acl -LiteralPath $installRoot -AclObject $acl
$transcriptStarted = $false
try {
    Start-Transcript -Path (Join-Path $installRoot 'install.log') -Append | Out-Host
    $transcriptStarted = $true
    if ($existing) {
        $service = Get-Service -Name $ServiceName
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $ServiceName
            $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
        }
    }
    if (Test-Path -LiteralPath $exe) {
        Copy-Item -LiteralPath $exe -Destination ($exe+'.'+[guid]::NewGuid().ToString('N')+'.bak')
    }
    Copy-Item -LiteralPath $payload -Destination $exe -Force
    $binaryPath = '"{0}" --service --service-name "{1}" --port {2} --python "{3}"' -f $exe,$ServiceName,$Port,$PythonPath
    if ($existing) {
        $changed = Invoke-CimMethod -InputObject $existing -MethodName Change -Arguments @{PathName=$binaryPath;StartMode='Automatic';StartName='LocalSystem'}
        if ($changed.ReturnValue -ne 0) { throw "Service configuration failed: $($changed.ReturnValue)" }
    } else {
        New-Service -Name $ServiceName -BinaryPathName $binaryPath -DisplayName "TCS Controlled Endpoint ($ServiceName)" -StartupType Automatic | Out-Host
    }
    & sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000
    if ($LASTEXITCODE -ne 0) { throw 'Service recovery configuration failed.' }
    $ruleName = "TCS-$ServiceName-TCP-$Port"
    $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($rule) {
        $rule | Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort $Port -Program $exe | Out-Host
    } else {
        New-NetFirewallRule -Name $ruleName -DisplayName "TCS $ServiceName TCP $Port" -Direction Inbound -Action Allow -Profile Any -Protocol TCP -LocalPort $Port -Program $exe | Out-Host
    }
    Start-Service -Name $ServiceName
    $ready = $false
    for ($i=0; $i -lt 30; $i++) {
        $running = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
        $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
        if ($running.State -eq 'Running' -and $running.ProcessId -gt 0 -and
            @($listeners | Where-Object { $_.OwningProcess -eq $running.ProcessId -and $_.LocalAddress -eq '::' }).Count) {
            $ready = $true
            break
        }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw "Service did not start listening. See $data\service.log" }
    Write-Host "Service installed and listening. Fixed identity: $hostKey"
    Write-Host "Service log: $data\service.log"
    Write-Host 'Authenticated connection, Python execution and upload must be tested separately from the controller.'
} catch {
    Write-Host "INSTALLATION FAILED: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace
    throw
} finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Host }
}
