$ErrorActionPreference='Stop'
. "$PSScriptRoot\set-user-path.ps1"
$target=Join-Path $env:LOCALAPPDATA 'TCS'
$cases=@(
    @{ Before=''; Expected=$target },
    @{ Before='C:\Tools'; Expected="C:\Tools;$target" },
    @{ Before="C:\Tools;$target"; Expected="C:\Tools;$target" },
    @{ Before="C:\Tools;$target\;$($target.ToUpperInvariant());D:\Tools"; Expected="C:\Tools;$target\;D:\Tools" },
    @{ Before='%LOCALAPPDATA%\TCS;C:\Tools'; Expected='%LOCALAPPDATA%\TCS;C:\Tools' },
    @{ Before="`"$target`";C:\Tools;$target"; Expected="`"$target`";C:\Tools" },
    @{ Before='C:\Tools;'; Expected="C:\Tools;$target" },
    @{ Before='C:\Tools;;D:\Tools'; Expected="C:\Tools;;D:\Tools;$target" }
)
foreach($case in $cases) {
    $actual=Get-TcsUserPath $case.Before $target
    if($actual -cne $case.Expected) { throw "Expected [$($case.Expected)] but got [$actual]" }
    if((Get-TcsUserPath $actual $target) -cne $actual) { throw 'Repeated install changed PATH again' }
}
Write-Host "PASS: $($cases.Count) PATH cases and repeated-install idempotency"
