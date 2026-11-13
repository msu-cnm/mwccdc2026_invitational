# Windows PowerShell 5.1+. No account, firewall, service or domain policy changes.
[CmdletBinding()]
param(
    [ValidateSet('Assess','Harden','Rollback')][string]$Action = 'Assess',
    [switch]$Apply,
    [string]$Backup
)
$ErrorActionPreference = 'Stop'
function Audit([string[]]$Arguments) {
    & auditpol.exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed ($LASTEXITCODE)" }
}
if ($Action -eq 'Assess') {
    if ($Apply -or $Backup) { throw 'Assess does not accept Apply or Backup' }
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4672,4697,4698,4720,4728,4732; StartTime=(Get-Date).AddMinutes(-15)} -MaxEvents 500 -ErrorAction SilentlyContinue
    [ordered]@{
        TimeUTC = (Get-Date).ToUniversalTime().ToString('o')
        Services = @(Get-Service | Select-Object Name,Status,StartType)
        TCP = @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess)
        UDP = @(Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess)
        Firewall = @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction)
        Tasks = @(Get-ScheduledTask | Select-Object TaskPath,TaskName,State)
        AuthAndPersistenceEventCounts = @($events | Group-Object Id | Select-Object Name,Count)
        Resources = @(Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize,LastBootUpTime)
        Disks = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,FreeSpace,Size)
    } | ConvertTo-Json -Depth 5
    return
}
# Language-independent subcategory GUID: Logon. Preserve other audit subcategories.
$logon = '{0CCE9215-69AE-11D9-BED3-505054503030}'
if ($Action -eq 'Rollback' -and (-not $Backup -or -not (Test-Path -LiteralPath $Backup -PathType Leaf))) { throw 'Existing auditpol backup required' }
if (-not $Apply) {
    if ($Action -eq 'Harden') { "PLAN: enable success/failure Logon auditing ($logon); no services or ports changed" }
    else { "PLAN: restore full audit policy from $Backup" }
    return
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated' }
if ($Action -eq 'Rollback') {
    Audit -Arguments @('/restore',"/file:$Backup")
    return
}
if (-not $Backup -or (Test-Path -LiteralPath $Backup)) { throw 'Provide a fresh backup path; never overwrite original audit policy' }
# Reserve the path without overwriting a previous backup.
$file = [IO.File]::Open($Backup,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
$file.Dispose()
try {
    Audit -Arguments @('/backup',"/file:$Backup")
    Audit -Arguments @('/set',"/subcategory:$logon",'/success:enable','/failure:enable')
    Audit -Arguments @('/get',"/subcategory:$logon")
} catch {
    # Restore only if auditpol produced a usable backup.
    if ((Get-Item -LiteralPath $Backup).Length -gt 0) { Audit -Arguments @('/restore',"/file:$Backup") }
    throw
}
