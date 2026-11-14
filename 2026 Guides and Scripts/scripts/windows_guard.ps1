# Windows PowerShell 5.1+. No account, service or domain policy changes; firewall rules are additive and prefixed TEAM-HARDEN-.
[CmdletBinding()]
param(
    [ValidateSet('Assess','Harden','Rollback','Firewall')][string]$Action = 'Assess',
    [switch]$Apply,
    [string]$Backup,
    # Topology host id for per-host firewall profiles (config/host-firewall.json).
    [string]$HostId = '',
    [string]$ProfilePath = ''
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
if ($Action -eq 'Firewall') {
    # NetSecurity is built in on Server 2019/2022 and Windows 11 (PowerShell 5.1).
    # Explicit block rules override allows: compute the IPv4 complement, block IPv6.
    if (-not $HostId) { throw 'Firewall requires -HostId from config/host-firewall.json' }
    $path = if ($ProfilePath) { $ProfilePath } else { Join-Path (Split-Path -Parent $PSScriptRoot) 'config/host-firewall.json' }
    $data = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $property = $data.PSObject.Properties[$HostId]
    if ($null -eq $property -or $property.Value.platform -ne 'windows') { throw 'Unknown Windows host profile' }
    $trusted = @($property.Value.trusted_ssh_sources)
    if ($trusted.Count -eq 0) { throw 'Empty trusted sources' }
    function Convert-CidrToRange([string]$Cidr) {
        $parts = $Cidr -split '/'
        if ($parts.Count -ne 2 -or $parts[1] -notmatch '^([0-9]|[12][0-9]|3[0-2])$') { throw 'Invalid IPv4 prefix' }
        $ip = [System.Net.IPAddress]::Parse($parts[0])
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'IPv4 trusted sources required' }
        $value = [Convert]::ToUInt64(([BitConverter]::ToString($ip.GetAddressBytes()).Replace('-','')),16)
        $size = [uint64][Math]::Pow(2, (32 - [int]$parts[1]))
        $start = $value - ($value % $size)
        [pscustomobject]@{ Start = $start; End = $start + $size - 1 }
    }
    function ToIp([uint64]$Value) {
        '{0}.{1}.{2}.{3}' -f (($Value -shr 24) -band 255), (($Value -shr 16) -band 255), (($Value -shr 8) -band 255), ($Value -band 255)
    }
    $ranges = @($trusted | ForEach-Object { Convert-CidrToRange $_ } | Sort-Object Start)
    $blocked = @()
    [uint64]$cursor = 0
    foreach ($range in $ranges) {
        if ($range.Start -gt $cursor) { $blocked += (ToIp $cursor) + '-' + (ToIp ($range.Start - 1)) }
        if (($range.End + 1) -gt $cursor) { $cursor = $range.End + 1 }
    }
    if ($cursor -le 4294967295) { $blocked += (ToIp $cursor) + '-255.255.255.255' }
    # No trusted IPv6 management networks are defined; deny new SSH over IPv6 explicitly.
    $blocked += '::/0'
    $plan = @(
        "New-NetFirewallRule -Name 'TEAM-HARDEN-SSH-ALLOW' -DisplayName 'TEAM-HARDEN-SSH-ALLOW' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress @('" + ($trusted -join "','") + "') -Profile Any",
        "New-NetFirewallRule -Name 'TEAM-HARDEN-SSH-MGMT' -DisplayName 'TEAM-HARDEN-SSH-MGMT' -Direction Inbound -Action Block -Protocol TCP -LocalPort 22 -RemoteAddress @('" + ($blocked -join "','") + "') -Profile Any"
    )
    if (-not $Apply) {
        'PLAN: console access required. Check effective GPO/firewall policy and actual operator source before applying.'
        'Back up: netsh advfirewall export C:\Secure\firewall-before.wfw (fresh protected path)'
        $plan
        "Rollback: Remove-NetFirewallRule -Name 'TEAM-HARDEN-SSH-ALLOW','TEAM-HARDEN-SSH-MGMT'"
        'Verify fresh trusted and untrusted IPv4 SSH, IPv6 denial, and scored services after application.'
        return
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated' }
    if (Get-NetFirewallRule -Name 'TEAM-HARDEN-SSH-*' -ErrorAction SilentlyContinue) { throw 'Team rules already exist; inspect before replacing' }
    if (@(Get-NetFirewallProfile | Where-Object { -not $_.Enabled }).Count) { throw 'Enable and validate firewall profiles before applying this policy' }
    if (-not $Backup -or (Test-Path -LiteralPath $Backup)) { throw 'Provide a fresh -Backup .wfw path' }
    & netsh.exe advfirewall export $Backup
    if ($LASTEXITCODE -ne 0) { throw 'Firewall backup failed' }
    try {
        foreach ($cmd in $plan) { Invoke-Expression $cmd }
    } catch {
        Remove-NetFirewallRule -Name 'TEAM-HARDEN-SSH-ALLOW','TEAM-HARDEN-SSH-MGMT' -ErrorAction SilentlyContinue
        throw
    }
    "Applied. Check effective policy: Get-NetFirewallRule -PolicyStore ActiveStore -Name 'TEAM-HARDEN-SSH-*'"
    "Rollback: Remove-NetFirewallRule -Name 'TEAM-HARDEN-SSH-ALLOW','TEAM-HARDEN-SSH-MGMT'"
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
