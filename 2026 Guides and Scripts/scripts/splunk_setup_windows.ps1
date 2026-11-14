# splunk_setup_windows.ps1 — Windows-only equivalent of scripts/splunk_setup.py
# for the three Windows hosts (2022-ad, 2019-mssql, windows11-workstation), which
# do not have Python installed. Generates the Universal Forwarder outputs.conf and
# inputs.conf directly on the host using Windows PowerShell 5.1+ (no dependencies).
#
# It generates configuration files only: it does not install the forwarder,
# change services, open ports, or touch firewall/NAT rules. Deploying the files
# still follows docs/splunk-data-sources.md "Windows forwarder" and the event
# change gate.
#
# Usage (in PowerShell on the target host or any Windows machine):
#   # Preview the files without writing anything:
#   .\splunk_setup_windows.ps1 -Receiver <splunk-ip>
#
#   # Write outputs.conf + inputs.conf into a staging directory:
#   .\splunk_setup_windows.ps1 -Receiver <splunk-ip> -OutDir .\generated-2022ad
#
#   # Add optional channels (Directory Service on the DC, PowerShell/Defender
#   # where the channel exists — confirm with Get-WinEvent -ListLog first).
#   # Pass all extra channels as ONE array-valued argument; the core channels
#   # (Security, System, Application) are always kept:
#   .\splunk_setup_windows.ps1 -Receiver <splunk-ip> -OutDir .\generated-2022ad `
#       -Channel @('Directory Service', 'Microsoft-Windows-PowerShell/Operational')
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Receiver,
    [int]$Port = 9997,
    [string]$Index = 'team_security',
    [ValidateSet('2022-ad', '2019-mssql', 'windows11-workstation')][string]$HostId = 'windows11-workstation',
    [ValidateSet('operational', 'sysmon', 'dc')][string[]]$OptionalSource = @(),
    [string[]]$InputPath = @(),
    [string]$OutDir,
    [string[]]$Channel = @()
)
$ErrorActionPreference = 'Stop'

# Core channels are always collected; -Channel appends optional ones.
$channels = @('Security', 'System', 'Application') + $Channel

$profiles = @{
    operational = @('Microsoft-Windows-PowerShell/Operational',
        'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-TaskScheduler/Operational',
        'Microsoft-Windows-WMI-Activity/Operational')
    sysmon = @('Microsoft-Windows-Sysmon/Operational')
    dc = @('Directory Service', 'DNS Server', 'DFS Replication')
}
foreach ($option in $OptionalSource) {
    if ($option -eq 'dc' -and $HostId -ne '2022-ad') { throw 'dc sources require 2022-ad' }
    $channels += $profiles[$option]
}
if ($Receiver -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Receiver must be a bare IP or hostname' }
if ($Port -lt 1 -or $Port -gt 65535) { throw "Port out of range: $Port" }
$index = if ($Index -eq '') { 'main' } else { $Index }
if ($index -notmatch '^[A-Za-z0-9_.-]+$') { throw 'Unsafe index' }
Write-Host 'Optional channels require Get-WinEvent -ListLog verification, read permission and enabled channels. Audit policy, PowerShell logging and Sysmon installation are separate prerequisites.'

# outputs.conf — identical content to scripts/splunk_setup.py windows_forwarder().
$outputs = '[tcpout]' + "`n" +
    'defaultGroup = team_indexer' + "`n`n" +
    '[tcpout:team_indexer]' + "`n" +
    "server = ${Receiver}:$Port"

# inputs.conf — one WinEventLog stanza per requested channel.
$inputs = ''
foreach ($chan in ($channels | Select-Object -Unique)) {
    if (-not $chan -or $chan -match '[\x00-\x1f\x7f\[\]]') { throw 'Unsafe channel' }
    $inputs += "[WinEventLog://$chan`]" + "`n" +
        'disabled = 0' + "`n" +
        "index = $index" + "`n" +
        'renderXml = true' + "`n`n"
}

# Discovered paths only: e.g. C:\...\ERRORLOG:sql_error or SQLAGENT.OUT:sql_agent.
# Split at the final colon, preserving the drive prefix. No Python required.
$seen = @{}
foreach ($spec in $InputPath) {
    if ($spec -notmatch '^([A-Za-z]:[\\/].*):([A-Za-z0-9_.:-]+)$') { throw 'Use absolute PATH:SOURCETYPE' }
    $logPath = $Matches[1]; $sourceType = $Matches[2]
    if ($logPath -match '[\x00-\x1f\x7f\[\]]') { throw 'Unsafe path' }
    if ($seen.ContainsKey($logPath)) {
        if ($seen[$logPath] -ne $sourceType) { throw 'Conflicting sourcetypes' }
        continue
    }
    $seen[$logPath] = $sourceType
    $inputs += "[monitor://$logPath`]`ndisabled = 0`nindex = $index`nsourcetype = $sourceType`n`n"
}

function Show-Files([string]$Outputs, [string]$Inputs) {
    Write-Host '===== outputs.conf ====='
    Write-Host $Outputs
    Write-Host '===== inputs.conf ====='
    Write-Host $Inputs
}

if (-not $OutDir) {
    # Plan mode: preview only, write nothing.
    Show-Files $outputs $inputs
    Write-Host ''
    Write-Host 'PLAN: no files written. Re-run with -OutDir to generate, then deploy per'
    Write-Host 'docs/splunk-data-sources.md "Windows forwarder" Step 2 (copy into the'
    Write-Host 'team_collection app local dir and restart the forwarder service).'
    return
}

# Reserve the directory without clobbering an existing one silently.
if (Test-Path -LiteralPath $OutDir) {
    $existing = @(Get-ChildItem -LiteralPath $OutDir -File -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        throw "Refusing to overwrite non-empty OutDir '$OutDir' (contains $($existing.Count) file(s)); remove it or choose another path"
    }
} else {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
}

# Write with 0600-equivalent permissions: deny everyone, keep owner access.
foreach ($name in @('outputs.conf', 'inputs.conf')) {
    $content = if ($name -eq 'outputs.conf') { $outputs } else { $inputs }
    $path = Join-Path $OutDir $name
    [IO.File]::WriteAllText($path, $content)
    # Tighten ACL: only the current user (and Administrators via inheritance off).
    $acl = Get-Acl -LiteralPath $path
    $acl.SetAccessRuleProtection($true, $false)
    $me = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($me, 'FullControl', 'Allow')
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $path -AclObject $acl
}

Show-Files $outputs $inputs
Write-Host ''
Write-Host "Wrote 2 file(s) to $OutDir"
Write-Host 'Next steps (elevated PowerShell, per docs/splunk-data-sources.md "Windows forwarder"):'
Write-Host '  $d = "C:\Program Files\SplunkUniversalForwarder\etc\apps\team_collection\local"'
Write-Host '  New-Item -ItemType Directory -Force -Path $d | Out-Null'
Write-Host "  Copy-Item '$(Join-Path $OutDir 'outputs.conf')', '$(Join-Path $OutDir 'inputs.conf')' -Destination `$d -Force"
Write-Host '  Restart-Service SplunkForwarder'
