# Run on Windows PowerShell 5.1: powershell -NoProfile -File tests/test_windows_guard.ps1
# Plan generation only: no firewall mutation and no elevation required.
$ErrorActionPreference = 'Stop'
$script = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/windows_guard.ps1'
$plan = . $script -Action Firewall -HostId 2022-ad
foreach ($case in @(
    @('172.20.240.0/24', '172.20.240.0', '172.20.240.255'),
    @('172.17.0.0/24', '172.17.0.0', '172.17.0.255'),
    @('0.0.0.0/0', '0.0.0.0', '255.255.255.255'),
    @('255.255.255.255/32', '255.255.255.255', '255.255.255.255')
)) {
    $range = Convert-CidrToRange $case[0]
    if ((ToIp $range.Start) -ne $case[1] -or (ToIp $range.End) -ne $case[2]) { throw "Bad conversion: $($case[0])" }
}
$block = @($plan | Where-Object { $_ -match '^New-NetFirewallRule.*-Action Block' })
foreach ($expected in @('0.0.0.0-172.16.255.255','172.17.1.0-172.20.239.255','172.20.241.0-255.255.255.255','::/0')) {
    if (-not $block[0].Contains($expected)) { throw "Missing complement range: $expected" }
}
# Parse commands and check named parameters against installed NetSecurity cmdlet metadata.
$metadata = Get-Command New-NetFirewallRule
foreach ($line in @($plan | Where-Object { $_ -match '^New-NetFirewallRule ' })) {
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($line, [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Generated command does not parse' }
    foreach ($parameter in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.CommandParameterAst]}, $true)) {
        if (-not $metadata.Parameters.ContainsKey($parameter.ParameterName)) { throw "Unsupported parameter: $($parameter.ParameterName)" }
    }
}
$workstationPlan = . $script -Action Firewall -HostId windows11-workstation
$allow = @($workstationPlan | Where-Object { $_ -match '^New-NetFirewallRule.*-Action Allow' })
if ($allow[0] -match '172.17.0.0/24') { throw 'Workstation profile incorrectly includes Kali segment' }
if ($allow[0] -notmatch '172.20.240.0/24') { throw 'Workstation trusted profile missing' }
'Target Windows plan checks passed; still test effective policy and real connections.'
