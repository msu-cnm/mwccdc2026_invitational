$webhookUrl = "https://webhook.site/YOUR-UNIQUE-ID"
$test = "test connection"
try {
    $response = Invoke-RestMethod -Uri $webhookUrl -Method Post -Body $test -ContentType "text/plain" -Verbose
    Write-Host "Success"
    Write-Host $response
} catch {
    Write-Host "Error: $_"
    Write-Host $_.Exception.Message
}
