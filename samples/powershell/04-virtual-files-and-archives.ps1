Set-Content -Path "C:\Temp\safe.txt" -Value "archive demo"
Compress-Archive `
    -Path "C:\Temp\safe.txt" `
    -DestinationPath "C:\Temp\safe.zip"
Expand-Archive `
    -Path "C:\Temp\safe.zip" `
    -DestinationPath "C:\Restored"

$hash = $(Get-FileHash -Path "C:\Restored\safe.txt" -Algorithm SHA256)
Write-Output "restored=$(Get-Content -Raw 'C:\Restored\safe.txt')"
Write-Output "hash algorithm=$($hash.Algorithm)"
