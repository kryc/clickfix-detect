$encoded = "SGVsbG8="
$decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
Write-Output $decoded
