$bytes = [Text.Encoding]::UTF8.GetBytes("Hello from the emulator")
$encoded = [Convert]::ToBase64String($bytes)
$decoded = [Text.Encoding]::UTF8.GetString(
    [Convert]::FromBase64String($encoded)
)

$json = "{`"name`":`"ClickFix`",`"safe`":true}"
$data = $(ConvertFrom-Json $json)
$clean = [regex]::Replace("fixture-123", "[0-9]+", "safe")

Write-Output "base64=$encoded"
Write-Output "decoded=$decoded"
Write-Output "json=$($data.name):$($data.safe)"
Write-Output "regex=$clean"
