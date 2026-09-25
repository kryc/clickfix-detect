function Double($Value) { return $Value * 2 }
$values = 1..5 | ForEach-Object { Double $_ }
if ($values.Count -gt 0) { Write-Output ($values -join ',') }
