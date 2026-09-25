function Double($Value) {
    return $Value * 2
}

$values = 1..5 |
    ForEach-Object { Double $_ } |
    Where-Object { $_ -gt 5 }

$sum = 0
for ($i = 1; $i -le 5; $i++) {
    $sum += $i
}

switch ($sum) {
    15 { Write-Output "pipeline=$($values -join ',')" }
    default { Write-Output "unexpected sum" }
}

Write-Output "sum=$sum"
