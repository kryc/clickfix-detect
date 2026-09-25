$name = "ClickFix"
$number = 2 + 3 * 4
$reversed = $name[-1..-8] -join ''
$binaryCharacter = [char][Convert]::ToInt32("1100110", 2)

Write-Output "name=$($name)"
Write-Output "number=$number"
Write-Output "reversed=$reversed"
Write-Output "binary character=$binaryCharacter"
