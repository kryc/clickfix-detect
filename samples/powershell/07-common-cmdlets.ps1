$csv = "Name,Value`nbeta,2`nalpha,1`nalpha,1"
$rows = $(ConvertFrom-Csv $csv)

$rows |
    Sort-Object Name -Unique |
    ForEach-Object { Write-Output "$($_.Name)=$($_.Value)" }

"first`nsecond-123`nthird-456" |
    Select-String -Pattern "[0-9]+" |
    Select-Object -ExpandProperty Line |
    ForEach-Object { Write-Output "match=$_" }

$computer = Get-ComputerInfo
$os = Get-CimInstance Win32_OperatingSystem
Write-Output "host=$($computer.CsName) os=$($os.OSArchitecture)"

$shell = New-Object -ComObject WScript.Shell
$expanded = $shell.ExpandEnvironmentStrings("%TEMP%\safe.txt")
Write-Output "expanded=$expanded"
