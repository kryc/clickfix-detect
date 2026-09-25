$workspace = New-Item "$HOME\ProviderDemo" -ItemType Directory
Set-Content "$($workspace.FullName)\note.txt" "provider-safe"

$file = Get-Item "$($workspace.FullName)\note.txt"
Write-Output "$($file.Name):$($file.Extension):$($file.Length)"

Set-Item Env:CLICKFIX_PROVIDER_SAMPLE enabled
Write-Output (Get-Item Env:CLICKFIX_PROVIDER_SAMPLE).Value
Remove-Item Env:CLICKFIX_PROVIDER_SAMPLE

Push-Location $workspace.FullName
Write-Output (Get-Location).Path
Pop-Location

$temporary = New-TemporaryFile
Clear-Content $temporary.FullName
Unblock-File $temporary.FullName
Write-Output (Get-AuthenticodeSignature $temporary.FullName).Status
