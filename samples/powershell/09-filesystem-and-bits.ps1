$root = "C:\Users\analysis\SafeFixture"
New-Item $root -ItemType Directory
New-Item "$root\Nested" -ItemType Directory

Set-Content "$root\one.txt" "first" -Encoding UTF8 -NoNewline
Add-Content "$root\one.txt" "|second" -Encoding UTF8 -NoNewline
Set-Content "$root\Nested\two.log" "ignored" -NoNewline

Get-ChildItem $root -Recurse -File -Include "*.txt" |
    ForEach-Object { Write-Output "file=$($_.Name)" }

$job = Start-BitsTransfer `
    -Source "https://example.invalid/safe-fixture" `
    -Destination "$root\download.txt" `
    -DisplayName "SafeFixture" `
    -Asynchronous

Write-Output "bits=$($job.JobState)"
Remove-BitsTransfer -BitsJob $job
