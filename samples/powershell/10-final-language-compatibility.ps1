function Pair {
    Write-Output 1
    Write-Output 2
}

$request = @{
    Uri = "https://example.invalid/final"
    Meth = "POST"
    Body = "safe"
}

$response = Invoke-WebRequest @request

$stream = [IO.MemoryStream]::new()
$bytes = [Text.Encoding]::UTF8.GetBytes("stream-safe")
$stream.Write($bytes, 0, $bytes.Length)

[Net.ServicePointManager]::SecurityProtocol = "Tls12"

Pair | ForEach-Object { Write-Output "pair=$_" }
Write-Output "stream=$([Text.Encoding]::UTF8.GetString($stream.ToArray()))"
Write-Output "web=$($response.Content)"
Write-Output "tls=$([Net.ServicePointManager]::SecurityProtocol)"
