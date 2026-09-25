$data = [Text.Encoding]::UTF8.GetBytes("safe crypto")
$key = [Text.Encoding]::UTF8.GetBytes("0123456789ABCDEF")
$iv = [Text.Encoding]::UTF8.GetBytes("FEDCBA9876543210")

$aes = [Security.Cryptography.Aes]::Create()
$aes.Key = $key
$aes.IV = $iv

$encryptor = $aes.CreateEncryptor()
$cipher = $encryptor.TransformFinalBlock($data, 0, $data.Length)
$decryptor = $aes.CreateDecryptor()
$plain = $decryptor.TransformFinalBlock($cipher, 0, $cipher.Length)

try {
    switch -Regex ("build-123") {
        "^build-[0-9]+$" {
            Write-Output ([Text.Encoding]::UTF8.GetString($plain))
        }
    }
}
catch {
    Write-Output "unexpected error"
}
finally {
    Write-Output "crypto fixture complete"
}
