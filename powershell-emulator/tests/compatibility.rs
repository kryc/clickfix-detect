use emulator_core::{AnalysisLimits, EventKind, NetworkResponse, VirtualHost};
use powershell_emulator::PowerShellEmulator;
use std::collections::BTreeMap;

fn emulate(script: &str) -> (Vec<String>, VirtualHost) {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    let result = emulator.emulate(script, &mut host, 0).unwrap();
    (result.stdout, host)
}

#[test]
fn evaluates_arithmetic_strings_characters_and_ranges() {
    let (stdout, _) = emulate(
        r#"
        $name = "Sample"
        $number = 2 + 3 * 4
        $reversed = $name[-1..-8] -join ''
        $character = [char][Convert]::ToInt32("1100110", 2)
        Write-Output "$($name):$($number):$($reversed):$($character)"
        "#,
    );

    assert_eq!(stdout, ["Sample:14:elpmaS:f"]);
}

#[test]
fn supports_functions_loops_pipelines_and_switch() {
    let (stdout, _) = emulate(
        r#"
        function Double($Value) { return $Value * 2 }
        $values = 1..5 |
            ForEach-Object { Double $_ } |
            Where-Object { $_ -gt 5 }
        $sum = 0
        for ($i = 1; $i -le 5; $i++) { $sum += $i }
        switch ($sum) {
            15 { Write-Output "$($values -join ','):$sum" }
            default { Write-Output "unexpected" }
        }
        "#,
    );

    assert_eq!(stdout, ["6,8,10:15"]);
}

#[test]
fn supports_base64_json_regex_and_error_flow() {
    let (stdout, _) = emulate(
        r#"
        $bytes = [Text.Encoding]::UTF8.GetBytes("Hello")
        $encoded = [Convert]::ToBase64String($bytes)
        $decoded = [Text.Encoding]::UTF8.GetString(
            [Convert]::FromBase64String($encoded)
        )
        $json = "{`"name`":`"Sample`",`"count`":3}"
        $object = $(ConvertFrom-Json $json)
        $clean = [regex]::Replace("build-123", "[0-9]+", "safe")
        try { throw "expected" }
        catch {
            Write-Output "$($encoded):$($decoded):$($object.name):$($clean):caught"
        }
        finally { Write-Output "finally" }
        "#,
    );

    assert_eq!(
        stdout,
        ["SGVsbG8=:Hello:Sample:build-safe:caught", "finally"]
    );
}

#[test]
fn creates_archives_and_hashes_only_virtual_files() {
    let (stdout, host) = emulate(
        r#"
        Set-Content -Path "C:\Temp\safe.txt" -Value "archive demo" -NoNewline
        Compress-Archive -Path "C:\Temp\safe.txt" -DestinationPath "C:\Temp\safe.zip"
        Expand-Archive -Path "C:\Temp\safe.zip" -DestinationPath "C:\Restored"
        $hash = $(Get-FileHash -Path "C:\Restored\safe.txt" -Algorithm SHA256)
        Write-Output "$(Get-Content -Raw 'C:\Restored\safe.txt'):$($hash.Algorithm)"
        "#,
    );

    assert_eq!(stdout, ["archive demo:SHA256"]);
    let snapshot = host.snapshot();
    assert_eq!(snapshot.virtual_files.len(), 3);
}

#[test]
fn fixture_network_responses_allow_safe_multistage_analysis() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    host.register_network_response(
        "GET",
        "https://example.invalid/data",
        NetworkResponse {
            status: 200,
            headers: BTreeMap::new(),
            body: br#"{"message":"fixture response"}"#.to_vec(),
        },
    );

    let result = emulator
        .emulate(
            r#"
            $response = $(Invoke-RestMethod -Uri "https://example.invalid/data")
            Write-Output $response.message
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["fixture response"]);
    assert!(host
        .snapshot()
        .trace
        .iter()
        .any(|event| event.kind == EventKind::NetworkIntent));
}

#[test]
fn dangerous_apis_are_recorded_but_never_executed() {
    let (_, mut host) = emulate(
        r#"
        Add-Type '[DllImport("kernel32.dll")] public static extern IntPtr VirtualAlloc();'
        [Reflection.Assembly]::Load([Convert]::FromBase64String("TVqQAAMAAAAEAAAA"))
        [System.Runtime.InteropServices.Marshal]::Copy(@(1,2,3), 0, 0, 3)
        Register-ScheduledTask -TaskName "BenignFixture" -Action "echo safe"
        "#,
    );

    assert!(host.take_process_intents().is_empty());
    let snapshot = host.snapshot();
    assert!(snapshot.unsupported_operations >= 3);
    assert!(snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "add-type-source.cs"));
    assert!(snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::RegistryWrite));
}

#[test]
fn models_aes_hashes_and_switch_modes() {
    let (stdout, _) = emulate(
        r#"
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
        switch -Regex ("build-123") {
            "^build-[0-9]+$" {
                Write-Output ([Text.Encoding]::UTF8.GetString($plain))
            }
        }
        "#,
    );

    assert_eq!(stdout, ["safe crypto"]);
}

#[test]
fn caps_adversarial_ranges_and_repetition() {
    let limits = AnalysisLimits {
        max_loop_iterations: 16,
        max_artifact_bytes: 64,
        ..AnalysisLimits::default()
    };
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(limits);

    let result = emulator
        .emulate("1pb..-; 'abcdef' * 1pb", &mut host, 0)
        .unwrap();

    assert!(matches!(
        result.last_value,
        Some(powershell_emulator::Value::String(value)) if value.len() <= 64
    ));
    assert!(host
        .snapshot()
        .trace
        .iter()
        .any(|event| event.kind == EventKind::LimitReached));
}
