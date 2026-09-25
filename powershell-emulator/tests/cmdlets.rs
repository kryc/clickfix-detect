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
fn pipeline_collection_cmdlets_transform_objects() {
    let (stdout, _) = emulate(
        r#"
        $csv = "Name,Value`nbeta,2`nalpha,1`nalpha,1"
        $rows = $(ConvertFrom-Csv $csv)
        $rows |
            Sort-Object Name -Unique |
            ForEach-Object { Write-Output "$($_.Name)=$($_.Value)" }
        "first`nsecond-123`nthird-456" |
            Select-String -Pattern "[0-9]+" |
            Select-Object -ExpandProperty Line |
            ForEach-Object { Write-Output $_ }
        "#,
    );

    assert_eq!(stdout, ["alpha=1", "beta=2", "second-123", "third-456"]);
}

#[test]
fn com_objects_use_virtual_effects_and_blocked_networking() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    host.set_default_network_response_text("fixture body");

    let result = emulator
        .emulate(
            r#"
            $http = New-Object -ComObject MSXML2.XMLHTTP
            $http.Open("GET", "https://example.invalid/com", $false)
            $http.Send()
            $stream = New-Object -ComObject ADODB.Stream
            $stream.Open()
            $stream.WriteText($http.ResponseText)
            $stream.SaveToFile("C:\Temp\com.txt", 2)
            Write-Output (Get-Content -Raw "C:\Temp\com.txt")
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["fixture body"]);
    let snapshot = host.snapshot();
    assert!(snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::NetworkIntent));
    assert_eq!(
        snapshot.virtual_files[0].text.as_deref(),
        Some("fixture body")
    );
}

#[test]
fn security_cmdlets_are_observable_but_not_applied() {
    let (_, host) = emulate(
        r#"
        Set-MpPreference -DisableRealtimeMonitoring $true
        Set-ExecutionPolicy Bypass
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-c echo safe"
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        Register-ScheduledTask -TaskName "SafeFixture" -Action $action -Trigger $trigger
        New-NetFirewallRule -DisplayName "SafeFixture" -Action Allow
        "#,
    );

    let snapshot = host.snapshot();
    assert!(snapshot.unsupported_operations >= 2);
    assert!(snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::RegistryWrite));
}

#[test]
fn recon_cmdlets_return_deterministic_objects() {
    let (stdout, _) = emulate(
        r#"
        $computer = Get-ComputerInfo
        $os = Get-CimInstance Win32_OperatingSystem
        $drive = Get-PSDrive | Where-Object { $_.Name -eq "C" }
        Write-Output "$($computer.CsName):$($os.OSArchitecture):$($drive.Name)"
        "#,
    );

    assert_eq!(stdout, ["ANALYSIS-HOST:64-bit:C"]);
}

#[test]
fn web_sessions_preserve_synthetic_cookies() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    host.register_network_response(
        "GET",
        "https://example.invalid/one",
        NetworkResponse {
            status: 200,
            headers: BTreeMap::from([("Set-Cookie".into(), "session=safe".into())]),
            body: b"first".to_vec(),
        },
    );
    host.register_network_response(
        "POST",
        "https://example.invalid/two",
        NetworkResponse::text("second"),
    );

    let result = emulator
        .emulate(
            r#"
            $one = Invoke-WebRequest -Uri "https://example.invalid/one" -SessionVariable web
            $two = Invoke-WebRequest -Uri "https://example.invalid/two" -Method POST -WebSession $web -Body "safe"
            Write-Output "$($one.Content):$($two.Content):$($web.Cookie)"
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["first:second:session=safe"]);
    assert!(host.snapshot().trace.iter().any(|event| {
        event.kind == EventKind::NetworkIntent
            && event
                .data
                .get("request_body_bytes")
                .is_some_and(|value| value == "4")
            && event
                .data
                .get("request_headers")
                .is_some_and(|value| value == "1")
    }));
}

#[test]
fn powershell_51_web_aliases_and_bits_jobs_are_modeled() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    for (url, body) in [
        ("https://example.invalid/curl", "curl-safe"),
        ("https://example.invalid/wget", "wget-safe"),
        ("https://example.invalid/bits", "bits-safe"),
    ] {
        host.register_network_response("GET", url, NetworkResponse::text(body));
    }

    let result = emulator
        .emulate(
            r#"
            $curlResponse = curl -Uri "https://example.invalid/curl"
            $wgetResponse = wget -Uri "https://example.invalid/wget"
            Write-Output "$($curlResponse.Content):$($wgetResponse.Content)"

            $job = Start-BitsTransfer -Source "https://example.invalid/bits" -Destination "C:\Temp\bits.txt" -DisplayName "SafeFixture" -Asynchronous
            $current = Get-BitsTransfer -Name "SafeFixture"
            Write-Output "$($current.JobState):$(Get-Content 'C:\Temp\bits.txt' -Raw)"
            Suspend-BitsTransfer -BitsJob $job
            $suspended = Get-BitsTransfer -Name "SafeFixture"
            Write-Output $suspended.JobState
            Resume-BitsTransfer -BitsJob $job
            $resumed = Get-BitsTransfer -Name "SafeFixture"
            Write-Output $resumed.JobState
            Complete-BitsTransfer -BitsJob $job
            $remaining = Get-BitsTransfer
            Write-Output "remaining=$($remaining.Count)"
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(
        result.stdout,
        [
            "curl-safe:wget-safe",
            "Transferred:bits-safe",
            "Suspended",
            "Transferred",
            "remaining=0"
        ]
    );
    assert_eq!(
        host.snapshot()
            .virtual_files
            .iter()
            .find(|file| file.path.ends_with("bits.txt"))
            .and_then(|file| file.text.as_deref()),
        Some("bits-safe")
    );
}
