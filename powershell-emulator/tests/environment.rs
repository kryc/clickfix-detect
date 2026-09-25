use emulator_core::{AnalysisLimits, Host, VirtualHost};
use powershell_emulator::PowerShellEmulator;

#[test]
fn exposes_windows_11_environment_defaults() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    let result = emulator
        .emulate(
            r#"
            Write-Output "$($env:OS):$($env:COMPUTERNAME):$($env:USERNAME)"
            Write-Output "$($env:ProgramFiles):$($env:PROCESSOR_ARCHITECTURE)"
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(
        result.stdout,
        [
            "Windows_NT:ANALYSIS-HOST:analysis",
            r"C:\Program Files:AMD64"
        ]
    );
}

#[test]
fn environment_provider_is_case_insensitive_and_mutable() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    let result = emulator
        .emulate(
            r#"
            $env:Demo = "safe"
            Write-Output $env:DEMO
            $removed = Remove-Item Env:demo
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["safe"]);
    assert!(host.environment("demo").is_none());
}

#[test]
fn dotnet_environment_apis_read_write_list_and_expand() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    let result = emulator
        .emulate(
            r#"
            [Environment]::SetEnvironmentVariable("DEMO", "fixture")
            $all = [Environment]::GetEnvironmentVariables()
            Write-Output $all.DEMO
            Write-Output ([Environment]::ExpandEnvironmentVariables("%TEMP%\%DEMO%.txt"))
            [Environment]::SetEnvironmentVariable("DEMO", $null)
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(
        result.stdout,
        [
            "fixture",
            r"C:\Users\analysis\AppData\Local\Temp\fixture.txt"
        ]
    );
    assert!(host.environment("DEMO").is_none());
}

#[test]
fn static_environment_properties_follow_the_virtual_host() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    host.set_environment("COMPUTERNAME", "OVERRIDE-HOST");
    host.set_environment("USERNAME", "tester");

    let result = emulator
        .emulate(
            r#"
            Write-Output "$([Environment]::MachineName):$([Environment]::UserName)"
            Write-Output "$([Environment]::Is64BitOperatingSystem):$([Environment]::ProcessorCount)"
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["OVERRIDE-HOST:tester", "True:8"]);
}
