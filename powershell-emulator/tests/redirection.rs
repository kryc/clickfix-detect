use emulator_core::{AnalysisLimits, Host, VirtualHost};
use powershell_emulator::PowerShellEmulator;

#[test]
fn success_output_redirects_to_a_utf16le_virtual_file() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    let result = emulator
        .emulate("echo 'abc' > test.txt", &mut host, 0)
        .unwrap();
    assert!(result.stdout.is_empty());

    let bytes = host
        .read_file(
            r"C:\Users\analysis\test.txt",
            emulator_core::Engine::PowerShell,
            0,
        )
        .unwrap();
    assert!(bytes.starts_with(&[0xff, 0xfe]));

    let result = emulator
        .emulate("Get-Content test.txt", &mut host, 0)
        .unwrap();
    assert_eq!(result.stdout, ["abc"]);
}

#[test]
fn append_redirection_preserves_existing_content_and_one_bom() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    emulator
        .emulate("echo first > test.txt", &mut host, 0)
        .unwrap();
    emulator
        .emulate("echo second >> test.txt", &mut host, 0)
        .unwrap();
    let bytes = host
        .read_file(
            r"C:\Users\analysis\test.txt",
            emulator_core::Engine::PowerShell,
            0,
        )
        .unwrap();

    assert!(bytes.starts_with(&[0xff, 0xfe]));
    assert_eq!(
        bytes
            .windows(2)
            .filter(|window| *window == [0xff, 0xfe])
            .count(),
        1
    );
    let result = emulator
        .emulate("Get-Content test.txt", &mut host, 0)
        .unwrap();
    assert_eq!(result.stdout, ["first", "second"]);
}

#[test]
fn error_redirection_does_not_consume_success_output() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    let result = emulator
        .emulate(
            "Write-Error 'bad' 2> error.txt; echo 'ok' 2> empty.txt",
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(result.stdout, ["ok"]);
    emulator.drain_stdout();

    let result = emulator
        .emulate("Get-Content error.txt", &mut host, 0)
        .unwrap();
    assert_eq!(result.stdout, ["bad"]);
    emulator.drain_stdout();

    let result = emulator
        .emulate("Get-Content empty.txt -Raw", &mut host, 0)
        .unwrap();
    assert_eq!(result.stdout, [""]);
}

#[test]
fn all_stream_and_merge_redirections_are_modeled() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    let result = emulator
        .emulate(
            "Write-Error 'bad' *> all.txt; Write-Error 'merged' 2>&1",
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(result.stdout, ["merged"]);
    emulator.drain_stdout();
    let result = emulator
        .emulate("Get-Content all.txt", &mut host, 0)
        .unwrap();
    assert_eq!(result.stdout, ["bad"]);
}
