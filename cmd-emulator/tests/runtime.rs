use cmd_emulator::CmdEmulator;
use emulator_core::{AnalysisLimits, EventKind, Host, VirtualHost};

fn host() -> VirtualHost {
    VirtualHost::new(AnalysisLimits::default())
}

#[test]
fn environment_expansion_is_case_insensitive_and_deterministic() {
    let mut host = host();
    host.set_environment("Greeting", "hello");
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate("echo %greeting% %CD% %DATE% %TIME%", &mut host, 0)
        .unwrap();
    assert_eq!(
        result.stdout,
        [r"hello C:\Users\analysis Mon 01/01/2024 00:00:00.00"]
    );
}

#[test]
fn delayed_expansion_is_optional() {
    let mut host = host();
    host.set_environment("VALUE", "safe");
    let mut emulator = CmdEmulator::new().with_delayed_expansion(true);
    assert_eq!(
        emulator
            .emulate("echo !value!", &mut host, 0)
            .unwrap()
            .stdout,
        ["safe"]
    );
}

#[test]
fn chaining_observes_exit_codes_and_errorlevel() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate(
            "type missing.txt && echo no || echo failed & echo %ERRORLEVEL%",
            &mut host,
            0,
        )
        .unwrap();
    assert!(result.stdout.contains(&"failed".into()));
    assert!(!result.stdout.contains(&"no".into()));
    assert_eq!(result.exit_code, 0);
}

#[test]
fn set_arithmetic_and_persistent_directories_work() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate(
            "set /a count=6*7 & md demo & pushd demo & echo %CD% & popd",
            &mut host,
            0,
        )
        .unwrap();
    assert!(result.stdout.contains(&"42".into()));
    assert!(result
        .stdout
        .iter()
        .any(|line| line.eq_ignore_ascii_case(r"C:\Users\analysis\demo")));
    assert_eq!(emulator.current_directory(), r"C:\Users\analysis");
    assert_eq!(host.environment("COUNT"), Some("42"));
}

#[test]
fn output_and_error_redirection_use_virtual_files() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    emulator
        .emulate(
            "echo first > out.txt & echo second >> out.txt & type absent 2> err.txt",
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(
        host.read_file(r"C:\Users\analysis\out.txt", emulator_core::Engine::Cmd, 0)
            .unwrap(),
        b"first\r\nsecond\r\n"
    );
    assert!(String::from_utf8(
        host.read_file(r"C:\Users\analysis\err.txt", emulator_core::Engine::Cmd, 0)
            .unwrap()
    )
    .unwrap()
    .contains("cannot find"));
}

#[test]
fn descriptor_merges_and_group_redirection_share_virtual_sinks() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    emulator
        .emulate(
            "(echo visible & type absent) > combined.txt 2>&1",
            &mut host,
            0,
        )
        .unwrap();
    let contents = String::from_utf8(
        host.read_file(
            r"C:\Users\analysis\combined.txt",
            emulator_core::Engine::Cmd,
            0,
        )
        .unwrap(),
    )
    .unwrap();
    assert!(contents.contains("visible"));
    assert!(contents.contains("cannot find"));
}

#[test]
fn file_builtins_copy_move_rename_and_delete() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    emulator
        .emulate("echo data>one.txt & copy one.txt two.txt & move two.txt three.txt & ren three.txt four.txt & del one.txt", &mut host, 0)
        .unwrap();
    assert_eq!(
        host.read_file(r"C:\Users\analysis\four.txt", emulator_core::Engine::Cmd, 0)
            .unwrap(),
        b"data\r\n"
    );
    assert!(host
        .read_file(r"C:\Users\analysis\one.txt", emulator_core::Engine::Cmd, 0)
        .is_none());
}

#[test]
fn external_commands_and_start_emit_process_intents() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    emulator
        .emulate(
            "tool.exe --safe & start \"title\" app.exe arg",
            &mut host,
            0,
        )
        .unwrap();
    let snapshot = host.snapshot();
    assert_eq!(
        snapshot
            .trace
            .iter()
            .filter(|event| event.kind == EventKind::ProcessIntent)
            .count(),
        2
    );
    let intents = host.take_process_intents();
    assert_eq!(intents[1].program, "app.exe");
    assert_eq!(intents[1].args, ["arg"]);
}

#[test]
fn batch_goto_uses_preparsed_labels() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate_batch(
            "goto target\r\necho skipped\r\n:target\r\nset X=ok\r\necho %X%\r\ngoto :eof\r\n",
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(result.stdout, ["ok"]);
    assert_eq!(host.snapshot().unsupported_operations, 0);
}

#[test]
fn dir_lists_virtual_files_and_directories() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();

    emulator
        .emulate("md demo & echo hello>test.txt", &mut host, 0)
        .unwrap();
    let result = emulator.emulate("dir", &mut host, 0).unwrap();

    assert!(result
        .stdout
        .iter()
        .any(|line| line.contains("<DIR>") && line.ends_with("demo")));
    assert!(result
        .stdout
        .iter()
        .any(|line| line.contains('7') && line.ends_with("test.txt")));
    assert!(result.stdout.iter().any(|line| line.contains("1 File(s)")));

    let bare = emulator.emulate("dir /b", &mut host, 0).unwrap();
    assert!(bare.stdout.contains(&"demo".into()));
    assert!(bare.stdout.contains(&"test.txt".into()));
}

#[test]
fn unknown_commands_return_windows_error_9009() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();

    let result = emulator.emulate("ls", &mut host, 0).unwrap();

    assert_eq!(result.exit_code, 9009);
    assert!(result.stderr[0].contains("'ls' is not recognized"));
}
