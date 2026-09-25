use cmd_emulator::CmdEmulator;
use emulator_core::{AnalysisLimits, VirtualHost};

#[test]
fn pipeline_stdout_is_attached_to_external_process_intents() {
    let mut host = VirtualHost::new(AnalysisLimits::default());
    let mut emulator = CmdEmulator::new();

    let result = emulator
        .emulate("(echo Alpha & echo beta) | findstr /i alpha", &mut host, 0)
        .unwrap();
    let intents = host.take_process_intents();

    assert!(result.stdout.is_empty());
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].program, "findstr");
    assert_eq!(intents[0].stdin, ["Alpha", "beta"]);
    assert_eq!(intents[0].current_directory, r"C:\Users\analysis");
}

#[test]
fn deferred_external_processes_report_command_not_found() {
    let mut host = VirtualHost::new(AnalysisLimits::default());
    let mut emulator = CmdEmulator::new();

    let result = emulator
        .emulate(
            "tool.exe safe && echo unexpected || echo fallback",
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["fallback"]);
    assert_eq!(result.exit_code, 0);
    assert!(result.stderr[0].contains("not recognized"));
    assert_eq!(host.take_process_intents().len(), 1);
}
