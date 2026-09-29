use bash_emulator::BashEmulator;
use emulator_core::{AnalysisLimits, EventKind, VirtualHost};

#[test]
fn functions_loops_conditionals_and_redirection_work_together() {
    let mut host = VirtualHost::macos(AnalysisLimits::default());
    let mut emulator = BashEmulator::new();
    let result = emulator
        .emulate(
            r#"
emit() { echo "item:$1"; }
for value in one two; do
  if test -n "$value"; then emit "$value"; fi
done > /tmp/items
cat /tmp/items
"#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["item:one", "item:two"]);
    assert!(host.snapshot().trace.iter().any(|event| {
        event.kind == EventKind::FileWrite && event.message.contains("/tmp/items")
    }));
}

#[test]
fn external_commands_are_typed_process_intents() {
    let mut host = VirtualHost::macos(AnalysisLimits::default());
    let mut emulator = BashEmulator::new();
    let result = emulator
        .emulate("osascript -e 'display dialog \"hello\"'", &mut host, 0)
        .unwrap();

    assert_eq!(result.exit_code, 127);
    assert!(host.snapshot().trace.iter().any(|event| {
        event.kind == EventKind::ProcessIntent
            && event
                .data
                .get("program")
                .is_some_and(|program| program == "osascript")
    }));
}

#[test]
fn substitutions_and_pipeline_stages_are_isolated() {
    let mut host = VirtualHost::macos(AnalysisLimits::default());
    let mut emulator = BashEmulator::new();
    let result = emulator
        .emulate(
            "value=outer; echo \"$(value=inner; echo $value)\"; echo hi | read piped; echo \"${value}:${piped:-missing}\"",
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["inner", "outer:missing"]);
}

#[test]
fn file_test_predicates_use_the_virtual_macos_host() {
    let mut host = VirtualHost::macos(AnalysisLimits::default());
    let mut emulator = BashEmulator::new();
    let result = emulator
        .emulate(
            "touch /tmp/present; if test -f /tmp/present; then echo found; fi",
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["found"]);
}

#[test]
fn brace_and_process_substitution_feed_real_commands() {
    let mut host = VirtualHost::macos(AnalysisLimits::default());
    let mut emulator = BashEmulator::new();
    let result = emulator
        .emulate(
            "for value in {1..3}; do cat <(echo \"item:$value\"); done",
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["item:1", "item:2", "item:3"]);
}
