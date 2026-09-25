use cmd_emulator::{CmdEmulator, CmdError};
use emulator_core::{AnalysisLimits, Engine, Host, HostError, VirtualHost};

fn host() -> VirtualHost {
    VirtualHost::new(AnalysisLimits::default())
}

#[test]
fn batch_arguments_shift_and_path_modifiers_work() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate_batch_with_args(
            "echo %0^|%1^|%2^|%*\necho %~f1^|%~d1^|%~p1^|%~n1^|%~x1\nshift\necho %1\necho %~dp0\necho %~nx1",
            r"C:\Scripts\demo.cmd",
            &[r"C:\Temp\name.txt", "two words"],
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(
        result.stdout,
        [
            r#"C:\Scripts\demo.cmd|C:\Temp\name.txt|two words|C:\Temp\name.txt "two words""#,
            r"C:\Temp\name.txt|C:|\Temp\|name|.txt",
            "two words",
            r"C:\Scripts\",
            "two words"
        ]
    );
}

#[test]
fn goto_call_exit_b_and_double_expansion_work() {
    let mut host = host();
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate_batch(
            r"
set VALUE=expanded
call echo %%VALUE%%
call :sub first second
echo after-%ERRORLEVEL%
goto :eof
:sub
echo sub-%1
shift
echo shifted-%1
exit /b 7
echo unreachable
",
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(
        result.stdout,
        ["expanded", "sub-first", "shifted-second", "after-7"]
    );
}

#[test]
fn environment_replacement_and_substring_expansion_work() {
    let mut host = host();
    host.set_environment("VALUE", "abcdefabc");
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate(
            "echo %VALUE:abc=XY% & echo %VALUE:~2,4% & echo %VALUE:~-3%",
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(result.stdout, ["XYdefXY", "cdef", "abc"]);
}

#[test]
fn if_forms_and_else_blocks_respect_conditions() {
    let mut host = host();
    host.set_environment("FLAG", "yes");
    host.write_file(
        r"C:\Users\analysis\present.txt",
        b"safe",
        false,
        Engine::Cmd,
        0,
    )
    .unwrap();
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate_batch(
            r#"
type missing.txt
if errorlevel 1 echo error
if exist present.txt echo exists
if defined flag (echo defined) else (echo wrong)
if not defined absent echo absent
if "A"=="A" echo equal
if /i "A"=="a" echo iequal
if 10 GTR 2 echo greater
if beta LSS gamma echo lexical
if 2 GEQ 9 (echo wrong) else (echo else)
"#,
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(
        result.stdout,
        ["error", "exists", "defined", "absent", "equal", "iequal", "greater", "lexical", "else"]
    );
}

#[test]
fn for_simple_linear_recursive_and_text_modes_work() {
    let mut host = host();
    host.write_file(
        r"C:\Users\analysis\data.csv",
        b";ignored\r\none,two\r\nthree,four\r\n",
        false,
        Engine::Cmd,
        0,
    )
    .unwrap();
    host.write_file(r"C:\Users\analysis\tree\a.txt", b"a", false, Engine::Cmd, 0)
        .unwrap();
    host.write_file(r"C:\Users\analysis\tree\b.log", b"b", false, Engine::Cmd, 0)
        .unwrap();
    let mut emulator = CmdEmulator::new();
    let result = emulator
        .emulate_batch(
            r#"
for %%A in (one two) do echo simple-%%A
for /L %%N in (1,2,5) do echo number-%%N
for /F "tokens=1,2 delims=, skip=1 eol=;" %%A in (data.csv) do echo csv-%%A-%%B
for /F "tokens=1,2 delims=," %%A in ("left,right") do echo text-%%A-%%B
for /F "tokens=1" %%A in ('echo command-output') do echo command-%%A
for /R tree %%F in (*.txt) do echo recursive-%%~nxF
"#,
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(
        result.stdout,
        [
            "simple-one",
            "simple-two",
            "number-1",
            "number-3",
            "number-5",
            "csv-one-two",
            "csv-three-four",
            "text-left-right",
            "command-command-output",
            "recursive-a.txt"
        ]
    );
}

#[test]
fn cyclic_goto_stops_at_step_limit_and_cleans_context() {
    let mut limited_host = VirtualHost::new(AnalysisLimits {
        max_steps: 20,
        ..AnalysisLimits::default()
    });
    let mut emulator = CmdEmulator::new();
    let error = emulator
        .emulate_batch(":again\ngoto again", &mut limited_host, 0)
        .unwrap_err();
    assert!(matches!(error, CmdError::Host(HostError::StepLimit)));

    let mut fresh_host = host();
    assert_eq!(
        emulator
            .emulate("echo recovered", &mut fresh_host, 0)
            .unwrap()
            .stdout,
        ["recovered"]
    );
}

#[test]
fn zero_step_for_stops_at_loop_limit() {
    let mut host = VirtualHost::new(AnalysisLimits {
        max_loop_iterations: 4,
        ..AnalysisLimits::default()
    });
    let mut emulator = CmdEmulator::new();
    let error = emulator
        .emulate("for /L %A in (1,0,2) do echo %A", &mut host, 0)
        .unwrap_err();
    assert!(matches!(error, CmdError::LoopLimit { limit: 4 }));
}

#[test]
fn recursive_batch_calls_stop_at_depth_limit() {
    let mut host = VirtualHost::new(AnalysisLimits {
        max_depth: 2,
        ..AnalysisLimits::default()
    });
    let mut emulator = CmdEmulator::new();
    let error = emulator
        .emulate_batch("call :again\ngoto :eof\n:again\ncall :again", &mut host, 0)
        .unwrap_err();
    assert!(matches!(
        error,
        CmdError::Host(HostError::DepthLimit { .. })
    ));
}
