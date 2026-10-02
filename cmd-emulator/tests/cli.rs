use std::io::Write;
use std::process::{Command, Stdio};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cmd-emulator"))
}

#[test]
fn command_flag_and_environment_override_print_output() {
    let output = command()
        .args(["--env", "NAME=tester", "-c", "echo hello %NAME%"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "hello tester\n");
}

#[test]
fn standard_input_is_treated_as_batch_text() {
    let mut child = command()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"set X=stdin\r\necho %X%\r\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "stdin\n");
}

#[test]
fn piped_interactive_mode_preserves_state() {
    let mut child = command()
        .arg("--interactive")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"set VALUE=42\necho %VALUE%\nmd demo\ncd demo\necho %CD%\nquit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "42\nC:\\Users\\analysis\\demo\n"
    );
}

#[test]
fn trace_reports_process_intent_without_execution() {
    let output = command()
        .args(["--trace", "-c", "example.exe safe"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("requested process launch"));
}

#[test]
fn file_mode_exposes_repeatable_batch_arguments() {
    let sample = format!(
        "{}/../samples/cmd/04-batch-control.cmd",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = command()
        .args(["--file", &sample, "--arg", "cli-value"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("input=cli-value result=second"));
}

#[test]
fn interactive_dir_lists_redirected_files_and_ls_errors() {
    let mut child = command()
        .arg("--interactive")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"echo 'hello' > test.txt\ndir /b\ntype test.txt\nls\nexit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.lines().any(|line| line == "test.txt"));
    assert!(stdout.lines().any(|line| line == "'hello'"));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("'ls' is not recognized"));
}

#[test]
fn system_directory_lists_modeled_windows_executables() {
    let output = command()
        .args(["-c", r"dir /b C:\Windows\System32"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(stdout.lines().any(|line| line == "cmd.exe"));
    assert!(stdout.lines().any(|line| line == "mshta.exe"));
    assert!(stdout.lines().any(|line| line == "rundll32.exe"));
}
