use std::io::Write;
use std::process::{Command, Output, Stdio};

fn runbox_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_runbox-emulator"))
}

fn run_interactive(input: &str, arguments: &[&str]) -> Output {
    let mut child = runbox_command()
        .arg("--interactive")
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn command_mode_dispatches_powershell_and_returns_stdout() {
    let output = runbox_command()
        .args([
            "-c",
            r#"powershell -c "Write-Output 'hello from powershell'""#,
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "hello from powershell"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn interactive_cmd_and_powershell_share_environment_and_files() {
    let output = run_interactive(
        "set SHARED=from-cmd\n\
         powershell -c \"Write-Output $env:SHARED\"\n\
         powershell -c \"Set-Content shared.txt 'from-powershell'\"\n\
         type shared.txt\n\
         exit\n",
        &[],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(stdout.lines().any(|line| line == "from-cmd"), "{stdout}");
    assert!(stdout.contains("from-powershell"), "{stdout}");
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
}

#[test]
fn powershell_mode_dispatches_cmd_and_returns_stdout() {
    let output = runbox_command()
        .args(["--shell", "powershell", "-c", "cmd /c echo hello-from-cmd"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "hello-from-cmd"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn interactive_powershell_and_cmd_share_environment_and_files() {
    let output = run_interactive(
        "$env:SHARED='from-powershell'\n\
         cmd /c echo %SHARED%\n\
         cmd /c \"echo from-cmd>shared.txt\"\n\
         Get-Content shared.txt\n\
         exit\n",
        &["--shell", "powershell"],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(
        stdout.lines().any(|line| line == "from-powershell"),
        "{stdout}"
    );
    assert!(stdout.contains("from-cmd"), "{stdout}");
    assert!(output.stderr.is_empty(), "{:?}", output.stderr);
}
