use std::io::Write;
use std::process::{Command, Stdio};

fn emulator_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_powershell-emulator"))
}

#[test]
fn command_flag_prints_echo_string_output() {
    let output = emulator_command()
        .args(["-c", "echo 'hello from the emulator'"])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "hello from the emulator\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn positional_script_prints_write_output_content() {
    let output = emulator_command()
        .arg("Write-Output \"positional script\"")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "positional script\n"
    );
}

#[test]
fn reads_scripts_from_standard_input() {
    let mut child = emulator_command()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"echo 'stdin script'")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "stdin script\n");
}

#[test]
fn blocked_web_requests_return_the_configured_fixed_text() {
    let output = emulator_command()
        .args([
            "--web-response",
            "fixed fixture body",
            "-c",
            "$response = Invoke-WebRequest 'https://example.invalid/test'; Write-Output $response.Content",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "fixed fixture body\n"
    );
}

#[test]
fn web_requests_are_still_reported_as_blocked() {
    let output = emulator_command()
        .args([
            "--trace",
            "--web-response",
            "fixed",
            "-c",
            "$response = Invoke-WebRequest 'https://example.invalid/test'; Write-Output $response.Content",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("blocked network request: GET https://example.invalid/test"));
}

#[test]
fn allow_network_still_blocks_private_destinations() {
    let output = emulator_command()
        .args([
            "--allow-network",
            "--trace",
            "-c",
            "Invoke-WebRequest 'http://127.0.0.1/private'",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    assert!(stderr.contains("network destination is not public"));
}

#[test]
fn system_directory_lists_modeled_windows_executables() {
    let output = emulator_command()
        .args(["-c", r"Get-ChildItem -Name C:\Windows\System32"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(stdout.lines().any(|line| line == "cmd.exe"));
    assert!(stdout.lines().any(|line| line == "mshta.exe"));
    assert!(stdout.lines().any(|line| line == "rundll32.exe"));
}

#[test]
fn interactive_mode_preserves_variables_and_virtual_files() {
    let output = run_interactive(
        r#"
$value = 40
$value += 2
Set-Content -Path "C:\Temp\interactive.txt" -Value $value -NoNewline
Write-Output $value
Write-Output (Get-Content -Raw "C:\Temp\interactive.txt")
exit
"#,
    );

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "42\n42\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn interactive_mode_accepts_multiline_functions() {
    let output = run_interactive(
        r#"
function Pair {
    Write-Output "one"
    Write-Output "two"
}
Pair
quit
"#,
    );

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "one\ntwo\n");
}

#[test]
fn interactive_errors_do_not_end_the_session() {
    let output = run_interactive(
        r#"
throw "expected"
Write-Output "after error"
:exit
"#,
    );

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "after error\n");
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("PowerShell expression could not be evaluated: expected"));
}

#[test]
fn interactive_trace_only_prints_new_events() {
    let mut child = emulator_command()
        .args(["--interactive", "--trace"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"Write-Output 'one'\nWrite-Output 'two'\nexit\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    assert_eq!(stderr.matches("parsed PowerShell input").count(), 2);
}

#[test]
fn interactive_echo_uses_powershell_argument_mode() {
    let output = run_interactive(
        r"
$x = 1
$y = 3
echo $x+$y
echo ($x+$y)
exit
",
    );

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "1+3\n4\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn interactive_unknown_commands_report_command_not_found() {
    let output = run_interactive(
        r"
$x = 1
$y = 3
WriteOutput $x+$y
exit
",
    );

    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(
        "writeoutput: The term 'writeoutput' is not recognized as a PowerShell command."
    ));
}

#[test]
fn interactive_mkdir_and_ls_use_the_current_location() {
    let output = run_interactive(
        r"
mkdir demo
ls -Name
cd demo
md child
dir -Name
exit
",
    );

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Directory: c:\\users\\analysis"));
    assert!(stdout.contains("d-----"));
    assert!(stdout.lines().any(|line| line.ends_with(" demo")));
    assert!(stdout.contains("Directory: c:\\users\\analysis\\demo"));
    assert!(stdout.lines().any(|line| line.ends_with(" child")));
    assert!(!stdout.contains("PSIsContainer="));
    assert!(output.stderr.is_empty());
}

#[test]
fn interactive_ls_formats_files_and_directories_as_a_table() {
    let output = run_interactive(
        r"
mkdir demo
Set-Content -Path note.txt -Value safe -NoNewline
ls
exit
",
    );

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Mode                 LastWriteTime         Length Name"));
    assert!(stdout.contains("d-----"));
    assert!(stdout.contains("demo"));
    assert!(stdout.contains("-a----"));
    assert!(stdout.contains("     4 note.txt"));
    assert!(!stdout.contains("DirectoryName="));
}

#[test]
fn interactive_output_redirection_writes_virtual_files() {
    let output = run_interactive(
        r"
echo 'abc' > test.txt
Get-Content test.txt
echo 'def' >> test.txt
Get-Content test.txt
exit
",
    );

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "abc\nabc\ndef\n");
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_environment_overrides_apply_to_direct_execution() {
    let output = emulator_command()
        .args([
            "--env",
            "USERNAME=tester",
            "--env",
            r"TEMP=C:\Scratch",
            "-c",
            r#"Write-Output "$($env:USERNAME):$($env:TEMP)""#,
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "tester:C:\\Scratch\n"
    );
}

#[test]
fn cli_rejects_invalid_environment_overrides() {
    let output = emulator_command()
        .args(["--env", "INVALID", "-c", "Write-Output safe"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("environment overrides must use NAME=VALUE"));
}

fn run_interactive(input: &str) -> std::process::Output {
    let mut child = emulator_command()
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
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}
