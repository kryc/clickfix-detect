use std::process::Command;

#[test]
fn cli_emulates_bash_source() {
    let output = Command::new(env!("CARGO_BIN_EXE_bash-emulator"))
        .args(["-c", "name=world; echo \"hello $name\""])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "hello world"
    );
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_selects_linux_host() {
    let output = Command::new(env!("CARGO_BIN_EXE_bash-emulator"))
        .args(["--platform", "linux", "-c", "pwd; echo \"$HOME\""])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.lines().all(|line| line == "/home/analysis"));
    assert!(stdout.contains("/home/analysis"));
    assert!(output.stderr.is_empty());
}
