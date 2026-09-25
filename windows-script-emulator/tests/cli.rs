use std::process::Command;

fn emulator_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_windows-script-emulator"))
}

#[test]
fn allow_network_still_blocks_private_destinations() {
    let output = emulator_command()
        .args([
            "--allow-network",
            "--trace",
            "-c",
            r#"var request = new ActiveXObject("MSXML2.XMLHTTP"); request.open("GET", "http://127.0.0.1/private", false); request.send();"#,
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(output.status.success());
    assert!(stderr.contains("network destination is not public"));
}

#[test]
fn filesystem_object_sees_modeled_windows_executables() {
    let output = emulator_command()
        .args([
            "-c",
            r#"var fso = new ActiveXObject("Scripting.FileSystemObject"); WScript.Echo(fso.FileExists("C:\\Windows\\System32\\cmd.exe"));"#,
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "true\n");
}
