use emulator_core::{AnalysisLimits, EventKind, VirtualHost};
use powershell_emulator::PowerShellEmulator;

fn emulate(script: &str) -> (Vec<String>, VirtualHost) {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    let result = emulator.emulate(script, &mut host, 0).unwrap();
    (result.stdout, host)
}

#[test]
fn supports_parameter_abbreviation_and_hashtable_splatting() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    host.set_default_network_response_text("fixture");

    let result = emulator
        .emulate(
            r#"
            $parameters = @{
                Uri = "https://example.invalid/splat"
                Meth = "POST"
                Body = "safe"
            }
            $first = Invoke-WebRequest @parameters
            $second = Invoke-WebRequest -U "https://example.invalid/short" -M POST -B safe
            Write-Output "$($first.Content):$($second.Content)"
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["fixture:fixture"]);
    assert_eq!(
        host.snapshot()
            .trace
            .iter()
            .filter(|event| event.kind == EventKind::NetworkIntent)
            .count(),
        2
    );
}

#[test]
fn preserves_multiple_function_and_scriptblock_outputs() {
    let (stdout, _) = emulate(
        r#"
        function Pair {
            Write-Output 1
            Write-Output 2
        }
        Pair | ForEach-Object { Write-Output $_ }
        3..4 | ForEach-Object { $_; $_ * 10 }
        $items = @("one", "two")
        Write-Output @items
        "#,
    );

    assert_eq!(stdout, ["1", "2", "3", "30", "4", "40", "one", "two"]);
}

#[test]
fn models_type_constructors_stream_state_and_static_properties() {
    let (stdout, _) = emulate(
        r#"
        [Net.ServicePointManager]::SecurityProtocol = "Tls12"
        $stream = [IO.MemoryStream]::new()
        $bytes = [Text.Encoding]::UTF8.GetBytes("safe")
        $stream.Write($bytes, 0, $bytes.Length)
        Write-Output ([Text.Encoding]::UTF8.GetString($stream.ToArray()))
        Write-Output ([Net.ServicePointManager]::SecurityProtocol)
        "#,
    );

    assert_eq!(stdout, ["safe", "Tls12"]);
}

#[test]
fn records_reflection_and_native_resolution_without_execution() {
    let (_, host) = emulate(
        r#"
        $type = [Ref].Assembly.GetType(
            "System.Management.Automation.AmsiUtils"
        )
        $field = $type.GetField("amsiInitFailed")
        $field.SetValue($null, $true)
        [Runtime.InteropServices.NativeLibrary]::Load("kernel32.dll")
        [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            0,
            [Type]
        )
        "#,
    );

    let snapshot = host.snapshot();
    assert!(snapshot.unsupported_operations >= 3);
    assert!(snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Unsupported
            && event
                .message
                .to_ascii_lowercase()
                .contains("amsiinitfailed")
    }));
    assert!(snapshot.trace.iter().any(|event| {
        event.kind == EventKind::Unsupported
            && event.message.to_ascii_lowercase().contains("native")
    }));
}

#[test]
fn array_splatting_emits_each_argument() {
    let (stdout, _) = emulate(
        r#"
        $items = @("alpha", "beta")
        Write-Output @items
        "#,
    );

    assert_eq!(stdout, ["alpha", "beta"]);
}

#[test]
fn implicit_expression_output_is_visible() {
    let (stdout, _) = emulate("1 + 1");
    assert_eq!(stdout, ["2"]);
}

#[test]
fn static_type_literals_remain_values() {
    let (stdout, _) = emulate("Write-Output ([string].TypeName)");
    assert_eq!(stdout, ["Type:string"]);
}

#[test]
fn constructor_objects_are_mutable_maps() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    let result = emulator
        .emulate(
            r#"
            $client = [Net.WebClient]::new()
            $client.Headers = @{ Test = "safe" }
            Write-Output $client.Headers.Test
            "#,
            &mut host,
            0,
        )
        .unwrap();

    assert_eq!(result.stdout, ["safe"]);
}

#[test]
fn unknown_commands_are_not_reinterpreted_as_expressions() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());
    let result = emulator
        .emulate("$x=1;$y=3;WriteOutput $x+$y", &mut host, 0)
        .unwrap();

    assert!(result.stdout.is_empty());
    assert!(host.snapshot().trace.iter().any(|event| {
        event.kind == EventKind::Unsupported
            && event.message == "unsupported PowerShell command: writeoutput"
    }));
}
