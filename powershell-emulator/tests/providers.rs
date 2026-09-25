use emulator_core::{AnalysisLimits, EventKind, Host, VirtualHost};
use powershell_emulator::{PowerShellEmulator, Value};

fn run(emulator: &mut PowerShellEmulator, host: &mut VirtualHost, script: &str) -> Option<Value> {
    emulator.emulate(script, host, 0).unwrap().last_value
}

fn property<'a>(value: &'a Value, name: &str) -> &'a Value {
    let Value::Map(properties) = value else {
        panic!("expected a property map, got {value:?}");
    };
    properties
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map_or_else(
            || panic!("missing property {name} in {value:?}"),
            |(_, value)| value,
        )
}

#[test]
fn models_files_directories_metadata_content_and_locations() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    run(
        &mut emulator,
        &mut host,
        r#"Set-Content "C:\Users\analysis\demo.txt" "safe" -NoNewline"#,
    );
    let item = run(
        &mut emulator,
        &mut host,
        r"Get-Item C:\Users\analysis\demo.txt",
    )
    .unwrap();
    assert_eq!(property(&item, "Name"), &Value::String("demo.txt".into()));
    assert_eq!(property(&item, "Extension"), &Value::String(".txt".into()));
    assert_eq!(property(&item, "Length"), &Value::Number(4));
    assert_eq!(
        property(&item, "DirectoryName"),
        &Value::String(r"c:\users\analysis".into())
    );
    run(
        &mut emulator,
        &mut host,
        r#"Set-Item C:\Users\analysis\demo.txt "changed""#,
    );
    let item = run(
        &mut emulator,
        &mut host,
        r"Get-Item C:\Users\analysis\demo.txt",
    )
    .unwrap();
    assert_eq!(property(&item, "Length"), &Value::Number(7));

    run(
        &mut emulator,
        &mut host,
        r"New-Item C:\Users\analysis\Reports -ItemType Directory",
    );
    let children = run(
        &mut emulator,
        &mut host,
        r"Get-ChildItem C:\Users\analysis -Directory",
    )
    .unwrap();
    assert!(matches!(
        children,
        Value::Array(values)
            if values.iter().any(|value| property(value, "Name") == &Value::String("reports".into()))
    ));

    run(
        &mut emulator,
        &mut host,
        r"Clear-Content C:\Users\analysis\demo.txt",
    );
    assert_eq!(
        host.snapshot()
            .virtual_files
            .iter()
            .find(|file| file.path.ends_with("demo.txt"))
            .map(|file| file.size),
        Some(0)
    );

    let first_temp = run(&mut emulator, &mut host, "New-TemporaryFile").unwrap();
    let second_temp = run(&mut emulator, &mut host, "New-TemporaryFile").unwrap();
    assert_ne!(
        property(&first_temp, "FullName"),
        property(&second_temp, "FullName")
    );

    run(
        &mut emulator,
        &mut host,
        r"Push-Location C:\Users\analysis\Reports",
    );
    let location = run(&mut emulator, &mut host, "Get-Location").unwrap();
    assert_eq!(
        property(&location, "Path"),
        &Value::String(r"c:\users\analysis\reports".into())
    );
    run(&mut emulator, &mut host, "Pop-Location");
    let location = run(&mut emulator, &mut host, "Get-Location").unwrap();
    assert_eq!(
        property(&location, "Path"),
        &Value::String(r"C:\Users\analysis".into())
    );
    assert!(matches!(
        run(
            &mut emulator,
            &mut host,
            r"Remove-Item C:\Users\analysis\demo.txt"
        ),
        Some(Value::Bool(true))
    ));
}

#[test]
fn mkdir_and_md_create_relative_directories_for_ls() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    run(&mut emulator, &mut host, "mkdir demo");
    let children = run(&mut emulator, &mut host, "ls -Name").unwrap();
    assert!(matches!(
        children,
        Value::Array(values) if values.contains(&Value::String("demo".into()))
    ));

    run(&mut emulator, &mut host, "cd demo");
    run(&mut emulator, &mut host, "md child");
    let children = run(&mut emulator, &mut host, "dir -Name").unwrap();
    assert_eq!(children, Value::Array(vec![Value::String("child".into())]));
}

#[test]
fn models_environment_variable_alias_and_function_providers() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    run(&mut emulator, &mut host, "Set-Item Env:DEMO safe");
    let environment = run(&mut emulator, &mut host, "Get-Item Env:DEMO").unwrap();
    assert_eq!(
        property(&environment, "Value"),
        &Value::String("safe".into())
    );
    let environment_children = run(&mut emulator, &mut host, "Get-ChildItem Env:").unwrap();
    assert!(matches!(
        environment_children,
        Value::Array(values)
            if values.iter().any(|value| property(value, "Name") == &Value::String("demo".into()))
    ));

    run(&mut emulator, &mut host, "Set-Item Variable:answer 42");
    let variable = run(&mut emulator, &mut host, "Get-Item Variable:answer").unwrap();
    assert_eq!(property(&variable, "Value"), &Value::Number(42));

    run(&mut emulator, &mut host, "Set-Item Alias:say write-output");
    run(
        &mut emulator,
        &mut host,
        r#"Set-Item Function:greet { Write-Output "hello" }"#,
    );
    run(&mut emulator, &mut host, "greet");
    assert!(emulator
        .emulate("say done", &mut host, 0)
        .unwrap()
        .stdout
        .ends_with(&["hello".into(), "done".into()]));
    for (provider, expected) in [
        ("Variable:", "answer"),
        ("Alias:", "say"),
        ("Function:", "greet"),
    ] {
        let children = run(
            &mut emulator,
            &mut host,
            &format!("Get-ChildItem {provider}"),
        )
        .unwrap();
        assert!(matches!(
            children,
            Value::Array(values)
                if values.iter().any(|value| property(value, "Name") == &Value::String(expected.into()))
        ));
    }

    assert!(matches!(
        run(&mut emulator, &mut host, "Remove-Item Env:DEMO"),
        Some(Value::Bool(true))
    ));
    assert!(host.environment("DEMO").is_none());
}

#[test]
fn models_registry_items_and_properties() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    run(
        &mut emulator,
        &mut host,
        r"New-Item HKCU:\Software\ProviderDemo -ItemType RegistryKey",
    );
    run(
        &mut emulator,
        &mut host,
        r"Set-ItemProperty HKCU:\Software\ProviderDemo -Name Marker -Value safe",
    );
    let property_value = run(
        &mut emulator,
        &mut host,
        r"Get-ItemProperty HKCU:\Software\ProviderDemo -Name Marker",
    )
    .unwrap();
    assert_eq!(
        property(&property_value, "Marker"),
        &Value::String("safe".into())
    );
    assert_eq!(
        run(
            &mut emulator,
            &mut host,
            r"Get-ItemPropertyValue HKCU:\Software\ProviderDemo -Name Marker"
        ),
        Some(Value::String("safe".into()))
    );

    let children = run(&mut emulator, &mut host, r"Get-ChildItem HKCU:\Software").unwrap();
    assert!(matches!(
        children,
        Value::Array(values)
            if values.iter().any(|value| property(value, "Name") == &Value::String("providerdemo".into()))
    ));

    assert!(matches!(
        run(
            &mut emulator,
            &mut host,
            r"Remove-ItemProperty HKCU:\Software\ProviderDemo -Name Marker"
        ),
        Some(Value::Bool(true))
    ));
    assert!(host
        .read_registry(
            r"HKCU\Software\ProviderDemo\Marker",
            emulator_core::Engine::PowerShell,
            0
        )
        .is_none());

    run(
        &mut emulator,
        &mut host,
        r"New-Item HKLM:\Software\ProviderDemo -ItemType RegistryKey",
    );
    let machine_children = run(&mut emulator, &mut host, r"Get-ChildItem HKLM:\Software").unwrap();
    assert!(matches!(
        machine_children,
        Value::Array(values)
            if values.iter().any(|value| property(value, "Name") == &Value::String("providerdemo".into()))
    ));
}

#[test]
fn filters_and_recursively_manages_virtual_directories() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    for directory in [r"C:\Users\analysis\Tree", r"C:\Users\analysis\Tree\Nested"] {
        run(
            &mut emulator,
            &mut host,
            &format!(r#"New-Item "{directory}" -ItemType Directory"#),
        );
    }
    for (path, value) in [
        (r"C:\Users\analysis\Tree\keep.txt", "one"),
        (r"C:\Users\analysis\Tree\skip.txt", "two"),
        (r"C:\Users\analysis\Tree\Nested\deep.txt", "three"),
        (r"C:\Users\analysis\Tree\Nested\other.log", "four"),
    ] {
        run(
            &mut emulator,
            &mut host,
            &format!(r#"Set-Content "{path}" "{value}" -NoNewline"#),
        );
    }

    let files = run(
        &mut emulator,
        &mut host,
        r#"Get-ChildItem "C:\Users\analysis\Tree" -Recurse -File -Filter "*.txt" -Include "*.txt" -Exclude "skip*""#,
    )
    .unwrap();
    assert!(matches!(
        files,
        Value::Array(values)
            if values.len() == 2
                && values.iter().any(|value| property(value, "Name") == &Value::String("keep.txt".into()))
                && values.iter().any(|value| property(value, "Name") == &Value::String("deep.txt".into()))
    ));

    run(
        &mut emulator,
        &mut host,
        r#"Copy-Item "C:\Users\analysis\Tree" "C:\Users\analysis\Copied" -Recurse"#,
    );
    assert_eq!(
        run(
            &mut emulator,
            &mut host,
            r#"Get-Content "C:\Users\analysis\Copied\Nested\deep.txt" -Raw"#
        ),
        Some(Value::String("three".into()))
    );
    run(
        &mut emulator,
        &mut host,
        r#"Move-Item "C:\Users\analysis\Copied" "C:\Users\analysis\Moved" -Recurse"#,
    );
    assert_eq!(
        run(
            &mut emulator,
            &mut host,
            r#"Get-Content "C:\Users\analysis\Moved\keep.txt" -Raw"#
        ),
        Some(Value::String("one".into()))
    );
    assert!(matches!(
        run(
            &mut emulator,
            &mut host,
            r#"Remove-Item "C:\Users\analysis\Moved" -Recurse"#
        ),
        Some(Value::Bool(true))
    ));
    assert_eq!(
        run(
            &mut emulator,
            &mut host,
            r#"Get-Content "C:\Users\analysis\Moved\keep.txt" -Raw"#
        ),
        Some(Value::Null)
    );
}

#[test]
fn models_content_tail_delimiters_encodings_and_newlines() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    run(
        &mut emulator,
        &mut host,
        r#"Set-Content "C:\Users\analysis\records.txt" "one`ntwo`nthree" -NoNewline -Encoding UTF8"#,
    );
    assert_eq!(
        run(
            &mut emulator,
            &mut host,
            r#"Get-Content "C:\Users\analysis\records.txt" -Tail 2 -Encoding UTF8"#
        ),
        Some(Value::Array(vec![
            Value::String("two".into()),
            Value::String("three".into())
        ]))
    );

    run(
        &mut emulator,
        &mut host,
        r#"Set-Content "C:\Users\analysis\delimited.txt" "alpha|beta|gamma" -NoNewline"#,
    );
    assert_eq!(
        run(
            &mut emulator,
            &mut host,
            r#"Get-Content "C:\Users\analysis\delimited.txt" -Delimiter "|""#
        ),
        Some(Value::Array(vec![
            Value::String("alpha|".into()),
            Value::String("beta|".into()),
            Value::String("gamma".into())
        ]))
    );

    run(
        &mut emulator,
        &mut host,
        r#"Set-Content "C:\Users\analysis\unicode.txt" "safe" -Encoding Unicode"#,
    );
    assert_eq!(
        run(
            &mut emulator,
            &mut host,
            r#"Get-Content "C:\Users\analysis\unicode.txt" -Raw"#
        ),
        Some(Value::String("safe\r\n".into()))
    );
    run(
        &mut emulator,
        &mut host,
        r#"Out-File "C:\Users\analysis\joined.txt" "left" -Encoding UTF8 -NoNewline"#,
    );
    run(
        &mut emulator,
        &mut host,
        r#"Add-Content "C:\Users\analysis\joined.txt" "right" -Encoding UTF8 -NoNewline"#,
    );
    assert_eq!(
        run(
            &mut emulator,
            &mut host,
            r#"Get-Content "C:\Users\analysis\joined.txt" -Raw"#
        ),
        Some(Value::String("leftright".into()))
    );
}

#[test]
fn records_shell_association_and_synthetic_file_metadata_operations() {
    let mut emulator = PowerShellEmulator::new();
    let mut host = VirtualHost::new(AnalysisLimits::default());

    run(
        &mut emulator,
        &mut host,
        r#"Set-Content "C:\Users\analysis\demo.ps1" "Write-Output safe""#,
    );
    let signature = run(
        &mut emulator,
        &mut host,
        r"Get-AuthenticodeSignature C:\Users\analysis\demo.ps1",
    )
    .unwrap();
    assert_eq!(
        property(&signature, "Status"),
        &Value::String("NotSigned".into())
    );

    run(
        &mut emulator,
        &mut host,
        r"Unblock-File C:\Users\analysis\demo.ps1",
    );
    run(
        &mut emulator,
        &mut host,
        r"Invoke-Item C:\Users\analysis\demo.ps1",
    );

    let intents = host.take_process_intents();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].program, r"c:\users\analysis\demo.ps1");
    assert!(intents[0].origin.contains("shell association"));
    assert!(host.snapshot().trace.iter().any(|event| {
        event.kind == EventKind::Command
            && event
                .data
                .get("metadata")
                .is_some_and(|metadata| metadata == "Zone.Identifier")
    }));
}
