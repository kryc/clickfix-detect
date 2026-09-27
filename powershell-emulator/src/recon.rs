use crate::syntax::{find_switch, named_or_positional};
use crate::{PowerShellEmulator, Value};
use emulator_core::{Engine, EventKind, Host, TraceEvent};

pub(crate) enum ReconDispatch {
    NotHandled,
    Handled(Option<Value>),
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines)]
    pub(crate) fn execute_recon_command(
        &mut self,
        command: &str,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> ReconDispatch {
        let value = match command {
            "get-computerinfo" => Some(computer_info()),
            "get-service" => Some(Value::Array(vec![
                service(
                    "WinDefend",
                    "Microsoft Defender Antivirus Service",
                    "Running",
                ),
                service("EventLog", "Windows Event Log", "Running"),
                service("BITS", "Background Intelligent Transfer Service", "Running"),
            ])),
            "get-hotfix" => Some(Value::Array(vec![Value::Map(
                [
                    ("HotFixID".into(), Value::String("KB5030001".into())),
                    (
                        "Description".into(),
                        Value::String("Security Update".into()),
                    ),
                    ("InstalledOn".into(), Value::String("2024-01-01".into())),
                ]
                .into_iter()
                .collect(),
            )])),
            "get-netipaddress" => Some(Value::Array(vec![Value::Map(
                [
                    ("IPAddress".into(), Value::String("192.0.2.10".into())),
                    ("InterfaceAlias".into(), Value::String("Ethernet".into())),
                    ("AddressFamily".into(), Value::String("IPv4".into())),
                    ("PrefixLength".into(), Value::Number(24)),
                ]
                .into_iter()
                .collect(),
            )])),
            "get-netadapter" => Some(Value::Array(vec![Value::Map(
                [
                    ("Name".into(), Value::String("Ethernet".into())),
                    (
                        "InterfaceDescription".into(),
                        Value::String("Synthetic Ethernet Adapter".into()),
                    ),
                    ("Status".into(), Value::String("Up".into())),
                    (
                        "MacAddress".into(),
                        Value::String("00-00-5E-00-53-01".into()),
                    ),
                ]
                .into_iter()
                .collect(),
            )])),
            "get-nettcpconnection" => Some(Value::Array(vec![Value::Map(
                [
                    ("LocalAddress".into(), Value::String("192.0.2.10".into())),
                    ("LocalPort".into(), Value::Number(49_152)),
                    (
                        "RemoteAddress".into(),
                        Value::String("198.51.100.10".into()),
                    ),
                    ("RemotePort".into(), Value::Number(443)),
                    ("State".into(), Value::String("Established".into())),
                ]
                .into_iter()
                .collect(),
            )])),
            "resolve-dnsname" | "nslookup" => {
                let name = named_or_positional(arguments, &["-name"], 0)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .to_string();
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::NetworkIntent,
                        format!("blocked DNS resolution: {name}"),
                    )
                    .with_data("name", &name),
                );
                Some(Value::Map(
                    [
                        ("Name".into(), Value::String(name)),
                        ("Type".into(), Value::String("A".into())),
                        ("IPAddress".into(), Value::String("192.0.2.123".into())),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            "test-netconnection" | "tnc" => {
                let host_name = named_or_positional(arguments, &["-computername", "-host"], 0)
                    .unwrap_or("example.invalid")
                    .trim_matches(['\'', '"'])
                    .to_string();
                let port = named_or_positional(arguments, &["-port"], usize::MAX)
                    .and_then(|value| value.parse::<i64>().ok())
                    .unwrap_or(443);
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::NetworkIntent,
                        format!("blocked connectivity test: {host_name}:{port}"),
                    )
                    .with_data("host", &host_name)
                    .with_data("port", port.to_string()),
                );
                Some(Value::Map(
                    [
                        ("ComputerName".into(), Value::String(host_name)),
                        ("RemotePort".into(), Value::Number(port)),
                        ("TcpTestSucceeded".into(), Value::Bool(false)),
                        ("PingSucceeded".into(), Value::Bool(false)),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            "get-localuser" => Some(Value::Array(vec![Value::Map(
                [
                    ("Name".into(), Value::String("analysis".into())),
                    ("Enabled".into(), Value::Bool(true)),
                    ("SID".into(), Value::String("S-1-5-21-1000".into())),
                ]
                .into_iter()
                .collect(),
            )])),
            "get-localgroupmember" => Some(Value::Array(vec![Value::Map(
                [
                    ("Name".into(), Value::String(r"ANALYSIS\analysis".into())),
                    ("ObjectClass".into(), Value::String("User".into())),
                    ("PrincipalSource".into(), Value::String("Local".into())),
                ]
                .into_iter()
                .collect(),
            )])),
            "get-psdrive" => Some(Value::Array(vec![
                drive("C", "FileSystem", r"C:\"),
                drive("Env", "Environment", ""),
                drive("HKCU", "Registry", "HKEY_CURRENT_USER"),
                drive("HKLM", "Registry", "HKEY_LOCAL_MACHINE"),
                drive("Variable", "Variable", ""),
                drive("Alias", "Alias", ""),
                drive("Function", "Function", ""),
            ])),
            "import-module" => {
                let name = named_or_positional(arguments, &["-name"], 0)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .to_string();
                self.variables.insert(
                    format!("__module:{name}").to_ascii_lowercase(),
                    Value::Bool(true),
                );
                Some(module_value(&name))
            }
            "get-module" => {
                let list_available = find_switch(arguments, "-listavailable").is_some();
                let modules = [
                    "Microsoft.PowerShell.Management",
                    "Microsoft.PowerShell.Utility",
                    "ScheduledTasks",
                    "Defender",
                    "NetTCPIP",
                ]
                .iter()
                .filter(|name| {
                    list_available
                        || self
                            .variables
                            .contains_key(&format!("__module:{name}").to_ascii_lowercase())
                })
                .map(|name| module_value(name))
                .collect();
                Some(Value::Array(modules))
            }
            "remove-module" => {
                let name = named_or_positional(arguments, &["-name"], 0)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .to_string();
                self.variables
                    .remove(&format!("__module:{name}").to_ascii_lowercase());
                Some(Value::Null)
            }
            _ => return ReconDispatch::NotHandled,
        };
        ReconDispatch::Handled(value)
    }

    pub(crate) fn cim_class_value(class: &str) -> Value {
        match class.to_ascii_lowercase().as_str() {
            "win32_operatingsystem" => Value::Map(
                [
                    (
                        "Caption".into(),
                        Value::String("Microsoft Windows 10 Pro".into()),
                    ),
                    ("Version".into(), Value::String("10.0.19045".into())),
                    ("OSArchitecture".into(), Value::String("64-bit".into())),
                    ("BuildNumber".into(), Value::String("19045".into())),
                ]
                .into_iter()
                .collect(),
            ),
            "win32_computersystem" => Value::Map(
                [
                    ("Name".into(), Value::String("ANALYSIS-HOST".into())),
                    ("Domain".into(), Value::String("ANALYSIS".into())),
                    (
                        "UserName".into(),
                        Value::String(r"ANALYSIS\analysis".into()),
                    ),
                    ("Manufacturer".into(), Value::String("Synthetic".into())),
                ]
                .into_iter()
                .collect(),
            ),
            "win32_process" => Value::Array(vec![
                process("powershell.exe", 4_242, 1_337),
                process("explorer.exe", 1_337, 500),
            ]),
            "win32_logicaldisk" => Value::Array(vec![Value::Map(
                [
                    ("DeviceID".into(), Value::String("C:".into())),
                    ("DriveType".into(), Value::Number(3)),
                    ("FreeSpace".into(), Value::Number(32 * 1024 * 1024 * 1024)),
                ]
                .into_iter()
                .collect(),
            )]),
            "win32_networkadapterconfiguration" => Value::Array(vec![Value::Map(
                [
                    (
                        "Description".into(),
                        Value::String("Synthetic Ethernet".into()),
                    ),
                    (
                        "IPAddress".into(),
                        Value::Array(vec![Value::String("192.0.2.10".into())]),
                    ),
                    (
                        "DNSServerSearchOrder".into(),
                        Value::Array(vec![Value::String("192.0.2.53".into())]),
                    ),
                ]
                .into_iter()
                .collect(),
            )]),
            "win32_quickfixengineering" => Value::Array(vec![Value::Map(
                [("HotFixID".into(), Value::String("KB5030001".into()))]
                    .into_iter()
                    .collect(),
            )]),
            "antivirusproduct" => Value::Array(vec![Value::Map(
                [
                    (
                        "displayName".into(),
                        Value::String("Microsoft Defender Antivirus".into()),
                    ),
                    ("productState".into(), Value::Number(397_568)),
                ]
                .into_iter()
                .collect(),
            )]),
            _ => Value::Map(
                [
                    ("ClassName".into(), Value::String(class.into())),
                    ("ComputerName".into(), Value::String("ANALYSIS-HOST".into())),
                ]
                .into_iter()
                .collect(),
            ),
        }
    }
}

fn computer_info() -> Value {
    Value::Map(
        [
            ("CsName".into(), Value::String("ANALYSIS-HOST".into())),
            ("CsDomain".into(), Value::String("ANALYSIS".into())),
            (
                "WindowsProductName".into(),
                Value::String("Windows 10 Pro".into()),
            ),
            ("WindowsVersion".into(), Value::String("22H2".into())),
            ("OsArchitecture".into(), Value::String("64-bit".into())),
            ("PowerShellVersion".into(), Value::String("5.1".into())),
        ]
        .into_iter()
        .collect(),
    )
}

fn service(name: &str, display_name: &str, status: &str) -> Value {
    Value::Map(
        [
            ("Name".into(), Value::String(name.into())),
            ("DisplayName".into(), Value::String(display_name.into())),
            ("Status".into(), Value::String(status.into())),
        ]
        .into_iter()
        .collect(),
    )
}

fn drive(name: &str, provider: &str, root: &str) -> Value {
    Value::Map(
        [
            ("Name".into(), Value::String(name.into())),
            ("Provider".into(), Value::String(provider.into())),
            ("Root".into(), Value::String(root.into())),
        ]
        .into_iter()
        .collect(),
    )
}

fn module_value(name: &str) -> Value {
    Value::Map(
        [
            ("Name".into(), Value::String(name.into())),
            ("Version".into(), Value::String("1.0.0.0".into())),
            ("ModuleType".into(), Value::String("Manifest".into())),
        ]
        .into_iter()
        .collect(),
    )
}

fn process(name: &str, process_id: i64, parent_process_id: i64) -> Value {
    Value::Map(
        [
            ("Name".into(), Value::String(name.into())),
            ("ProcessId".into(), Value::Number(process_id)),
            ("ParentProcessId".into(), Value::Number(parent_process_id)),
        ]
        .into_iter()
        .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulator_core::{AnalysisLimits, VirtualHost};

    #[test]
    fn connectivity_checks_remain_blocked() {
        let mut emulator = PowerShellEmulator::new();
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let ReconDispatch::Handled(Some(Value::Map(values))) = emulator.execute_recon_command(
            "test-netconnection",
            &["example.invalid".into(), "-Port".into(), "443".into()],
            &mut host,
            0,
        ) else {
            panic!("expected result")
        };
        assert_eq!(values["TcpTestSucceeded"], Value::Bool(false));
        assert_eq!(host.snapshot().trace[0].kind, EventKind::NetworkIntent);
    }
}
