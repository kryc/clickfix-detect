use crate::syntax::{find_switch, named_or_positional};
use crate::{PowerShellEmulator, PowerShellError, Value};
use emulator_core::{Engine, EventKind, Host, TraceEvent};

pub(crate) enum SecurityDispatch {
    NotHandled,
    Handled(Option<Value>),
}

impl PowerShellEmulator {
    #[allow(clippy::too_many_lines, clippy::unnecessary_wraps)]
    pub(crate) fn execute_security_command(
        &mut self,
        command: &str,
        arguments: &[String],
        statement: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<SecurityDispatch, PowerShellError> {
        let value = match command {
            "set-mppreference" | "add-mppreference" | "remove-mppreference" => {
                host.write_registry(
                    r"HKLM\Software\EmulatorState\DefenderPreferences",
                    statement,
                    Engine::PowerShell,
                    depth,
                );
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled Microsoft Defender preference change: {command}"),
                );
                Some(Value::Map(
                    [
                        ("Command".into(), Value::String(command.into())),
                        ("Applied".into(), Value::Bool(false)),
                        ("Arguments".into(), Value::String(arguments.join(" "))),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            "get-mppreference" => Some(Value::Map(
                [
                    ("DisableRealtimeMonitoring".into(), Value::Bool(false)),
                    ("DisableScriptScanning".into(), Value::Bool(false)),
                    ("ExclusionPath".into(), Value::Array(Vec::new())),
                    ("ExclusionProcess".into(), Value::Array(Vec::new())),
                ]
                .into_iter()
                .collect(),
            )),
            "get-mpcomputerstatus" => Some(Value::Map(
                [
                    ("AMServiceEnabled".into(), Value::Bool(true)),
                    ("AntivirusEnabled".into(), Value::Bool(true)),
                    ("BehaviorMonitorEnabled".into(), Value::Bool(true)),
                    ("RealTimeProtectionEnabled".into(), Value::Bool(true)),
                ]
                .into_iter()
                .collect(),
            )),
            "set-executionpolicy" => {
                let policy = named_or_positional(arguments, &["-executionpolicy"], 0)
                    .unwrap_or("Restricted")
                    .trim_matches(['\'', '"'])
                    .to_string();
                self.variables
                    .insert("__executionpolicy".into(), Value::String(policy.clone()));
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Command,
                        "modeled execution policy change",
                    )
                    .with_data("policy", &policy)
                    .with_data("applied", "false"),
                );
                Some(Value::String(policy))
            }
            "get-executionpolicy" => Some(
                self.variables
                    .get("__executionpolicy")
                    .cloned()
                    .unwrap_or_else(|| Value::String("RemoteSigned".into())),
            ),
            "clear-history" => {
                host.emit(TraceEvent::new(
                    depth,
                    Engine::PowerShell,
                    EventKind::Command,
                    "modeled PowerShell history clearing",
                ));
                Some(Value::Null)
            }
            "set-psreadlineoption" | "remove-module"
                if arguments
                    .join(" ")
                    .to_ascii_lowercase()
                    .contains("psreadline") =>
            {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    "modeled PowerShell history/logging suppression",
                );
                Some(Value::Null)
            }
            "new-netfirewallrule"
            | "set-netfirewallrule"
            | "remove-netfirewallrule"
            | "set-netfirewallprofile" => {
                host.write_registry(
                    r"HKLM\Software\EmulatorState\Firewall",
                    statement,
                    Engine::PowerShell,
                    depth,
                );
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled firewall modification: {command}"),
                );
                Some(Value::Object("ModeledFirewallRule".into()))
            }
            "new-service" | "set-service" | "start-service" | "stop-service"
            | "restart-service" | "remove-service" => {
                let name = named_or_positional(arguments, &["-name"], 0)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .to_string();
                host.write_registry(
                    &format!(r"HKLM\System\CurrentControlSet\Services\{name}"),
                    statement,
                    Engine::PowerShell,
                    depth,
                );
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled service operation: {command} {name}"),
                );
                Some(service_value(&name, service_status(command)))
            }
            "write-eventlog" | "new-eventlog" | "remove-eventlog" | "limit-eventlog"
            | "clear-eventlog" => {
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::PowerShell,
                        EventKind::Command,
                        format!("modeled event log operation: {command}"),
                    )
                    .with_data("arguments", arguments.join(" ")),
                );
                Some(Value::Null)
            }
            "get-acl" => {
                let path = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default()
                    .trim_matches(['\'', '"'])
                    .to_string();
                Some(Value::Map(
                    [
                        ("Path".into(), Value::String(path)),
                        ("Owner".into(), Value::String(r"ANALYSIS\analysis".into())),
                        (
                            "AccessToString".into(),
                            Value::String("ANALYSIS\\analysis Allow FullControl".into()),
                        ),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            "set-acl" => {
                let path = named_or_positional(arguments, &["-path", "-literalpath"], 0)
                    .unwrap_or_default();
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled ACL modification for {path}"),
                );
                Some(Value::Null)
            }
            "restart-computer" | "stop-computer" => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled system power operation: {command}"),
                );
                Some(Value::Null)
            }
            "disable-netadapter" | "enable-netadapter" => {
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled network adapter operation: {command}"),
                );
                Some(Value::Null)
            }
            "new-scheduledtaskaction" => Some(Value::Map(
                [
                    ("__type".into(), Value::String("ScheduledTaskAction".into())),
                    (
                        "Execute".into(),
                        Value::String(
                            named_or_positional(arguments, &["-execute"], 0)
                                .unwrap_or_default()
                                .trim_matches(['\'', '"'])
                                .into(),
                        ),
                    ),
                    (
                        "Argument".into(),
                        Value::String(
                            named_or_positional(arguments, &["-argument"], usize::MAX)
                                .unwrap_or_default()
                                .trim_matches(['\'', '"'])
                                .into(),
                        ),
                    ),
                ]
                .into_iter()
                .collect(),
            )),
            "new-scheduledtasktrigger" => Some(Value::Map(
                [
                    (
                        "__type".into(),
                        Value::String("ScheduledTaskTrigger".into()),
                    ),
                    (
                        "Kind".into(),
                        Value::String(scheduled_trigger_kind(arguments).into()),
                    ),
                    (
                        "At".into(),
                        Value::String(
                            named_or_positional(arguments, &["-at"], usize::MAX)
                                .unwrap_or_default()
                                .into(),
                        ),
                    ),
                ]
                .into_iter()
                .collect(),
            )),
            "new-scheduledtaskprincipal" => Some(Value::Map(
                [
                    (
                        "__type".into(),
                        Value::String("ScheduledTaskPrincipal".into()),
                    ),
                    (
                        "UserId".into(),
                        Value::String(
                            named_or_positional(arguments, &["-userid"], 0)
                                .unwrap_or_default()
                                .into(),
                        ),
                    ),
                    (
                        "RunLevel".into(),
                        Value::String(
                            named_or_positional(arguments, &["-runlevel"], usize::MAX)
                                .unwrap_or("Limited")
                                .into(),
                        ),
                    ),
                ]
                .into_iter()
                .collect(),
            )),
            "new-scheduledtasksettingsset" => Some(Value::Map(
                [
                    (
                        "__type".into(),
                        Value::String("ScheduledTaskSettings".into()),
                    ),
                    (
                        "Hidden".into(),
                        Value::Bool(find_switch(arguments, "-hidden").is_some()),
                    ),
                ]
                .into_iter()
                .collect(),
            )),
            "register-scheduledtask" => {
                let name = named_or_positional(arguments, &["-taskname"], 0)
                    .unwrap_or("UnnamedTask")
                    .trim_matches(['\'', '"'])
                    .to_string();
                host.write_registry(
                    &format!(r"HKCU\Software\EmulatorState\ScheduledTasks\{name}"),
                    statement,
                    Engine::PowerShell,
                    depth,
                );
                Some(scheduled_task_value(&name, "Ready"))
            }
            "get-scheduledtask" => {
                let name = named_or_positional(arguments, &["-taskname"], 0)
                    .unwrap_or("ModeledTask")
                    .trim_matches(['\'', '"'])
                    .to_string();
                Some(scheduled_task_value(&name, "Ready"))
            }
            "start-scheduledtask" | "unregister-scheduledtask" => {
                let name = named_or_positional(arguments, &["-taskname"], 0)
                    .unwrap_or("ModeledTask")
                    .trim_matches(['\'', '"'])
                    .to_string();
                host.unsupported(
                    Engine::PowerShell,
                    depth,
                    &format!("modeled scheduled task operation: {command} {name}"),
                );
                Some(scheduled_task_value(
                    &name,
                    if command == "start-scheduledtask" {
                        "Running"
                    } else {
                        "Removed"
                    },
                ))
            }
            "register-wmievent" | "register-objectevent" | "register-engineevent" => {
                host.write_registry(
                    r"HKCU\Software\EmulatorState\EventSubscriptions",
                    statement,
                    Engine::PowerShell,
                    depth,
                );
                Some(Value::Map(
                    [
                        ("__type".into(), Value::String("EventSubscriber".into())),
                        ("SourceIdentifier".into(), Value::String(command.into())),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            _ => return Ok(SecurityDispatch::NotHandled),
        };
        Ok(SecurityDispatch::Handled(value))
    }
}

fn service_value(name: &str, status: &str) -> Value {
    Value::Map(
        [
            ("Name".into(), Value::String(name.into())),
            ("DisplayName".into(), Value::String(name.into())),
            ("Status".into(), Value::String(status.into())),
        ]
        .into_iter()
        .collect(),
    )
}

fn service_status(command: &str) -> &'static str {
    match command {
        "start-service" | "restart-service" => "Running",
        "stop-service" => "Stopped",
        "remove-service" => "Removed",
        _ => "Configured",
    }
}

fn scheduled_trigger_kind(arguments: &[String]) -> &'static str {
    if find_switch(arguments, "-atlogon").is_some() {
        "AtLogOn"
    } else if find_switch(arguments, "-atstartup").is_some() {
        "AtStartup"
    } else if find_switch(arguments, "-once").is_some() {
        "Once"
    } else if find_switch(arguments, "-daily").is_some() {
        "Daily"
    } else {
        "Unknown"
    }
}

fn scheduled_task_value(name: &str, state: &str) -> Value {
    Value::Map(
        [
            ("TaskName".into(), Value::String(name.into())),
            ("State".into(), Value::String(state.into())),
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
    fn defender_changes_are_never_applied() {
        let mut emulator = PowerShellEmulator::new();
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let result = emulator
            .execute_security_command(
                "set-mppreference",
                &["-DisableRealtimeMonitoring".into(), "$true".into()],
                "Set-MpPreference -DisableRealtimeMonitoring $true",
                &mut host,
                0,
            )
            .unwrap();

        assert!(matches!(result, SecurityDispatch::Handled(Some(_))));
        assert!(host.snapshot().unsupported_operations > 0);
    }
}
