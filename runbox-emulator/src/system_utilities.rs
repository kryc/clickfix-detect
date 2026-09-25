use emulator_core::{ArtifactKind, Engine, Host, NetworkIntent};

use crate::artifacts::first_url;
use crate::{Runbox, RunboxError};

impl Runbox {
    pub(crate) fn emulate_schtasks(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        let name = switch_value(arguments, &["/tn"]).unwrap_or_else(|| "UnnamedTask".into());
        let path = format!(
            r"HKLM\Software\EmulatorState\ScheduledTasks\{}",
            sanitize_key(&name)
        );
        if has_switch(arguments, "/create") {
            let command = switch_value(arguments, &["/tr"]).unwrap_or_default();
            let schedule = switch_value(arguments, &["/sc"]).unwrap_or_else(|| "ONCE".into());
            let value = format!("TR={command};SC={schedule};STATE=Ready");
            self.host
                .write_registry(&path, &value, Engine::Runbox, depth);
            self.emit_utility_result(
                &[format!(
                    "SUCCESS: The scheduled task \"{name}\" has been created."
                )],
                &[],
                0,
                depth,
            );
        } else if has_switch(arguments, "/delete") {
            let removed = self
                .host
                .delete_registry(&path, true, Engine::Runbox, depth);
            self.emit_utility_result(
                &[],
                &(!matches!(removed, 0)).then(Vec::new).unwrap_or_else(|| {
                    vec![format!(
                        "ERROR: The system cannot find the task named \"{name}\"."
                    )]
                }),
                i32::from(removed == 0),
                depth,
            );
        } else if has_switch(arguments, "/run") {
            if let Some(value) = self.host.read_registry(&path, Engine::Runbox, depth) {
                if let Some(command) = field(&value, "TR") {
                    self.dispatch_command_line(command, depth + 1, "schtasks /run")?;
                }
                self.emit_utility_result(
                    &[format!(
                        "SUCCESS: Attempted to run the scheduled task \"{name}\"."
                    )],
                    &[],
                    0,
                    depth,
                );
            } else {
                self.emit_utility_result(
                    &[],
                    &[format!(
                        "ERROR: The system cannot find the task named \"{name}\"."
                    )],
                    1,
                    depth,
                );
            }
        } else {
            let values = self
                .host
                .list_registry(
                    r"HKLM\Software\EmulatorState\ScheduledTasks",
                    Engine::Runbox,
                    depth,
                )
                .into_iter()
                .map(|(path, value)| {
                    format!(
                        "TaskName: {}  Status: {}",
                        path.rsplit('\\').next().unwrap_or(&path),
                        field(&value, "STATE").unwrap_or("Ready")
                    )
                })
                .collect::<Vec<_>>();
            self.emit_utility_result(&values, &[], 0, depth);
        }
        Ok(())
    }

    pub(crate) fn emulate_sc(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        let Some(operation) = arguments.first().map(|value| value.to_ascii_lowercase()) else {
            self.emit_utility_result(&[], &["DESCRIPTION: SC command".into()], 1, depth);
            return Ok(());
        };
        let name = arguments.get(1).cloned().unwrap_or_default();
        let path = format!(
            r"HKLM\System\CurrentControlSet\Services\{}",
            sanitize_key(&name)
        );
        match operation.as_str() {
            "create" | "config" => self.configure_service(arguments, depth, &operation, &path),
            "start" => self.start_service(depth, &path)?,
            "stop" => self.stop_service(depth, &path),
            "delete" => self.delete_service(depth, &path),
            _ => self.query_service(depth, &name, &path),
        }
        Ok(())
    }

    fn configure_service(
        &mut self,
        arguments: &[String],
        depth: usize,
        operation: &str,
        path: &str,
    ) {
        let bin_path = assignment_value(arguments, "binpath").unwrap_or_default();
        let start = assignment_value(arguments, "start").unwrap_or_else(|| "demand".into());
        self.host.write_registry(
            path,
            &format!("BINPATH={bin_path};START={start};STATE=Stopped"),
            Engine::Runbox,
            depth,
        );
        self.emit_utility_result(
            &[format!(
                "[SC] {}Service SUCCESS",
                operation.to_ascii_uppercase()
            )],
            &[],
            0,
            depth,
        );
    }

    fn start_service(&mut self, depth: usize, path: &str) -> Result<(), RunboxError> {
        let Some(value) = self.host.read_registry(path, Engine::Runbox, depth) else {
            self.emit_missing_service(depth);
            return Ok(());
        };
        if let Some(command) = field(&value, "BINPATH") {
            self.dispatch_command_line(command, depth + 1, "sc start")?;
        }
        self.host.write_registry(
            path,
            &replace_field(&value, "STATE", "Running"),
            Engine::Runbox,
            depth,
        );
        self.emit_utility_result(&["SERVICE_START_PENDING".into()], &[], 0, depth);
        Ok(())
    }

    fn stop_service(&mut self, depth: usize, path: &str) {
        let Some(value) = self.host.read_registry(path, Engine::Runbox, depth) else {
            self.emit_missing_service(depth);
            return;
        };
        self.host.write_registry(
            path,
            &replace_field(&value, "STATE", "Stopped"),
            Engine::Runbox,
            depth,
        );
        self.emit_utility_result(&["SERVICE_STOP_PENDING".into()], &[], 0, depth);
    }

    fn delete_service(&mut self, depth: usize, path: &str) {
        let removed = self.host.delete_registry(path, true, Engine::Runbox, depth);
        if removed > 0 {
            self.emit_utility_result(&["[SC] DeleteService SUCCESS".into()], &[], 0, depth);
        } else {
            self.emit_missing_service(depth);
        }
    }

    fn query_service(&mut self, depth: usize, name: &str, path: &str) {
        let Some(value) = self.host.read_registry(path, Engine::Runbox, depth) else {
            self.emit_missing_service(depth);
            return;
        };
        self.emit_utility_result(
            &[format!(
                "SERVICE_NAME: {name}\n        STATE              : {}",
                field(&value, "STATE").unwrap_or("Stopped")
            )],
            &[],
            0,
            depth,
        );
    }

    fn emit_missing_service(&mut self, depth: usize) {
        self.emit_utility_result(&[], &["[SC] OpenService FAILED 1060".into()], 1060, depth);
    }

    pub(crate) fn emulate_netsh(&mut self, arguments: &[String], depth: usize) {
        let command = arguments.join(" ");
        let normalized = command.to_ascii_lowercase();
        if normalized.contains("advfirewall")
            && normalized.contains("firewall")
            && normalized.contains("add")
            && normalized.contains("rule")
        {
            let name = assignment_value(arguments, "name").unwrap_or_else(|| "UnnamedRule".into());
            self.host.write_registry(
                &format!(
                    r"HKLM\Software\EmulatorState\Firewall\{}",
                    sanitize_key(&name)
                ),
                &command,
                Engine::Runbox,
                depth,
            );
        } else if normalized.contains("portproxy") && normalized.contains("add") {
            let port = assignment_value(arguments, "listenport").unwrap_or_else(|| "0".into());
            self.host.write_registry(
                &format!(r"HKLM\Software\EmulatorState\PortProxy\{port}"),
                &command,
                Engine::Runbox,
                depth,
            );
        } else if normalized.contains("delete") {
            self.host.unsupported(
                Engine::Runbox,
                depth,
                &format!("modeled netsh deletion intent: {command}"),
            );
        }
        self.emit_utility_result(&["Ok.".into()], &[], 0, depth);
    }

    pub(crate) fn emulate_wmic(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        let command = arguments.join(" ");
        let lower = command.to_ascii_lowercase();
        if lower.starts_with("process call create") {
            let requested = command["process call create".len()..]
                .trim()
                .trim_matches('"');
            self.dispatch_command_line(requested, depth + 1, "wmic process call create")?;
            self.emit_utility_result(
                &[
                    "Executing (Win32_Process)->Create()".into(),
                    "Method execution successful.".into(),
                    "ReturnValue = 0;".into(),
                ],
                &[],
                0,
                depth,
            );
        } else if let Some(url) = first_url(&command) {
            let response = self.host.network_request(NetworkIntent {
                method: "GET".into(),
                url,
                origin: "wmic remote XSL".into(),
                depth,
            });
            if let Some(response) = response {
                self.host.add_artifact(
                    ArtifactKind::Script,
                    "wmic-format.xsl",
                    "application/xml",
                    &response.body,
                    depth,
                );
            }
            self.host.unsupported(
                Engine::Runbox,
                depth,
                "WMIC remote XSL was retrieved but not executed",
            );
        } else {
            self.host
                .unsupported(Engine::Runbox, depth, "unsupported WMIC invocation");
        }
        Ok(())
    }

    pub(crate) fn emulate_system_audit_utility(
        &mut self,
        program: &str,
        arguments: &[String],
        depth: usize,
    ) {
        let command = arguments.join(" ");
        match program {
            "wevtutil" | "wevtutil.exe" => {
                self.host.unsupported(
                    Engine::Runbox,
                    depth,
                    &format!("modeled event log modification: {command}"),
                );
            }
            "auditpol" | "auditpol.exe" => {
                self.host.write_registry(
                    r"HKLM\Software\EmulatorState\AuditPolicy",
                    &command,
                    Engine::Runbox,
                    depth,
                );
            }
            "cmdkey" | "cmdkey.exe" => {
                let target = switch_value(arguments, &["/add"]).unwrap_or_else(|| "unknown".into());
                let user = switch_value(arguments, &["/user"]).unwrap_or_default();
                self.host.write_registry(
                    &format!(
                        r"HKCU\Software\EmulatorState\CredentialTargets\{}",
                        sanitize_key(&target)
                    ),
                    &format!("USER={user};PASSWORD=<redacted>"),
                    Engine::Runbox,
                    depth,
                );
            }
            _ => {}
        }
        self.emit_utility_result(&[], &[], 0, depth);
    }

    pub(crate) fn emulate_msiexec(&mut self, arguments: &[String], depth: usize) {
        let package = switch_value(arguments, &["/i", "/package"])
            .or_else(|| {
                arguments
                    .iter()
                    .find(|argument| !argument.starts_with('/'))
                    .cloned()
            })
            .unwrap_or_default();
        let bytes = if package.to_ascii_lowercase().starts_with("http") {
            self.host
                .network_request(NetworkIntent {
                    method: "GET".into(),
                    url: package.clone(),
                    origin: "msiexec remote package".into(),
                    depth,
                })
                .map(|response| response.body)
        } else {
            self.host.read_file(&package, Engine::Runbox, depth)
        };
        if let Some(bytes) = bytes {
            self.host.add_artifact(
                ArtifactKind::Binary,
                "installer.msi",
                "application/x-msi",
                &bytes,
                depth,
            );
        }
        self.host.unsupported(
            Engine::Runbox,
            depth,
            &format!("MSI installation was blocked: {}", arguments.join(" ")),
        );
        self.emit_utility_result(&[], &[], 0, depth);
    }
}

fn has_switch(arguments: &[String], requested: &str) -> bool {
    arguments.iter().any(|argument| {
        argument
            .split_once(':')
            .map_or(argument.as_str(), |(name, _)| name)
            .eq_ignore_ascii_case(requested)
    })
}

fn switch_value(arguments: &[String], names: &[&str]) -> Option<String> {
    for (index, argument) in arguments.iter().enumerate() {
        for name in names {
            if let Some((candidate, value)) = argument.split_once(':') {
                if candidate.eq_ignore_ascii_case(name) {
                    return Some(value.trim_matches('"').into());
                }
            }
            if argument.eq_ignore_ascii_case(name) {
                return arguments
                    .get(index + 1)
                    .map(|value| value.trim_matches('"').into());
            }
        }
    }
    None
}

fn assignment_value(arguments: &[String], name: &str) -> Option<String> {
    let normalized = name.trim_end_matches('=');
    for (index, argument) in arguments.iter().enumerate() {
        if let Some((candidate, value)) = argument.split_once('=') {
            if candidate.eq_ignore_ascii_case(normalized) {
                if value.is_empty() {
                    return arguments
                        .get(index + 1)
                        .map(|value| value.trim_matches('"').into());
                }
                return Some(value.trim_matches('"').into());
            }
        }
        if argument
            .trim_end_matches('=')
            .eq_ignore_ascii_case(normalized)
        {
            return arguments
                .get(index + 1)
                .map(|value| value.trim_matches('"').into());
        }
    }
    None
}

fn field<'a>(value: &'a str, name: &str) -> Option<&'a str> {
    value.split(';').find_map(|field| {
        let (candidate, value) = field.split_once('=')?;
        candidate.eq_ignore_ascii_case(name).then_some(value)
    })
}

fn replace_field(value: &str, name: &str, replacement: &str) -> String {
    let mut found = false;
    let mut fields = value
        .split(';')
        .map(|field| {
            let Some((candidate, _)) = field.split_once('=') else {
                return field.into();
            };
            if candidate.eq_ignore_ascii_case(name) {
                found = true;
                format!("{candidate}={replacement}")
            } else {
                field.into()
            }
        })
        .collect::<Vec<String>>();
    if !found {
        fields.push(format!("{name}={replacement}"));
    }
    fields.join(";")
}

fn sanitize_key(value: &str) -> String {
    value.replace(['\\', '/', ':'], "_")
}
