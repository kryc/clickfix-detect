mod archive_utilities;
mod artifacts;
mod bash;
mod cmd;
mod command_line;
mod launcher_utilities;
mod linux;
mod lolbins;
mod macos;
mod powershell;
mod process;
mod scripts;
mod system_utilities;

use bash_emulator::BashError;
use cmd_emulator::CmdError;
use emulator_core::{
    AnalysisLimits, Engine, EventKind, Host, HostError, HostPlatform, HostSnapshot, NetworkPolicy,
    ProcessIntent, TraceEvent, VirtualHost,
};
use powershell_emulator::PowerShellError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use windows_script_emulator::ScriptError;

use command_line::{
    basename, expand_environment_variables, has_script_extension, limited,
    split_windows_command_line,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "content", rename_all = "snake_case")]
pub enum RunboxInput {
    RawCommand(String),
    PowerShellScript(String),
    BashScript(String),
    LinuxShellScript(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunboxResult {
    pub snapshot: HostSnapshot,
}

#[derive(Debug, Error)]
pub enum RunboxError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    PowerShell(#[from] PowerShellError),
    #[error(transparent)]
    Cmd(#[from] CmdError),
    #[error(transparent)]
    Bash(#[from] BashError),
    #[error(transparent)]
    WindowsScript(#[from] ScriptError),
}

#[derive(Debug)]
pub struct Runbox {
    host: VirtualHost,
}

impl Default for Runbox {
    fn default() -> Self {
        Self::new(AnalysisLimits::default())
    }
}

impl Runbox {
    #[must_use]
    pub fn new(limits: AnalysisLimits) -> Self {
        Self {
            host: VirtualHost::new(limits),
        }
    }

    #[must_use]
    pub fn new_macos(limits: AnalysisLimits) -> Self {
        Self {
            host: VirtualHost::macos(limits),
        }
    }

    #[must_use]
    pub fn new_linux(limits: AnalysisLimits) -> Self {
        Self {
            host: VirtualHost::linux(limits),
        }
    }

    #[must_use]
    pub fn host(&self) -> &VirtualHost {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut VirtualHost {
        &mut self.host
    }

    /// Dispatch process intents queued by nested emulator activity.
    ///
    /// # Errors
    ///
    /// Returns an error when a queued child emulator reaches a host resource
    /// limit or cannot complete its modeled execution.
    pub fn drain_pending_processes(&mut self) -> Result<(), RunboxError> {
        self.drain_process_intents()
    }

    #[must_use]
    pub fn with_network_policy(mut self, policy: NetworkPolicy) -> Self {
        self.host.set_network_policy(policy);
        self
    }

    /// Emulate one command or `PowerShell` script and return a host snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when a nested emulator fails or a configured host
    /// resource limit rejects an operation.
    pub fn emulate(&mut self, input: RunboxInput) -> Result<RunboxResult, RunboxError> {
        match input {
            RunboxInput::RawCommand(command) => {
                self.host.emit(
                    TraceEvent::new(
                        0,
                        Engine::Runbox,
                        EventKind::Input,
                        "received raw command input",
                    )
                    .with_data("command", limited(&command, 2_048)),
                );
                self.dispatch_command_line(&command, 0, "analysis input")?;
            }
            RunboxInput::PowerShellScript(script) => {
                self.host.emit(
                    TraceEvent::new(
                        0,
                        Engine::Runbox,
                        EventKind::Input,
                        "received PowerShell script input",
                    )
                    .with_data("bytes", script.len().to_string()),
                );
                self.emulate_powershell(&script, 0)?;
            }
            RunboxInput::BashScript(script) => {
                self.host.emit(
                    TraceEvent::new(
                        0,
                        Engine::Runbox,
                        EventKind::Input,
                        "received Bash script input",
                    )
                    .with_data("bytes", script.len().to_string()),
                );
                self.emulate_bash(&script, 0)?;
            }
            RunboxInput::LinuxShellScript(script) => {
                self.host.emit(
                    TraceEvent::new(
                        0,
                        Engine::Runbox,
                        EventKind::Input,
                        "received Linux shell script input",
                    )
                    .with_data("bytes", script.len().to_string()),
                );
                self.emulate_bash(&script, 0)?;
            }
        }
        self.drain_process_intents()?;
        Ok(RunboxResult {
            snapshot: self.host.snapshot(),
        })
    }

    fn drain_process_intents(&mut self) -> Result<(), RunboxError> {
        loop {
            let intents = self.host.take_process_intents();
            if intents.is_empty() {
                return Ok(());
            }
            for intent in intents {
                if let Err(error) = self.dispatch_process(&intent) {
                    match error {
                        RunboxError::Host(error)
                        | RunboxError::Cmd(CmdError::Host(error))
                        | RunboxError::Bash(BashError::Host(error))
                        | RunboxError::PowerShell(PowerShellError::Host(error))
                        | RunboxError::WindowsScript(ScriptError::Host(error)) => {
                            return Err(error.into());
                        }
                        error => self.host.unsupported(
                            Engine::Runbox,
                            intent.depth,
                            &format!(
                                "child process emulation failed for {}: {error}",
                                intent.command_line
                            ),
                        ),
                    }
                }
            }
        }
    }

    fn dispatch_command_line(
        &mut self,
        command_line: &str,
        depth: usize,
        origin: &str,
    ) -> Result<(), RunboxError> {
        self.host
            .consume_step(Engine::Runbox, depth, "dispatching command line")?;
        let command_line =
            expand_environment_variables(command_line, &self.host.environment_entries());
        let arguments = split_windows_command_line(&command_line);
        let Some(program) = arguments.first() else {
            return Ok(());
        };
        let intent = ProcessIntent {
            program: program.clone(),
            args: arguments[1..].to_vec(),
            command_line,
            origin: origin.into(),
            depth,
            stdin: Vec::new(),
            current_directory: String::new(),
            causes: Vec::new(),
        };
        self.dispatch_process(&intent)
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_process(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        self.host
            .consume_step(Engine::Runbox, intent.depth, "dispatching virtual process")?;
        let program = basename(&intent.program).to_ascii_lowercase();
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                format!("dispatching virtual executable {program}"),
            )
            .with_data("origin", &intent.origin)
            .with_data("command_line", limited(&intent.command_line, 2_048)),
        );
        if self.block_virtual_binary_execution(intent) {
            return Ok(());
        }
        if let Some(result) = self.dispatch_extended_utility(&program, intent) {
            return result;
        }
        if self.dispatch_lolbin_utility(&program, intent) {
            return Ok(());
        }
        match self.host.platform() {
            HostPlatform::MacOs if self.dispatch_macos_utility(&program, intent)? => {
                return Ok(());
            }
            HostPlatform::Linux if self.dispatch_linux_utility(&program, intent)? => {
                return Ok(());
            }
            HostPlatform::Windows | HostPlatform::MacOs | HostPlatform::Linux => {}
        }

        match program.as_str() {
            "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => {
                self.dispatch_powershell_arguments(&intent.args, intent.depth)
            }
            "cmd" | "cmd.exe" => self.emulate_cmd(&intent.args, intent.depth),
            "bash" | "sh" | "zsh" => {
                self.dispatch_bash_arguments(&program, &intent.args, &intent.stdin, intent.depth)
            }
            "mshta" | "mshta.exe" => self.emulate_mshta(&intent.args, intent.depth),
            "wscript" | "wscript.exe" | "cscript" | "cscript.exe" => {
                self.emulate_wscript(&program, &intent.args, intent.depth)
            }
            "rundll32" | "rundll32.exe" => self.emulate_rundll32(&intent.args, intent.depth),
            "regsvr32" | "regsvr32.exe" => self.emulate_regsvr32(&intent.args, intent.depth),
            "curl" | "curl.exe" | "wget" | "wget.exe" => {
                self.emulate_downloader(&program, &intent.args, intent.depth)
            }
            "bitsadmin" | "bitsadmin.exe" => self.emulate_bitsadmin(&intent.args, intent.depth),
            "certutil" | "certutil.exe" => self.emulate_certutil(&intent.args, intent.depth),
            "reg" | "reg.exe" => {
                self.emulate_reg(&intent.args, intent.depth);
                Ok(())
            }
            "find" | "find.exe" => {
                self.emulate_find(intent, false);
                Ok(())
            }
            "findstr" | "findstr.exe" => {
                self.emulate_find(intent, true);
                Ok(())
            }
            "more" | "more.com" => {
                self.emulate_more(intent);
                Ok(())
            }
            "sort" | "sort.exe" => {
                self.emulate_sort(intent);
                Ok(())
            }
            "xcopy" | "xcopy.exe" | "robocopy" | "robocopy.exe" => {
                self.emulate_copy_utility(&program, intent)
            }
            "attrib" | "attrib.exe" => {
                self.emulate_attrib(intent);
                Ok(())
            }
            "chcp" | "chcp.com" => {
                self.emulate_chcp(intent);
                Ok(())
            }
            "schtasks" | "schtasks.exe" => self.emulate_schtasks(&intent.args, intent.depth),
            "sc" | "sc.exe" => self.emulate_sc(&intent.args, intent.depth),
            "netsh" | "netsh.exe" => {
                self.emulate_netsh(&intent.args, intent.depth);
                Ok(())
            }
            "wmic" | "wmic.exe" => self.emulate_wmic(&intent.args, intent.depth),
            "wevtutil" | "wevtutil.exe" | "auditpol" | "auditpol.exe" | "cmdkey" | "cmdkey.exe" => {
                self.emulate_system_audit_utility(&program, &intent.args, intent.depth);
                Ok(())
            }
            "msiexec" | "msiexec.exe" => {
                self.emulate_msiexec(&intent.args, intent.depth);
                Ok(())
            }
            _ if has_script_extension(&intent.program) => {
                self.emulate_shell_association(&intent.program, &intent.args, intent.depth)
            }
            _ => {
                self.record_urls(
                    &intent.command_line,
                    &format!("unmodeled process {program}"),
                    intent.depth,
                );
                self.host.unsupported(
                    Engine::Runbox,
                    intent.depth,
                    &format!("unsupported executable: {program}"),
                );
                Ok(())
            }
        }
    }

    fn block_virtual_binary_execution(&mut self, intent: &ProcessIntent) -> bool {
        let Some(path) = self.virtual_program_path(intent) else {
            return false;
        };
        if self
            .host
            .inspect_virtual_binary(&path, Engine::Runbox, intent.depth)
            .is_none()
        {
            return false;
        }
        self.record_urls(
            &intent.command_line,
            &format!("attempted virtual binary execution {path}"),
            intent.depth,
        );
        self.host.unsupported(
            Engine::Runbox,
            intent.depth,
            &format!(
                "unsupported executable: native binary execution intentionally not performed: {path}"
            ),
        );
        true
    }

    fn virtual_program_path(&self, intent: &ProcessIntent) -> Option<String> {
        if self.host.virtual_file(&intent.program).is_some() {
            return Some(intent.program.clone());
        }
        if intent.current_directory.is_empty() || is_absolute_path(&intent.program) {
            return None;
        }
        let separator = match self.host.platform() {
            HostPlatform::Windows => '\\',
            HostPlatform::MacOs | HostPlatform::Linux => '/',
        };
        let candidate = format!(
            "{}{separator}{}",
            intent.current_directory.trim_end_matches(['/', '\\']),
            intent.program
        );
        self.host
            .virtual_file(&candidate)
            .is_some()
            .then_some(candidate)
    }
}

fn is_absolute_path(path: &str) -> bool {
    path.starts_with(['/', '\\'])
        || path
            .as_bytes()
            .get(1)
            .is_some_and(|separator| *separator == b':')
}

#[cfg(test)]
mod tests;
