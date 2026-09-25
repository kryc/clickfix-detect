mod archive_utilities;
mod artifacts;
mod cmd;
mod command_line;
mod launcher_utilities;
mod lolbins;
mod powershell;
mod process;
mod scripts;
mod system_utilities;

use cmd_emulator::CmdError;
use emulator_core::{
    AnalysisLimits, Engine, EventKind, Host, HostError, HostSnapshot, NetworkPolicy, ProcessIntent,
    TraceEvent, VirtualHost,
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
    pub fn host(&self) -> &VirtualHost {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut VirtualHost {
        &mut self.host
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
        };
        self.dispatch_process(&intent)
    }

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
        if let Some(result) = self.dispatch_extended_utility(&program, intent) {
            return result;
        }
        if self.dispatch_lolbin_utility(&program, intent) {
            return Ok(());
        }

        match program.as_str() {
            "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => {
                self.dispatch_powershell_arguments(&intent.args, intent.depth)
            }
            "cmd" | "cmd.exe" => self.emulate_cmd(&intent.args, intent.depth),
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
}

#[cfg(test)]
mod tests;
