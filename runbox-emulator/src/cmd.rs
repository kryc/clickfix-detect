use cmd_emulator::CmdEmulator;
use emulator_core::{Engine, EventKind, Host, TraceEvent};

use crate::{Runbox, RunboxError};

impl Runbox {
    pub(crate) fn emulate_cmd(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        let delayed_expansion = arguments
            .iter()
            .any(|argument| argument.eq_ignore_ascii_case("/v:on"));
        let command_start = arguments
            .iter()
            .position(|argument| {
                argument.eq_ignore_ascii_case("/c") || argument.eq_ignore_ascii_case("/k")
            })
            .map_or(0, |index| index + 1);
        let command = arguments[command_start..].join(" ");
        if command.trim().is_empty() {
            self.host
                .unsupported(Engine::Cmd, depth, "cmd.exe command was empty");
            return Ok(());
        }
        let mut emulator = CmdEmulator::new().with_delayed_expansion(delayed_expansion);
        let result = emulator.emulate(&command, self, depth)?;
        self.host.emit(
            TraceEvent::new(depth, Engine::Cmd, EventKind::Command, "cmd.exe completed")
                .with_data("exit_code", result.exit_code.to_string()),
        );
        Ok(())
    }
}
