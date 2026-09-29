use bash_emulator::BashEmulator;
use emulator_core::{ArtifactKind, Engine, EventKind, Host, TraceEvent};

use crate::{Runbox, RunboxError};

impl Runbox {
    pub(crate) fn dispatch_bash_arguments(
        &mut self,
        shell: &str,
        arguments: &[String],
        stdin: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        if let Some(index) = arguments.iter().position(|argument| {
            argument == "-c"
                || argument.starts_with('-')
                    && !argument.starts_with("--")
                    && argument.chars().skip(1).any(|flag| flag == 'c')
        }) {
            let Some(script) = arguments.get(index + 1) else {
                self.host
                    .unsupported(Engine::Bash, depth, "shell -c command was empty");
                return Ok(());
            };
            let positional = arguments.get(index + 2..).unwrap_or_default();
            return self.emulate_bash_with_args(script, shell, positional, depth);
        }

        let script_index = arguments
            .iter()
            .position(|argument| !argument.starts_with('-'));
        if let Some(index) = script_index {
            let path = &arguments[index];
            let Some(bytes) = self.host.read_file(path, Engine::Bash, depth) else {
                self.host.unsupported(
                    Engine::Bash,
                    depth,
                    &format!("shell script is absent from the virtual filesystem: {path}"),
                );
                return Ok(());
            };
            let script = String::from_utf8_lossy(&bytes);
            self.host.add_artifact(
                ArtifactKind::Script,
                "shell-script.sh",
                "text/x-shellscript",
                script.as_bytes(),
                depth,
            );
            return self.emulate_bash_with_args(&script, path, &arguments[index + 1..], depth);
        }

        if !stdin.is_empty() {
            return self.emulate_bash_with_args(&stdin.join("\n"), shell, &[] as &[String], depth);
        }

        self.host.unsupported(
            Engine::Bash,
            depth,
            "interactive shell launch was not emulated",
        );
        Ok(())
    }

    pub(crate) fn emulate_bash(&mut self, script: &str, depth: usize) -> Result<(), RunboxError> {
        self.emulate_bash_with_args(script, "bash", &[], depth)
    }

    pub(crate) fn emulate_bash_with_args(
        &mut self,
        script: &str,
        script_name: &str,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        let mut emulator = BashEmulator::new();
        let result = emulator.emulate_with_args(script, script_name, arguments, self, depth)?;
        self.host.emit(
            TraceEvent::new(depth, Engine::Bash, EventKind::Command, "Bash completed")
                .with_data("exit_code", result.exit_code.to_string()),
        );
        Ok(())
    }
}
