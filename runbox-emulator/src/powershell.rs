use base64::Engine as _;
use emulator_core::{ArtifactKind, Engine, EventKind, Host, TraceEvent};
use powershell_emulator::PowerShellEmulator;

use crate::command_line::find_argument;
use crate::{Runbox, RunboxError};

impl Runbox {
    pub(crate) fn dispatch_powershell_arguments(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        if let Some(index) = find_argument(
            arguments,
            &["-encodedcommand", "-enc", "-e", "/encodedcommand"],
        ) {
            if let Some(encoded) = arguments.get(index + 1) {
                match base64::engine::general_purpose::STANDARD.decode(encoded.trim()) {
                    Ok(bytes) => {
                        let script = decode_powershell_encoded_command(&bytes);
                        self.host.add_artifact(
                            ArtifactKind::Script,
                            "encoded-command.ps1",
                            "text/x-powershell",
                            script.as_bytes(),
                            depth,
                        );
                        self.host.emit(
                            TraceEvent::new(
                                depth,
                                Engine::Runbox,
                                EventKind::Decode,
                                "decoded PowerShell -EncodedCommand",
                            )
                            .with_data("decoded_bytes", script.len().to_string()),
                        );
                        return self.emulate_powershell(&script, depth);
                    }
                    Err(error) => {
                        self.host.unsupported(
                            Engine::Runbox,
                            depth,
                            &format!("invalid PowerShell encoded command: {error}"),
                        );
                        return Ok(());
                    }
                }
            }
        }

        if let Some(index) = find_argument(arguments, &["-file", "-f"]) {
            if let Some(path) = arguments.get(index + 1) {
                if let Some(bytes) = self.host.read_file(path, Engine::Runbox, depth) {
                    return self.emulate_powershell(&String::from_utf8_lossy(&bytes), depth);
                }
                self.host.unsupported(
                    Engine::Runbox,
                    depth,
                    &format!(
                        "PowerShell -File target is absent from the virtual filesystem: {path}"
                    ),
                );
                return Ok(());
            }
        }

        if let Some(index) = find_argument(arguments, &["-command", "-c"]) {
            let script = arguments[index + 1..].join(" ");
            return self.emulate_powershell(&script, depth);
        }

        let script = arguments
            .iter()
            .filter(|argument| !is_powershell_flag(argument))
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
        if !script.is_empty() {
            self.emulate_powershell(&script, depth)?;
        }
        Ok(())
    }

    pub(crate) fn emulate_powershell(
        &mut self,
        script: &str,
        depth: usize,
    ) -> Result<(), RunboxError> {
        let mut emulator = PowerShellEmulator::new();
        emulator.emulate(script, self, depth)?;
        Ok(())
    }
}

fn decode_powershell_encoded_command(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes.len() % 2 == 0 {
        let odd_zeroes = bytes
            .iter()
            .skip(1)
            .step_by(2)
            .filter(|byte| **byte == 0)
            .count();
        if odd_zeroes * 4 >= bytes.len() {
            return String::from_utf16_lossy(
                &bytes
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .collect::<Vec<_>>(),
            );
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn is_powershell_flag(argument: &str) -> bool {
    [
        "-noprofile",
        "-nop",
        "-noninteractive",
        "-noni",
        "-windowstyle",
        "-w",
        "-executionpolicy",
        "-ep",
        "-sta",
        "-mta",
    ]
    .iter()
    .any(|flag| argument.eq_ignore_ascii_case(flag))
}
