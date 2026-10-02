use emulator_core::{ArtifactKind, Engine, EventKind, Host, ProcessIntent, TraceEvent};
use regex::Regex;
use std::sync::LazyLock;

use crate::{Runbox, RunboxError};

static DO_SHELL_SCRIPT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)do\s+shell\s+script\s+["']([^"']+)["']"#)
        .expect("valid AppleScript shell regex")
});

impl Runbox {
    pub(crate) fn dispatch_macos_utility(
        &mut self,
        program: &str,
        intent: &ProcessIntent,
    ) -> Result<bool, RunboxError> {
        match program {
            "osascript" => self.emulate_osascript(intent)?,
            "launchctl" => self.emulate_launchctl(intent),
            "open" => self.emulate_open(intent),
            "chmod" => self.emulate_posix_chmod(intent)?,
            "base64" => self.emulate_posix_base64(intent),
            "sudo" | "nohup" | "setsid" | "timeout" => {
                self.emulate_posix_wrapper(program, intent)?;
            }
            "dscl" | "security" => self.emulate_macos_credential_utility(program, intent),
            "xattr" | "spctl" | "defaults" | "scutil" => {
                self.host.emit(
                    TraceEvent::new(
                        intent.depth,
                        Engine::Runbox,
                        EventKind::Command,
                        format!("modeled macOS utility {program}"),
                    )
                    .with_data("arguments", intent.args.join(" ")),
                );
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn emulate_osascript(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let script = intent
            .args
            .windows(2)
            .filter(|pair| pair[0] == "-e")
            .map(|pair| pair[1].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if !script.is_empty() {
            self.host.add_artifact(
                ArtifactKind::Script,
                "osascript.applescript",
                "text/x-applescript",
                script.as_bytes(),
                intent.depth,
            );
            self.record_urls(&script, "osascript", intent.depth);
            for captures in DO_SHELL_SCRIPT_RE.captures_iter(&script) {
                let command = captures.get(1).map_or("", |capture| capture.as_str());
                self.host.process_intent(ProcessIntent {
                    program: "bash".into(),
                    args: vec!["-c".into(), command.into()],
                    command_line: format!("bash -c {command:?}"),
                    origin: "AppleScript do shell script".into(),
                    depth: intent.depth + 1,
                    stdin: Vec::new(),
                    current_directory: intent.current_directory.clone(),
                    causes: intent.causes.clone(),
                })?;
            }
        }
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                "modeled osascript execution",
            )
            .with_data("script_bytes", script.len().to_string()),
        );
        Ok(())
    }

    fn emulate_launchctl(&mut self, intent: &ProcessIntent) {
        let action = intent.args.first().map_or("", String::as_str);
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Persistence,
                format!("modeled launchctl {action}"),
            )
            .with_data("arguments", intent.args.join(" "))
            .with_data("persistence_kind", "macos_launchd"),
        );
        self.record_urls(&intent.command_line, "launchctl arguments", intent.depth);
    }

    fn emulate_open(&mut self, intent: &ProcessIntent) {
        self.record_urls(&intent.command_line, "macOS open", intent.depth);
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                "modeled macOS open request",
            )
            .with_data("arguments", intent.args.join(" ")),
        );
    }

    fn emulate_posix_chmod(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let executable = intent
            .args
            .first()
            .is_some_and(|mode| mode.contains('x') || mode.ends_with("755"));
        if executable {
            for path in intent.args.iter().skip(1) {
                self.host
                    .register_executable(path, Engine::Bash, intent.depth)?;
            }
        }
        Ok(())
    }

    fn emulate_macos_credential_utility(&mut self, program: &str, intent: &ProcessIntent) {
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                format!("modeled macOS credential utility {program}"),
            )
            .with_data(
                "operation",
                intent.args.first().cloned().unwrap_or_default(),
            )
            .with_data("credential_access", "true")
            .with_data("exit_code", "0"),
        );
    }
}
