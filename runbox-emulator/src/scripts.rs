use cmd_emulator::CmdEmulator;
use emulator_core::{ArtifactKind, Engine, EventKind, Host, NetworkIntent, TraceEvent};
use regex::Regex;
use std::sync::LazyLock;
use windows_script_emulator::{ScriptError, ScriptHost, ScriptLanguage, WindowsScriptEmulator};

use crate::command_line::{extension, limited, split_windows_command_line, trim_url_punctuation};
use crate::{Runbox, RunboxError};

static SCRIPT_RUN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\b(run|exec|shellexecute|eval)\s*\(\s*(?:"([^"]+)"|'([^']+)')"#)
        .expect("valid script run regex")
});
static CREATE_OBJECT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:createobject|activexobject)\s*\(\s*["']([^"']+)["']\s*\)"#)
        .expect("valid create object regex")
});
static HTTP_OPEN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)\.open\s*\(\s*["'](get|post|put|delete|head)["']\s*,\s*["']([^"']+)["']"#)
        .expect("valid HTTP open regex")
});
static TEXT_FILE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)createtextfile\s*\(\s*["']([^"']+)["'][^)]*\)\s*\.write(?:line)?\s*\(\s*["']([^"']*)["']"#,
    )
    .expect("valid text file regex")
});

impl Runbox {
    pub(crate) fn emulate_mshta(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        self.host
            .consume_step(Engine::Mshta, depth, "emulating mshta")?;
        let target = arguments.join(" ");
        self.host.emit(
            TraceEvent::new(
                depth,
                Engine::Mshta,
                EventKind::Parse,
                "parsed mshta target",
            )
            .with_data("target", limited(&target, 2_048)),
        );

        if target.to_ascii_lowercase().starts_with("javascript:") {
            return self.emulate_windows_script(
                target["javascript:".len()..].trim(),
                ScriptLanguage::JScript,
                ScriptHost::Mshta,
                &[],
                depth,
            );
        }
        if target.to_ascii_lowercase().starts_with("vbscript:") {
            return self.emulate_windows_script(
                target["vbscript:".len()..].trim(),
                ScriptLanguage::VBScript,
                ScriptHost::Mshta,
                &[],
                depth,
            );
        }
        if target.to_ascii_lowercase().starts_with("http://")
            || target.to_ascii_lowercase().starts_with("https://")
        {
            let url = trim_url_punctuation(target.trim_matches('"'));
            if let Some(response) = self.host.network_request(NetworkIntent {
                method: "GET".into(),
                url,
                origin: "mshta remote document".into(),
                depth,
            }) {
                self.host.add_artifact(
                    ArtifactKind::Script,
                    "remote.hta",
                    "application/hta",
                    &response.body,
                    depth,
                );
                return self.emulate_windows_script(
                    &String::from_utf8_lossy(&response.body),
                    ScriptLanguage::JScript,
                    ScriptHost::Mshta,
                    &[],
                    depth + 1,
                );
            }
            return Ok(());
        }

        let path = target.trim_matches('"');
        if let Some(bytes) = self.host.read_file(path, Engine::Mshta, depth) {
            let document = String::from_utf8_lossy(&bytes);
            self.emulate_windows_script(
                &document,
                ScriptLanguage::JScript,
                ScriptHost::Mshta,
                &[],
                depth + 1,
            )?;
        } else {
            self.record_urls(&target, "mshta argument", depth);
            self.host.unsupported(
                Engine::Mshta,
                depth,
                &format!("HTA target is absent from the virtual filesystem: {path}"),
            );
        }
        Ok(())
    }

    pub(crate) fn emulate_wscript(
        &mut self,
        program: &str,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        self.host
            .consume_step(Engine::Wscript, depth, "emulating WSH")?;
        let Some((path_index, path)) = arguments
            .iter()
            .enumerate()
            .find(|(_, argument)| !argument.starts_with("//"))
        else {
            self.host
                .unsupported(Engine::Wscript, depth, "WSH script path was not supplied");
            return Ok(());
        };
        let Some(bytes) = self.host.read_file(path, Engine::Wscript, depth) else {
            self.host.unsupported(
                Engine::Wscript,
                depth,
                &format!("WSH script is absent from the virtual filesystem: {path}"),
            );
            return Ok(());
        };
        let script = String::from_utf8_lossy(&bytes);
        let language = if extension(path) == "vbs" {
            ScriptLanguage::VBScript
        } else {
            ScriptLanguage::JScript
        };
        let host_kind = if program.starts_with("cscript") {
            ScriptHost::CScript
        } else {
            ScriptHost::WScript
        };
        self.emulate_windows_script(
            &script,
            language,
            host_kind,
            &arguments[path_index + 1..],
            depth,
        )
    }

    pub(crate) fn emulate_script_language(
        &mut self,
        script: &str,
        language: ScriptLanguage,
        depth: usize,
    ) -> Result<(), RunboxError> {
        self.emulate_windows_script(script, language, ScriptHost::WScript, &[], depth)
    }

    pub(crate) fn emulate_scriptlet(
        &mut self,
        script: &str,
        language: ScriptLanguage,
        depth: usize,
    ) -> Result<(), RunboxError> {
        self.emulate_windows_script(script, language, ScriptHost::Scriptlet, &[], depth)
    }

    fn emulate_windows_script(
        &mut self,
        script: &str,
        language: ScriptLanguage,
        host_kind: ScriptHost,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        let mut emulator = WindowsScriptEmulator::new();
        let result = match emulator.emulate(script, language, host_kind, arguments, self, depth) {
            Ok(result) => result,
            Err(ScriptError::Syntax(error)) => {
                self.host.warning(format!(
                    "Windows script parser fell back to conservative pattern extraction: {error}"
                ));
                return self.emulate_script_patterns(script, language, depth);
            }
            Err(error) => return Err(error.into()),
        };
        for diagnostic in result.diagnostics {
            self.host.warning(diagnostic);
        }
        self.emit_utility_result(&result.stdout, &result.stderr, result.exit_code, depth);
        Ok(())
    }

    fn emulate_script_patterns(
        &mut self,
        script: &str,
        language: ScriptLanguage,
        depth: usize,
    ) -> Result<(), RunboxError> {
        let engine = Engine::Wscript;
        self.host
            .consume_step(engine, depth, "emulating script language")?;
        self.host.emit(
            TraceEvent::new(
                depth,
                engine,
                EventKind::Parse,
                format!("modeled {} script", language.name()),
            )
            .with_data("bytes", script.len().to_string()),
        );

        for captures in CREATE_OBJECT_RE.captures_iter(script) {
            if let Some(prog_id) = captures.get(1) {
                let supported = [
                    "wscript.shell",
                    "scripting.filesystemobject",
                    "msxml2.xmlhttp",
                    "microsoft.xmlhttp",
                    "adodb.stream",
                    "shell.application",
                ]
                .iter()
                .any(|known| prog_id.as_str().eq_ignore_ascii_case(known));
                if !supported {
                    self.host.unsupported(
                        engine,
                        depth,
                        &format!("unmodeled COM object {}", prog_id.as_str()),
                    );
                }
            }
        }
        for captures in HTTP_OPEN_RE.captures_iter(script) {
            let method = captures
                .get(1)
                .map_or("GET", |value| value.as_str())
                .to_ascii_uppercase();
            let url = captures.get(2).map_or("", |value| value.as_str()).into();
            self.host.network_intent(NetworkIntent {
                method,
                url,
                origin: format!("{} XMLHTTP", language.name()),
                depth,
            });
        }
        for captures in SCRIPT_RUN_RE.captures_iter(script) {
            let method = captures.get(1).map_or("", |value| value.as_str());
            let command = captures
                .get(2)
                .or_else(|| captures.get(3))
                .map_or("", |value| value.as_str());
            if !command.is_empty() {
                if method.eq_ignore_ascii_case("eval") {
                    self.emulate_script_language(command, language, depth + 1)?;
                } else {
                    let words = split_windows_command_line(command);
                    if let Some(program) = words.first() {
                        self.queue_process(program, words[1..].to_vec(), language.name(), depth)?;
                    }
                }
            }
        }
        for captures in TEXT_FILE_RE.captures_iter(script) {
            let path = captures.get(1).map_or("", |value| value.as_str());
            let content = captures.get(2).map_or("", |value| value.as_str());
            self.host
                .write_file(path, content.as_bytes(), false, engine, depth)?;
        }
        self.record_urls(script, language.name(), depth);
        Ok(())
    }

    pub(crate) fn emulate_shell_association(
        &mut self,
        path: &str,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        self.host.consume_step(
            Engine::ShellAssociation,
            depth,
            "resolving shell association",
        )?;
        let extension = extension(path);
        let Some(bytes) =
            self.host
                .read_file(path.trim_matches('"'), Engine::ShellAssociation, depth)
        else {
            self.host.unsupported(
                Engine::ShellAssociation,
                depth,
                &format!("associated file is absent from the virtual filesystem: {path}"),
            );
            return Ok(());
        };
        let content = String::from_utf8_lossy(&bytes);
        if extension == "ps1" {
            self.emulate_powershell(&content, depth + 1)
        } else if matches!(extension.as_str(), "cmd" | "bat") {
            let mut emulator = CmdEmulator::new();
            emulator.emulate_batch_with_args(
                &content,
                path.trim_matches('"'),
                arguments,
                self,
                depth + 1,
            )?;
            Ok(())
        } else if extension == "js" {
            self.emulate_windows_script(
                &content,
                ScriptLanguage::JScript,
                ScriptHost::WScript,
                arguments,
                depth + 1,
            )
        } else if extension == "vbs" {
            self.emulate_windows_script(
                &content,
                ScriptLanguage::VBScript,
                ScriptHost::WScript,
                arguments,
                depth + 1,
            )
        } else if extension == "hta" {
            self.emulate_mshta(&[path.into()], depth + 1)
        } else {
            self.host.unsupported(
                Engine::ShellAssociation,
                depth,
                &format!("unsupported file association: {path}"),
            );
            Ok(())
        }
    }
}

trait ScriptLanguageName {
    fn name(self) -> &'static str;
}

impl ScriptLanguageName for ScriptLanguage {
    fn name(self) -> &'static str {
        match self {
            Self::JScript => "JScript",
            Self::VBScript => "VBScript",
        }
    }
}
