use std::collections::BTreeMap;
use std::sync::LazyLock;

use emulator_core::{ArtifactKind, Engine, Host, NetworkIntent, ProcessIntent};
use regex::Regex;

use crate::command_line::{extension, quote_argument, resolve_process_path, wildcard_match};
use crate::{Runbox, RunboxError};

static MSBUILD_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<Exec\b[^>]*\bCommand\s*=\s*["']([^"']+)["']"#)
        .expect("valid MSBuild Exec regex")
});
static PROCESS_START_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)Process\.Start\s*\(\s*["']([^"']+)["'](?:\s*,\s*["']([^"']*)["'])?\s*\)"#)
        .expect("valid Process.Start regex")
});

impl Runbox {
    pub(crate) fn dispatch_extended_utility(
        &mut self,
        program: &str,
        intent: &ProcessIntent,
    ) -> Option<Result<(), RunboxError>> {
        match program {
            "makecab" | "makecab.exe" => Some(self.emulate_makecab(intent)),
            "expand" | "expand.exe" => Some(self.emulate_expand(intent)),
            "extrac32" | "extrac32.exe" => Some(self.emulate_extrac32(intent)),
            "tar" | "tar.exe" => Some(self.emulate_tar(intent)),
            "msbuild" | "msbuild.exe" => Some(self.emulate_msbuild(intent)),
            "installutil" | "installutil.exe" => {
                self.emulate_installutil(intent);
                Some(Ok(()))
            }
            "cmstp" | "cmstp.exe" => Some(self.emulate_cmstp(intent)),
            "control" | "control.exe" => {
                self.emulate_control(intent);
                Some(Ok(()))
            }
            "forfiles" | "forfiles.exe" => Some(self.emulate_forfiles(intent)),
            "conhost" | "conhost.exe" => Some(self.emulate_conhost(intent)),
            _ => None,
        }
    }

    pub(crate) fn emulate_conhost(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let Some(index) = intent
            .args
            .iter()
            .position(|argument| argument.eq_ignore_ascii_case("--headless"))
        else {
            self.host.unsupported(
                Engine::Runbox,
                intent.depth,
                "interactive conhost.exe sessions are not modeled",
            );
            return Ok(());
        };
        let command = intent.args[index + 1..]
            .iter()
            .map(|argument| quote_argument(argument))
            .collect::<Vec<_>>()
            .join(" ");
        if command.is_empty() {
            self.host.unsupported(
                Engine::Runbox,
                intent.depth,
                "conhost.exe --headless command was empty",
            );
            return Ok(());
        }
        self.dispatch_command_line(&command, intent.depth + 1, "conhost.exe --headless")
    }

    pub(crate) fn emulate_msbuild(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let Some(project) = intent
            .args
            .iter()
            .find(|argument| !argument.starts_with('/') && !argument.starts_with('-'))
        else {
            self.emit_utility_result(
                &[],
                &["MSBUILD : error: project file required".into()],
                1,
                intent.depth,
            );
            return Ok(());
        };
        let remote = project.to_ascii_lowercase().starts_with("http");
        let bytes = if remote {
            self.host
                .network_request(NetworkIntent {
                    method: "GET".into(),
                    url: project.clone(),
                    origin: "MSBuild remote project".into(),
                    depth: intent.depth,
                })
                .map(|response| response.body)
        } else {
            let path = resolve_process_path(&intent.current_directory, project);
            self.host.read_file(&path, Engine::Runbox, intent.depth)
        };
        let Some(bytes) = bytes else {
            self.emit_utility_result(
                &[],
                &[format!(
                    "MSBUILD : error MSB1009: Project file does not exist: {project}"
                )],
                1,
                intent.depth,
            );
            return Ok(());
        };
        if remote {
            self.add_network_artifact(
                ArtifactKind::Script,
                "msbuild-project.xml",
                "application/xml",
                &bytes,
                intent.depth,
            );
        } else {
            self.host.add_artifact(
                ArtifactKind::Script,
                "msbuild-project.xml",
                "application/xml",
                &bytes,
                intent.depth,
            );
        }
        let project_text = String::from_utf8_lossy(&bytes);
        let mut dispatched = 0_usize;
        for captures in MSBUILD_EXEC_RE.captures_iter(&project_text) {
            let command = decode_xml_attribute(captures.get(1).map_or("", |value| value.as_str()));
            self.dispatch_command_line(&command, intent.depth + 1, "MSBuild Exec task")?;
            dispatched += 1;
        }
        for captures in PROCESS_START_RE.captures_iter(&project_text) {
            let program = captures.get(1).map_or("", |value| value.as_str());
            let arguments = captures.get(2).map_or("", |value| value.as_str());
            self.dispatch_command_line(
                &format!("{program} {arguments}"),
                intent.depth + 1,
                "MSBuild inline Process.Start",
            )?;
            dispatched += 1;
        }
        if dispatched == 0 {
            self.host.unsupported(
                Engine::Runbox,
                intent.depth,
                "MSBuild project contained no modeled Exec or Process.Start task",
            );
        }
        self.emit_utility_result(&["Build succeeded.".into()], &[], 0, intent.depth);
        Ok(())
    }

    pub(crate) fn emulate_installutil(&mut self, intent: &ProcessIntent) {
        let assemblies = intent
            .args
            .iter()
            .filter(|argument| !argument.starts_with('/') && !argument.starts_with('-'))
            .collect::<Vec<_>>();
        for assembly in assemblies {
            let path = resolve_process_path(&intent.current_directory, assembly);
            self.inspect_pe(&path, Engine::Runbox, intent.depth);
        }
        self.host.unsupported(
            Engine::Runbox,
            intent.depth,
            "InstallUtil installer hooks were identified but not executed",
        );
        self.emit_utility_result(&[], &[], 0, intent.depth);
    }

    pub(crate) fn emulate_cmstp(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let Some(path) = intent
            .args
            .iter()
            .rev()
            .find(|argument| !argument.starts_with('/') && !argument.starts_with('-'))
        else {
            self.emit_utility_result(&[], &["CMSTP INF path required.".into()], 1, intent.depth);
            return Ok(());
        };
        let path = resolve_process_path(&intent.current_directory, path);
        let Some(bytes) = self.host.read_file(&path, Engine::Runbox, intent.depth) else {
            self.emit_utility_result(&[], &[format!("INF not found: {path}")], 1, intent.depth);
            return Ok(());
        };
        self.host.add_artifact(
            ArtifactKind::Script,
            "cmstp-profile.inf",
            "text/plain",
            &bytes,
            intent.depth,
        );
        let commands = cmstp_commands(&String::from_utf8_lossy(&bytes));
        for command in &commands {
            self.dispatch_command_line(command, intent.depth + 1, "CMSTP INF command")?;
        }
        if commands.is_empty() {
            self.host.unsupported(
                Engine::Runbox,
                intent.depth,
                "CMSTP profile contained no modeled command section",
            );
        }
        self.emit_utility_result(&[], &[], 0, intent.depth);
        Ok(())
    }

    pub(crate) fn emulate_control(&mut self, intent: &ProcessIntent) {
        let Some(target) = intent
            .args
            .iter()
            .find(|argument| !argument.starts_with('/'))
        else {
            self.host.unsupported(
                Engine::Runbox,
                intent.depth,
                "Control Panel UI is not modeled",
            );
            return;
        };
        if extension(target) == "cpl" {
            let path = resolve_process_path(&intent.current_directory, target);
            self.inspect_pe(&path, Engine::Runbox, intent.depth);
            self.host.unsupported(
                Engine::Runbox,
                intent.depth,
                "Control Panel applet exports were not executed",
            );
        } else {
            self.host.unsupported(
                Engine::Runbox,
                intent.depth,
                &format!("unmodeled control.exe target: {target}"),
            );
        }
    }

    pub(crate) fn emulate_forfiles(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let root = switch_value(&intent.args, "/p").unwrap_or_else(|| {
            if intent.current_directory.is_empty() {
                r"C:\Users\analysis".into()
            } else {
                intent.current_directory.clone()
            }
        });
        let pattern = switch_value(&intent.args, "/m").unwrap_or_else(|| "*".into());
        let Some(command) = switch_value(&intent.args, "/c") else {
            self.emit_utility_result(
                &[],
                &["ERROR: /C command is required.".into()],
                1,
                intent.depth,
            );
            return Ok(());
        };
        let files = self.host.list_files(&root, Engine::Runbox, intent.depth);
        let mut matched = 0_usize;
        for file in files
            .into_iter()
            .filter(|path| wildcard_match(path.rsplit('\\').next().unwrap_or(path), &pattern))
            .take(self.host.limits().max_loop_iterations)
        {
            let name = file.rsplit('\\').next().unwrap_or(&file);
            let (stem, extension) = name.rsplit_once('.').unwrap_or((name, ""));
            let bytes = self
                .host
                .read_file(&file, Engine::Runbox, intent.depth)
                .unwrap_or_default();
            let command = replace_forfiles_variables(
                command.trim_matches('"'),
                &file,
                name,
                stem,
                extension,
                bytes.len(),
            );
            self.dispatch_command_line(&command, intent.depth + 1, "forfiles /C")?;
            matched += 1;
        }
        self.emit_utility_result(&[], &[], i32::from(matched == 0), intent.depth);
        Ok(())
    }
}

fn switch_value(arguments: &[String], requested: &str) -> Option<String> {
    arguments.iter().enumerate().find_map(|(index, argument)| {
        if let Some((name, value)) = argument.split_once(':') {
            if name.eq_ignore_ascii_case(requested) {
                return Some(value.trim_matches('"').into());
            }
        }
        argument
            .eq_ignore_ascii_case(requested)
            .then(|| arguments.get(index + 1).cloned())
            .flatten()
    })
}

fn cmstp_commands(source: &str) -> Vec<String> {
    let mut sections = BTreeMap::<String, Vec<String>>::new();
    let mut current = String::new();
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line[1..line.len() - 1].to_ascii_lowercase();
            continue;
        }
        sections
            .entry(current.clone())
            .or_default()
            .push(line.into());
    }
    let mut command_sections = sections
        .iter()
        .filter_map(|(_, lines)| {
            lines.iter().find_map(|line| {
                let (name, value) = line.split_once('=')?;
                (name.to_ascii_lowercase().starts_with("runpresetupcommands")
                    || name
                        .to_ascii_lowercase()
                        .starts_with("runpostsetupcommands"))
                .then(|| value.to_ascii_lowercase())
            })
        })
        .collect::<Vec<_>>();
    command_sections.extend(
        sections
            .keys()
            .filter(|name| name.contains("runpresetup") || name.contains("runpostsetup"))
            .cloned(),
    );
    let mut commands = Vec::new();
    for (section, lines) in &sections {
        for line in lines {
            if let Some((name, value)) = line.split_once('=') {
                if name.eq_ignore_ascii_case("commandline") {
                    commands.push(value.into());
                }
            } else if command_sections.iter().any(|name| name == section) {
                commands.push(line.into());
            }
        }
    }
    commands
}

fn replace_forfiles_variables(
    command: &str,
    path: &str,
    file: &str,
    stem: &str,
    extension: &str,
    size: usize,
) -> String {
    [
        ("@path", format!("\"{path}\"")),
        ("@file", format!("\"{file}\"")),
        ("@fname", format!("\"{stem}\"")),
        ("@ext", format!("\".{extension}\"")),
        ("@fsize", size.to_string()),
        ("@isdir", "FALSE".into()),
    ]
    .into_iter()
    .fold(command.to_owned(), |value, (needle, replacement)| {
        replace_ascii_case_insensitive(&value, needle, &replacement)
    })
}

fn replace_ascii_case_insensitive(source: &str, needle: &str, replacement: &str) -> String {
    let mut output = String::new();
    let mut remaining = source;
    let needle_lower = needle.to_ascii_lowercase();
    while let Some(position) = remaining.to_ascii_lowercase().find(&needle_lower) {
        output.push_str(&remaining[..position]);
        output.push_str(replacement);
        remaining = &remaining[position + needle.len()..];
    }
    output.push_str(remaining);
    output
}

fn decode_xml_attribute(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}
