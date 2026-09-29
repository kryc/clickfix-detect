use base64::Engine as _;
use emulator_core::{
    ArtifactKind, Engine, EventKind, Host, NetworkIntent, ProcessIntent, TraceEvent,
};
use windows_script_emulator::ScriptLanguage;

use crate::artifacts::{first_url, urls};
use crate::command_line::{find_argument, infer_http_method, resolve_process_path, wildcard_match};
use crate::{Runbox, RunboxError};

impl Runbox {
    pub(crate) fn dispatch_lolbin_utility(
        &mut self,
        program: &str,
        intent: &ProcessIntent,
    ) -> bool {
        match program {
            "where" | "where.exe" => self.emulate_where(intent),
            "finger" | "finger.exe" => self.emulate_finger(intent),
            _ => return false,
        }
        true
    }

    pub(crate) fn emulate_finger(&mut self, intent: &ProcessIntent) {
        let Some(target) = intent
            .args
            .iter()
            .find(|argument| !argument.starts_with('/'))
        else {
            self.emit_utility_result(&[], &["FINGER: target is required".into()], 1, intent.depth);
            return;
        };
        let Some((user, host)) = target.rsplit_once('@') else {
            self.emit_utility_result(&[], &["FINGER: expected user@host".into()], 1, intent.depth);
            return;
        };
        let response = self.host.network_request(NetworkIntent {
            method: "FINGER".into(),
            url: format!("finger://{host}/{user}"),
            origin: "runbox finger.exe".into(),
            depth: intent.depth,
        });
        let stdout = response
            .map(|response| {
                String::from_utf8_lossy(&response.body)
                    .replace("\r\n", "\n")
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        self.emit_utility_result(&stdout, &[], 0, intent.depth);
    }

    pub(crate) fn emulate_certutil(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        if let Some(index) = find_argument(arguments, &["-decode", "-decodehex"]) {
            let Some(source) = arguments.get(index + 1) else {
                return Ok(());
            };
            let Some(destination) = arguments.get(index + 2) else {
                return Ok(());
            };
            if let Some(bytes) = self.host.read_file(source, Engine::Cmd, depth) {
                let text = String::from_utf8_lossy(&bytes);
                let decoded = if arguments[index].eq_ignore_ascii_case("-decode") {
                    base64::engine::general_purpose::STANDARD
                        .decode(text.split_whitespace().collect::<String>())
                        .ok()
                } else {
                    decode_hex(&text)
                };
                if let Some(decoded) = decoded {
                    self.host
                        .write_file(destination, &decoded, false, Engine::Cmd, depth)?;
                    self.host.emit(
                        TraceEvent::new(
                            depth,
                            Engine::Cmd,
                            EventKind::Decode,
                            "emulated certutil decoding",
                        )
                        .with_data("source", source)
                        .with_data("destination", destination),
                    );
                } else {
                    self.host.unsupported(
                        Engine::Cmd,
                        depth,
                        "certutil input could not be decoded",
                    );
                }
            }
            return Ok(());
        }
        if find_argument(arguments, &["-urlcache"]).is_some() {
            self.record_urls(&arguments.join(" "), "cmd.exe certutil -urlcache", depth);
            self.host
                .unsupported(Engine::Cmd, depth, "certutil URL content is not downloaded");
            return Ok(());
        }
        self.host
            .unsupported(Engine::Cmd, depth, "unsupported certutil mode");
        Ok(())
    }

    pub(crate) fn emulate_downloader(
        &mut self,
        program: &str,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        let command_line = arguments.join(" ");
        let Some(url) = first_url(&command_line) else {
            self.host.unsupported(
                Engine::Runbox,
                depth,
                &format!("{program} invocation did not contain a modeled URL"),
            );
            return Ok(());
        };
        let method = infer_http_method(arguments);
        let output = find_argument(arguments, &["-o", "--output", "-outfile"])
            .and_then(|index| arguments.get(index + 1))
            .cloned()
            .or_else(|| {
                (program.starts_with("wget"))
                    .then(|| url.rsplit('/').next().unwrap_or("index.html").to_string())
            });
        let response = self.host.network_request(NetworkIntent {
            method,
            url,
            origin: format!("runbox {program}"),
            depth,
        });
        if let Some(response) = response {
            if let Some(output) = output {
                self.host
                    .write_file(&output, &response.body, false, Engine::Runbox, depth)?;
            } else {
                for line in String::from_utf8_lossy(&response.body).lines() {
                    self.host.emit(
                        TraceEvent::new(depth, Engine::Runbox, EventKind::Output, line)
                            .with_data("stream", "stdout")
                            .with_data("exit_code", "0"),
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn emulate_bitsadmin(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        let command_line = arguments.join(" ");
        let urls = urls(&command_line).collect::<Vec<_>>();
        for url in urls {
            let response = self.host.network_request(NetworkIntent {
                method: "GET".into(),
                url,
                origin: "runbox bitsadmin".into(),
                depth,
            });
            if let Some(response) = response {
                if let Some(destination) = arguments.last().filter(|value| {
                    !value.starts_with('/') && !value.to_ascii_lowercase().starts_with("http")
                }) {
                    self.host.write_file(
                        destination,
                        &response.body,
                        false,
                        Engine::Runbox,
                        depth,
                    )?;
                }
            }
        }
        self.host.emit(
            TraceEvent::new(
                depth,
                Engine::Runbox,
                EventKind::Command,
                "modeled bitsadmin invocation",
            )
            .with_data("arguments", command_line),
        );
        Ok(())
    }

    pub(crate) fn emulate_find(&mut self, intent: &ProcessIntent, regex_mode: bool) {
        let ignore_case = intent
            .args
            .iter()
            .any(|argument| argument.eq_ignore_ascii_case("/i"));
        let invert = intent
            .args
            .iter()
            .any(|argument| argument.eq_ignore_ascii_case("/v"));
        let literal = intent
            .args
            .iter()
            .any(|argument| argument.eq_ignore_ascii_case("/l"))
            || !regex_mode;
        let values = intent
            .args
            .iter()
            .filter(|argument| !argument.starts_with('/'))
            .collect::<Vec<_>>();
        let Some(pattern) = values.first() else {
            self.emit_utility_result(
                &[],
                &["FIND: Parameter format not correct".into()],
                1,
                intent.depth,
            );
            return;
        };
        let mut input = intent.stdin.clone();
        for file in values.iter().skip(1) {
            let path = resolve_process_path(&intent.current_directory, file);
            if let Some(bytes) = self.host.read_file(&path, Engine::Runbox, intent.depth) {
                input.extend(
                    String::from_utf8_lossy(&bytes)
                        .replace("\r\n", "\n")
                        .lines()
                        .map(str::to_string),
                );
            }
        }
        let pattern_value = pattern.trim_matches('"');
        let regex = (!literal)
            .then(|| {
                regex::RegexBuilder::new(pattern_value)
                    .case_insensitive(ignore_case)
                    .build()
                    .ok()
            })
            .flatten();
        let normalized_pattern = if ignore_case {
            pattern_value.to_ascii_lowercase()
        } else {
            pattern_value.into()
        };
        let stdout = input
            .into_iter()
            .filter(|line| {
                let matched = regex.as_ref().map_or_else(
                    || {
                        if ignore_case {
                            line.to_ascii_lowercase().contains(&normalized_pattern)
                        } else {
                            line.contains(&normalized_pattern)
                        }
                    },
                    |regex| regex.is_match(line),
                );
                matched != invert
            })
            .collect::<Vec<_>>();
        let exit_code = i32::from(stdout.is_empty());
        self.emit_utility_result(&stdout, &[], exit_code, intent.depth);
    }

    pub(crate) fn emulate_more(&mut self, intent: &ProcessIntent) {
        let mut stdout = intent.stdin.clone();
        for argument in intent
            .args
            .iter()
            .filter(|argument| !argument.starts_with('/'))
        {
            let path = resolve_process_path(&intent.current_directory, argument);
            if let Some(bytes) = self.host.read_file(&path, Engine::Runbox, intent.depth) {
                stdout.extend(
                    String::from_utf8_lossy(&bytes)
                        .replace("\r\n", "\n")
                        .lines()
                        .map(str::to_string),
                );
            }
        }
        self.emit_utility_result(&stdout, &[], 0, intent.depth);
    }

    pub(crate) fn emulate_sort(&mut self, intent: &ProcessIntent) {
        let mut stdout = intent.stdin.clone();
        if stdout.is_empty() {
            for argument in intent
                .args
                .iter()
                .filter(|argument| !argument.starts_with('/'))
            {
                let path = resolve_process_path(&intent.current_directory, argument);
                if let Some(bytes) = self.host.read_file(&path, Engine::Runbox, intent.depth) {
                    stdout.extend(
                        String::from_utf8_lossy(&bytes)
                            .replace("\r\n", "\n")
                            .lines()
                            .map(str::to_string),
                    );
                }
            }
        }
        stdout.sort_by_key(|line| line.to_ascii_lowercase());
        if intent
            .args
            .iter()
            .any(|argument| argument.eq_ignore_ascii_case("/r"))
        {
            stdout.reverse();
        }
        self.emit_utility_result(&stdout, &[], 0, intent.depth);
    }

    pub(crate) fn emulate_where(&mut self, intent: &ProcessIntent) {
        let patterns = intent
            .args
            .iter()
            .filter(|argument| !argument.starts_with('/'))
            .cloned()
            .collect::<Vec<_>>();
        let mut directories = vec![if intent.current_directory.is_empty() {
            r"C:\Users\analysis".into()
        } else {
            intent.current_directory.clone()
        }];
        directories.extend(
            self.host
                .environment("PATH")
                .unwrap_or_default()
                .split(';')
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        );
        let extensions = self
            .host
            .environment("PATHEXT")
            .unwrap_or(".COM;.EXE;.BAT;.CMD")
            .split(';')
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>();
        let mut stdout = Vec::new();
        for directory in directories {
            for file in self
                .host
                .list_files(&directory, Engine::Runbox, intent.depth)
            {
                let name = file.rsplit('\\').next().unwrap_or(&file);
                if patterns.iter().any(|pattern| {
                    wildcard_match(name, pattern)
                        || (!pattern.contains('.')
                            && extensions.iter().any(|extension| {
                                wildcard_match(name, &format!("{pattern}{extension}"))
                            }))
                }) && !stdout.contains(&file)
                {
                    stdout.push(file);
                }
            }
        }
        let exit_code = i32::from(stdout.is_empty());
        self.emit_utility_result(&stdout, &[], exit_code, intent.depth);
    }

    pub(crate) fn emulate_copy_utility(
        &mut self,
        program: &str,
        intent: &ProcessIntent,
    ) -> Result<(), RunboxError> {
        let values = intent
            .args
            .iter()
            .filter(|argument| !argument.starts_with('/'))
            .collect::<Vec<_>>();
        let (source, destination) = if program.starts_with("robocopy") {
            let [source, destination, ..] = values.as_slice() else {
                self.emit_utility_result(
                    &[],
                    &["ERROR: Invalid Parameter".into()],
                    16,
                    intent.depth,
                );
                return Ok(());
            };
            (*source, *destination)
        } else {
            let [source, destination, ..] = values.as_slice() else {
                self.emit_utility_result(
                    &[],
                    &["Invalid number of parameters".into()],
                    4,
                    intent.depth,
                );
                return Ok(());
            };
            (*source, *destination)
        };
        let source = resolve_process_path(&intent.current_directory, source);
        let destination = resolve_process_path(&intent.current_directory, destination);
        let mut copied = 0_usize;
        if let Some(bytes) = self.host.read_file(&source, Engine::Runbox, intent.depth) {
            let target = if destination.ends_with('\\') {
                format!(
                    "{}{}",
                    destination,
                    source.rsplit('\\').next().unwrap_or("file.bin")
                )
            } else {
                destination
            };
            self.host
                .write_file(&target, &bytes, false, Engine::Runbox, intent.depth)?;
            copied = 1;
        } else {
            for file in self.host.list_files(&source, Engine::Runbox, intent.depth) {
                if let Some(bytes) = self.host.read_file(&file, Engine::Runbox, intent.depth) {
                    let name = file.rsplit('\\').next().unwrap_or("file.bin");
                    self.host.write_file(
                        &format!("{}\\{name}", destination.trim_end_matches('\\')),
                        &bytes,
                        false,
                        Engine::Runbox,
                        intent.depth,
                    )?;
                    copied += 1;
                }
            }
        }
        let exit_code = if program.starts_with("robocopy") {
            i32::from(copied > 0)
        } else {
            i32::from(copied == 0)
        };
        self.emit_utility_result(
            &[format!("{copied} file(s) copied.")],
            &[],
            exit_code,
            intent.depth,
        );
        Ok(())
    }

    pub(crate) fn emulate_attrib(&mut self, intent: &ProcessIntent) {
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                "modeled attrib.exe metadata change",
            )
            .with_data("arguments", intent.args.join(" ")),
        );
        self.emit_utility_result(&[], &[], 0, intent.depth);
    }

    pub(crate) fn emulate_chcp(&mut self, intent: &ProcessIntent) {
        let code_page = intent
            .args
            .first()
            .map_or_else(|| "437".into(), |value| value.trim().to_string());
        self.host.set_environment("CMD_CODEPAGE", &code_page);
        self.emit_utility_result(
            &[format!("Active code page: {code_page}")],
            &[],
            0,
            intent.depth,
        );
    }

    pub(crate) fn emit_utility_result(
        &mut self,
        stdout: &[String],
        stderr: &[String],
        exit_code: i32,
        depth: usize,
    ) {
        for line in stdout {
            self.host.emit(
                TraceEvent::new(depth, Engine::Runbox, EventKind::Output, line)
                    .with_data("stream", "stdout")
                    .with_data("exit_code", exit_code.to_string()),
            );
        }
        for line in stderr {
            self.host.emit(
                TraceEvent::new(depth, Engine::Runbox, EventKind::Output, line)
                    .with_data("stream", "stderr")
                    .with_data("exit_code", exit_code.to_string()),
            );
        }
        if stdout.is_empty() && stderr.is_empty() {
            self.host.emit(
                TraceEvent::new(
                    depth,
                    Engine::Runbox,
                    EventKind::Command,
                    "modeled utility completed",
                )
                .with_data("exit_code", exit_code.to_string()),
            );
        }
    }

    pub(crate) fn emulate_reg(&mut self, arguments: &[String], depth: usize) {
        let Some(operation) = arguments.first() else {
            return;
        };
        let path = arguments.get(1).cloned().unwrap_or_default();
        if operation.eq_ignore_ascii_case("add") {
            let name = find_argument(arguments, &["/v"])
                .and_then(|index| arguments.get(index + 1))
                .cloned()
                .unwrap_or_else(|| "(Default)".into());
            let value = find_argument(arguments, &["/d"])
                .and_then(|index| arguments.get(index + 1))
                .cloned()
                .unwrap_or_default();
            self.host
                .write_registry(&format!(r"{path}\{name}"), &value, Engine::Cmd, depth);
        } else if operation.eq_ignore_ascii_case("query") {
            self.host.read_registry(&path, Engine::Cmd, depth);
        } else {
            self.host.unsupported(
                Engine::Cmd,
                depth,
                &format!("unsupported reg.exe operation: {operation}"),
            );
        }
    }

    pub(crate) fn emulate_rundll32(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        self.host
            .consume_step(Engine::Rundll32, depth, "emulating rundll32")?;
        let target = arguments.join(" ");
        self.record_urls(&target, "rundll32 arguments", depth);
        if let Some(index) = target.to_ascii_lowercase().find("javascript:") {
            return self.emulate_script_language(
                &target[index + "javascript:".len()..],
                ScriptLanguage::JScript,
                depth + 1,
            );
        }
        if let Some(first) = arguments.first() {
            let path = first.split(',').next().unwrap_or(first).trim_matches('"');
            self.inspect_pe(path, Engine::Rundll32, depth);
        }
        self.host.unsupported(
            Engine::Rundll32,
            depth,
            "native DLL exports are not executed; only static metadata and known patterns are modeled",
        );
        Ok(())
    }

    pub(crate) fn emulate_regsvr32(
        &mut self,
        arguments: &[String],
        depth: usize,
    ) -> Result<(), RunboxError> {
        self.host
            .consume_step(Engine::Regsvr32, depth, "emulating regsvr32")?;
        let target = arguments.join(" ");
        self.record_urls(&target, "regsvr32 arguments", depth);
        if target.to_ascii_lowercase().contains("scrobj.dll") {
            self.host.emit(TraceEvent::new(
                depth,
                Engine::Regsvr32,
                EventKind::Command,
                "modeled regsvr32 scriptlet invocation",
            ));
            if let Some(url) = first_url(&target) {
                if let Some(response) = self.host.network_request(NetworkIntent {
                    method: "GET".into(),
                    url,
                    origin: "regsvr32 remote scriptlet".into(),
                    depth,
                }) {
                    self.host.add_artifact(
                        ArtifactKind::Script,
                        "remote.sct",
                        "application/xml",
                        &response.body,
                        depth,
                    );
                    self.emulate_scriptlet(
                        &String::from_utf8_lossy(&response.body),
                        ScriptLanguage::JScript,
                        depth + 1,
                    )?;
                }
            } else if let Some(path) = arguments
                .iter()
                .rev()
                .find(|argument| extension_is(argument, "sct"))
            {
                if let Some(bytes) = self.host.read_file(path, Engine::Regsvr32, depth) {
                    self.emulate_scriptlet(
                        &String::from_utf8_lossy(&bytes),
                        ScriptLanguage::JScript,
                        depth + 1,
                    )?;
                }
            }
        }
        if let Some(path) = arguments
            .iter()
            .rev()
            .find(|argument| !argument.starts_with('/') && !argument.starts_with('-'))
        {
            if !path.to_ascii_lowercase().starts_with("http") && !extension_is(path, "sct") {
                self.inspect_pe(path.trim_matches('"'), Engine::Regsvr32, depth);
            }
        }
        self.host.unsupported(
            Engine::Regsvr32,
            depth,
            "native registration code is not executed",
        );
        Ok(())
    }
}

fn extension_is(path: &str, requested: &str) -> bool {
    path.trim_matches('"')
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension.eq_ignore_ascii_case(requested))
}

fn decode_hex(input: &str) -> Option<Vec<u8>> {
    let normalized = input
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>()
        .replace([' ', '\t', '\r', '\n', '-', ':'], "");
    if normalized.len() % 2 != 0 {
        return None;
    }
    normalized
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}
