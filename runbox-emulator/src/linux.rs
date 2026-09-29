use base64::Engine as _;
use emulator_core::{
    ArtifactKind, Engine, EventKind, Host, NetworkIntent, ProcessIntent, TraceEvent,
};
use regex::Regex;
use std::sync::LazyLock;

use crate::command_line::basename;
use crate::{Runbox, RunboxError};

static SCRIPT_SHELL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:system|popen|run)\s*\(\s*["']([^"']+)["']"#)
        .expect("valid interpreter shell execution regex")
});

impl Runbox {
    pub(crate) fn dispatch_linux_utility(
        &mut self,
        program: &str,
        intent: &ProcessIntent,
    ) -> Result<bool, RunboxError> {
        match program {
            "sudo" | "nohup" | "setsid" | "timeout" | "chroot" => {
                self.emulate_posix_wrapper(program, intent)?;
            }
            "systemctl" => self.emulate_systemctl(intent),
            "service" | "update-rc.d" | "chkconfig" => self.emulate_linux_service(program, intent),
            "crontab" | "at" => self.emulate_linux_scheduler(program, intent),
            "apt" | "apt-get" | "dpkg" | "yum" | "dnf" | "rpm" | "snap" => {
                self.emulate_linux_package_manager(program, intent);
            }
            "python" | "python3" | "perl" | "ruby" => {
                self.emulate_linux_interpreter(program, intent)?;
            }
            "base64" => self.emulate_posix_base64(intent),
            "uname" | "whoami" | "id" | "hostname" | "hostnamectl" => {
                self.emulate_linux_identity(program, intent);
            }
            "ls" => self.emulate_linux_ls(intent),
            "find" => self.emulate_linux_find(intent),
            "ssh" | "scp" | "nc" | "netcat" => self.emulate_linux_network_tool(program, intent),
            "chmod" => self.emulate_linux_chmod(intent)?,
            "chown" | "chgrp" | "chattr" | "mount" | "umount" | "iptables" | "nft" | "ufw"
            | "setenforce" => self.emulate_linux_system_utility(program, intent),
            "date" => self.emit_linux_output(
                &["Tue Sep 29 00:00:00 UTC 2026".into()],
                &[],
                0,
                intent.depth,
            ),
            "sleep" | "kill" | "killall" | "pkill" => {
                self.host.emit(
                    TraceEvent::new(
                        intent.depth,
                        Engine::Runbox,
                        EventKind::Command,
                        format!("modeled Linux utility {program}"),
                    )
                    .with_data("arguments", intent.args.join(" ")),
                );
                self.emit_linux_output(&[], &[], 0, intent.depth);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub(crate) fn emulate_posix_wrapper(
        &mut self,
        program: &str,
        intent: &ProcessIntent,
    ) -> Result<(), RunboxError> {
        let mut index = 0;
        match program {
            "sudo" => {
                while let Some(argument) = intent.args.get(index) {
                    if matches!(argument.as_str(), "-u" | "-g" | "-h" | "-p") {
                        index += 2;
                    } else if argument.starts_with('-') {
                        index += 1;
                    } else {
                        break;
                    }
                }
            }
            "timeout" => {
                while intent
                    .args
                    .get(index)
                    .is_some_and(|argument| argument.starts_with('-'))
                {
                    index += 1;
                }
                index = index.saturating_add(1);
            }
            "chroot" => index = 1,
            "nohup" | "setsid" => {
                while intent
                    .args
                    .get(index)
                    .is_some_and(|argument| argument.starts_with('-'))
                {
                    index += 1;
                }
            }
            _ => {}
        }
        let Some(command) = intent.args.get(index) else {
            self.host.unsupported(
                Engine::Runbox,
                intent.depth,
                &format!("{program} did not include a nested command"),
            );
            return Ok(());
        };
        let nested = ProcessIntent {
            program: command.clone(),
            args: intent.args[index + 1..].to_vec(),
            command_line: intent.args[index..].join(" "),
            origin: format!("POSIX {program} wrapper"),
            depth: intent.depth + 1,
            stdin: intent.stdin.clone(),
            current_directory: intent.current_directory.clone(),
        };
        self.host.record_process_request(&nested)?;
        self.dispatch_process(&nested)
    }

    fn emulate_systemctl(&mut self, intent: &ProcessIntent) {
        let action = intent
            .args
            .iter()
            .find(|argument| !argument.starts_with('-'))
            .map_or("", String::as_str);
        let persistence = matches!(
            action,
            "enable" | "reenable" | "link" | "preset" | "start" | "restart"
        );
        let mut event = TraceEvent::new(
            intent.depth,
            Engine::Runbox,
            if persistence {
                EventKind::Persistence
            } else {
                EventKind::Command
            },
            format!("modeled systemctl {action}"),
        )
        .with_data("arguments", intent.args.join(" "));
        if persistence {
            event = event.with_data("persistence_kind", "linux_systemd");
        }
        self.host.emit(event);
        for argument in &intent.args {
            if std::path::Path::new(argument)
                .extension()
                .is_some_and(|extension| extension == "service" || extension == "timer")
            {
                let path = resolve_linux_path(&intent.current_directory, argument);
                if let Some(bytes) = self.host.read_file(&path, Engine::Runbox, intent.depth) {
                    self.host.add_artifact(
                        ArtifactKind::Script,
                        "systemd-unit",
                        "text/plain",
                        &bytes,
                        intent.depth,
                    );
                }
            }
        }
        self.emit_linux_output(&[], &[], 0, intent.depth);
    }

    fn emulate_linux_service(&mut self, program: &str, intent: &ProcessIntent) {
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Persistence,
                format!("modeled Linux service utility {program}"),
            )
            .with_data("arguments", intent.args.join(" "))
            .with_data("persistence_kind", "linux_service"),
        );
        self.emit_linux_output(&[], &[], 0, intent.depth);
    }

    fn emulate_linux_scheduler(&mut self, program: &str, intent: &ProcessIntent) {
        let content = if program == "crontab" {
            intent
                .args
                .iter()
                .find(|argument| !argument.starts_with('-') && argument.as_str() != "-")
                .and_then(|path| {
                    self.host.read_file(
                        &resolve_linux_path(&intent.current_directory, path),
                        Engine::Runbox,
                        intent.depth,
                    )
                })
                .unwrap_or_else(|| intent.stdin.join("\n").into_bytes())
        } else {
            intent.stdin.join("\n").into_bytes()
        };
        if !content.is_empty() {
            self.host.add_artifact(
                ArtifactKind::Script,
                if program == "crontab" {
                    "crontab"
                } else {
                    "at-job"
                },
                "text/plain",
                &content,
                intent.depth,
            );
            self.record_urls(&String::from_utf8_lossy(&content), program, intent.depth);
        }
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Persistence,
                format!("modeled Linux scheduler {program}"),
            )
            .with_data("arguments", intent.args.join(" "))
            .with_data("persistence_kind", "linux_cron"),
        );
        self.emit_linux_output(&[], &[], 0, intent.depth);
    }

    fn emulate_linux_package_manager(&mut self, program: &str, intent: &ProcessIntent) {
        self.record_urls(
            &intent.command_line,
            &format!("Linux package manager {program}"),
            intent.depth,
        );
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                format!("modeled Linux package manager {program}"),
            )
            .with_data("arguments", intent.args.join(" "))
            .with_data("package_operation", "true"),
        );
        self.emit_linux_output(&[], &[], 0, intent.depth);
    }

    fn emulate_linux_interpreter(
        &mut self,
        program: &str,
        intent: &ProcessIntent,
    ) -> Result<(), RunboxError> {
        let switch = if program == "perl" || program == "ruby" {
            "-e"
        } else {
            "-c"
        };
        let script = intent
            .args
            .iter()
            .position(|argument| argument == switch)
            .and_then(|index| intent.args.get(index + 1))
            .cloned();
        if let Some(script) = script {
            self.host.add_artifact(
                ArtifactKind::Script,
                &format!("{program}-inline-script"),
                "text/plain",
                script.as_bytes(),
                intent.depth,
            );
            self.record_urls(&script, &format!("{program} inline script"), intent.depth);
            for captures in SCRIPT_SHELL_RE.captures_iter(&script) {
                let command = captures.get(1).map_or("", |capture| capture.as_str());
                self.host.process_intent(ProcessIntent {
                    program: "bash".into(),
                    args: vec!["-c".into(), command.into()],
                    command_line: format!("bash -c {command:?}"),
                    origin: format!("{program} shell execution"),
                    depth: intent.depth + 1,
                    stdin: Vec::new(),
                    current_directory: intent.current_directory.clone(),
                })?;
            }
        }
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                format!("inspected {program} invocation"),
            )
            .with_data("arguments", intent.args.join(" ")),
        );
        self.emit_linux_output(&[], &[], 0, intent.depth);
        Ok(())
    }

    pub(crate) fn emulate_posix_base64(&mut self, intent: &ProcessIntent) {
        let decode = intent
            .args
            .iter()
            .any(|argument| matches!(argument.as_str(), "-d" | "-D" | "--decode"));
        let file = intent
            .args
            .iter()
            .find(|argument| !argument.starts_with('-'));
        let bytes = file
            .and_then(|path| {
                self.host.read_file(
                    &resolve_linux_path(&intent.current_directory, path),
                    Engine::Runbox,
                    intent.depth,
                )
            })
            .unwrap_or_else(|| intent.stdin.join("\n").into_bytes());
        if decode {
            match base64::engine::general_purpose::STANDARD.decode(
                String::from_utf8_lossy(&bytes)
                    .chars()
                    .filter(|ch| !ch.is_whitespace())
                    .collect::<String>(),
            ) {
                Ok(decoded) => {
                    self.host.add_artifact(
                        if std::str::from_utf8(&decoded).is_ok() {
                            ArtifactKind::DecodedText
                        } else {
                            ArtifactKind::Binary
                        },
                        "base64-decoded",
                        "application/octet-stream",
                        &decoded,
                        intent.depth,
                    );
                    self.host.emit(
                        TraceEvent::new(
                            intent.depth,
                            Engine::Runbox,
                            EventKind::Decode,
                            "decoded Base64 with POSIX base64 utility",
                        )
                        .with_data("decoded_bytes", decoded.len().to_string()),
                    );
                    let output = String::from_utf8_lossy(&decoded)
                        .lines()
                        .map(str::to_owned)
                        .collect::<Vec<_>>();
                    self.emit_linux_output(&output, &[], 0, intent.depth);
                }
                Err(error) => self.emit_linux_output(
                    &[],
                    &[format!("base64: invalid input: {error}")],
                    1,
                    intent.depth,
                ),
            }
        } else {
            self.emit_linux_output(
                &[base64::engine::general_purpose::STANDARD.encode(bytes)],
                &[],
                0,
                intent.depth,
            );
        }
    }

    fn emulate_linux_identity(&mut self, program: &str, intent: &ProcessIntent) {
        let line = match program {
            "uname" if intent.args.iter().any(|argument| argument == "-a") => {
                "Linux analysis-linux 6.8.0-analysis #1 SMP x86_64 GNU/Linux"
            }
            "uname" => "Linux",
            "whoami" => "analysis",
            "id" => "uid=1000(analysis) gid=1000(analysis) groups=1000(analysis)",
            "hostname" => "analysis-linux",
            "hostnamectl" => "Static hostname: analysis-linux",
            _ => "",
        };
        self.emit_linux_output(&[line.into()], &[], 0, intent.depth);
    }

    fn emulate_linux_ls(&mut self, intent: &ProcessIntent) {
        let requested = intent
            .args
            .iter()
            .find(|argument| !argument.starts_with('-'))
            .map_or(".", String::as_str);
        let root = resolve_linux_path(&intent.current_directory, requested);
        let prefix = format!("{}/", root.trim_end_matches('/'));
        let mut entries = self
            .host
            .list_directories(&root, Engine::Runbox, intent.depth)
            .into_iter()
            .chain(self.host.list_files(&root, Engine::Runbox, intent.depth))
            .filter_map(|path| {
                let remainder = path.strip_prefix(&prefix)?;
                (!remainder.contains('/')).then(|| remainder.to_owned())
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries.dedup();
        self.emit_linux_output(&entries, &[], 0, intent.depth);
    }

    fn emulate_linux_find(&mut self, intent: &ProcessIntent) {
        let root = intent
            .args
            .first()
            .filter(|argument| !argument.starts_with('-'))
            .map_or_else(
                || resolve_linux_path(&intent.current_directory, "."),
                |path| resolve_linux_path(&intent.current_directory, path),
            );
        let pattern = intent
            .args
            .windows(2)
            .find(|pair| pair[0] == "-name")
            .map(|pair| pair[1].as_str());
        let mut paths = self.host.list_files(&root, Engine::Runbox, intent.depth);
        paths.extend(
            self.host
                .list_directories(&root, Engine::Runbox, intent.depth),
        );
        if let Some(pattern) = pattern {
            paths.retain(|path| linux_wildcard_match(basename(path), pattern));
        }
        paths.sort();
        paths.dedup();
        self.emit_linux_output(&paths, &[], 0, intent.depth);
    }

    fn emulate_linux_network_tool(&mut self, program: &str, intent: &ProcessIntent) {
        let target = match program {
            "ssh" => intent
                .args
                .iter()
                .find(|argument| !argument.starts_with('-'))
                .map(|value| value.rsplit('@').next().unwrap_or(value.as_str()))
                .unwrap_or_default(),
            "scp" => intent
                .args
                .iter()
                .find_map(|argument| argument.split_once(':').map(|(host, _)| host))
                .unwrap_or_default(),
            "nc" | "netcat" => intent
                .args
                .iter()
                .find(|argument| !argument.starts_with('-'))
                .map_or("", String::as_str),
            _ => "",
        };
        if !target.is_empty() {
            self.host.network_intent(NetworkIntent {
                method: "CONNECT".into(),
                url: format!("tcp://{target}"),
                origin: format!("Linux {program}"),
                depth: intent.depth,
            });
        }
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                format!("modeled Linux network utility {program}"),
            )
            .with_data("arguments", intent.args.join(" ")),
        );
        self.emit_linux_output(&[], &[], 0, intent.depth);
    }

    fn emulate_linux_chmod(&mut self, intent: &ProcessIntent) -> Result<(), RunboxError> {
        let executable = intent
            .args
            .first()
            .is_some_and(|mode| mode.contains('x') || mode.ends_with("755"));
        if executable {
            for path in intent.args.iter().skip(1) {
                self.host.register_executable(
                    &resolve_linux_path(&intent.current_directory, path),
                    Engine::Bash,
                    intent.depth,
                )?;
            }
        }
        self.emit_linux_output(&[], &[], 0, intent.depth);
        Ok(())
    }

    fn emulate_linux_system_utility(&mut self, program: &str, intent: &ProcessIntent) {
        self.host.emit(
            TraceEvent::new(
                intent.depth,
                Engine::Runbox,
                EventKind::Command,
                format!("modeled Linux system utility {program}"),
            )
            .with_data("arguments", intent.args.join(" "))
            .with_data("security_control", "true"),
        );
        self.emit_linux_output(&[], &[], 0, intent.depth);
    }

    fn emit_linux_output(
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
                    "Linux utility completed",
                )
                .with_data("exit_code", exit_code.to_string()),
            );
        }
    }
}

fn resolve_linux_path(current_directory: &str, path: &str) -> String {
    if path.starts_with('/') {
        emulator_core::normalize_posix_path(path)
    } else {
        let current = if current_directory.is_empty() {
            "/home/analysis"
        } else {
            current_directory
        };
        emulator_core::normalize_posix_path(&format!("{}/{}", current.trim_end_matches('/'), path))
    }
}

fn linux_wildcard_match(value: &str, pattern: &str) -> bool {
    fn matches_bytes(value: &[u8], pattern: &[u8]) -> bool {
        match pattern {
            [] => value.is_empty(),
            [b'*', rest @ ..] => {
                matches_bytes(value, rest)
                    || (!value.is_empty() && matches_bytes(&value[1..], pattern))
            }
            [b'?', rest @ ..] => !value.is_empty() && matches_bytes(&value[1..], rest),
            [first, rest @ ..] => value.first() == Some(first) && matches_bytes(&value[1..], rest),
        }
    }
    matches_bytes(value.as_bytes(), pattern.as_bytes())
}
