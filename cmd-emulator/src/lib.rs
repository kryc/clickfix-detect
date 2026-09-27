mod ast;
mod batch;
mod builtins;
mod control;
mod expansion;
mod parser;
mod runtime;
mod syntax;

pub mod tokenizer;

use ast::{Command, CommandKind, ForMode, IfCondition, Program};
use batch::{BatchAction, BatchContext};
use emulator_core::{Engine, EventKind, Host, HostError, TraceEvent};
use parser::ParsedDocument;
use runtime::Runtime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use syntax::{unquote_and_unescape, ChainOperator, Stream};
use thiserror::Error;

const MAX_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CmdResult {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub exit_code: i32,
    pub exited: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CmdParseSummary {
    pub bytes: usize,
    pub tokens: usize,
    pub commands: usize,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Error)]
pub enum CmdError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("cmd input exceeds the {MAX_INPUT_BYTES} byte limit")]
    InputTooLarge,
    #[error("cmd loop iteration limit {limit} reached")]
    LoopLimit { limit: usize },
    #[error("cmd syntax error: {0}")]
    Syntax(String),
}

#[derive(Debug, Clone, Default)]
pub struct CmdEmulator {
    runtime: Runtime,
    batch: Option<BatchContext>,
    loop_variables: BTreeMap<char, String>,
    pipe_input: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CommandOutput {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub code: i32,
    pub exited: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OutputSink {
    Stdout,
    Stderr,
    File { path: String, append: bool },
}

impl CmdEmulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_delayed_expansion(mut self, enabled: bool) -> Self {
        self.runtime.delayed_expansion = enabled;
        self
    }

    pub fn set_delayed_expansion(&mut self, enabled: bool) {
        self.runtime.delayed_expansion = enabled;
    }

    #[must_use]
    pub fn delayed_expansion(&self) -> bool {
        self.runtime.delayed_expansion
    }

    #[must_use]
    pub fn current_directory(&self) -> &str {
        &self.runtime.current_directory
    }

    #[must_use]
    pub fn error_level(&self) -> i32 {
        self.runtime.error_level
    }

    #[must_use]
    pub fn parse(command: &str) -> CmdParseSummary {
        let document = ParsedDocument::parse(command);
        CmdParseSummary {
            bytes: command.len(),
            tokens: document.tokens().len(),
            commands: document.program().parts.len(),
            diagnostics: document
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.message.clone())
                .collect(),
        }
    }

    #[must_use]
    pub fn parse_batch(batch: &str) -> CmdParseSummary {
        let context = BatchContext::new(batch, "<batch>", Vec::new());
        CmdParseSummary {
            bytes: batch.len(),
            tokens: context
                .lines
                .iter()
                .map(|document| document.tokens().len())
                .sum(),
            commands: context
                .lines
                .iter()
                .map(|document| document.program().parts.len())
                .sum(),
            diagnostics: context
                .lines
                .iter()
                .flat_map(ParsedDocument::diagnostics)
                .map(|diagnostic| diagnostic.message.clone())
                .collect(),
        }
    }

    /// Emulates a command line without invoking host processes or touching the host filesystem.
    ///
    /// # Errors
    ///
    /// Returns an error when an input or host resource limit is reached.
    pub fn emulate(
        &mut self,
        command: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CmdResult, CmdError> {
        if command.len() > MAX_INPUT_BYTES {
            return Err(CmdError::InputTooLarge);
        }
        host.consume_step(Engine::Cmd, depth, "parsing cmd input")?;
        let document = ParsedDocument::parse(command);
        host.emit(
            TraceEvent::new(depth, Engine::Cmd, EventKind::Parse, "tokenized cmd input")
                .with_data("bytes", command.len().to_string())
                .with_data("tokens", document.tokens().len().to_string()),
        );
        for diagnostic in document.diagnostics() {
            host.unsupported(
                Engine::Cmd,
                depth,
                &format!("cmd tokenizer diagnostic: {}", diagnostic.message),
            );
        }
        let output = self.execute_program(&document, document.program(), host, depth)?;
        Ok(CmdResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.code,
            exited: output.exited,
        })
    }

    /// Emulates batch text with a synthetic `<batch>` file name and no arguments.
    ///
    /// # Errors
    ///
    /// Returns an error when an input or host resource limit is reached.
    pub fn emulate_batch(
        &mut self,
        batch: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CmdResult, CmdError> {
        self.emulate_batch_with_args(batch, "<batch>", &[] as &[String], host, depth)
    }

    /// Emulates batch text with a file name and `%0`-`%9` arguments.
    ///
    /// # Errors
    ///
    /// Returns an error when an input, nesting, step, or loop resource limit is reached.
    pub fn emulate_batch_with_args<S: AsRef<str>>(
        &mut self,
        batch: &str,
        file_name: &str,
        args: &[S],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CmdResult, CmdError> {
        if batch.len() > MAX_INPUT_BYTES {
            return Err(CmdError::InputTooLarge);
        }
        let arguments = args.iter().map(|value| value.as_ref().into()).collect();
        self.batch = Some(BatchContext::new(batch, file_name, arguments));
        let result = self.run_batch_context(host, depth);
        self.batch = None;
        result
    }

    fn run_batch_context(
        &mut self,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CmdResult, CmdError> {
        let mut result = CommandOutput::default();
        loop {
            let Some(context) = self.batch.as_ref() else {
                break;
            };
            if context.pc >= context.lines.len() {
                if context.call_depth() == 0 {
                    break;
                }
                self.batch
                    .as_mut()
                    .expect("batch context exists")
                    .return_from_call();
                continue;
            }
            let execution_depth = depth.saturating_add(context.call_depth());
            host.consume_step(
                Engine::Cmd,
                execution_depth,
                "executing batch program counter",
            )?;
            let line = context.lines[context.pc].clone();
            self.batch.as_mut().expect("batch context exists").pc += 1;
            let trimmed = line.source().trim();
            if trimmed.is_empty() || line.is_non_executable() {
                continue;
            }
            let line_output = self.execute_program(&line, line.program(), host, execution_depth)?;
            result.stdout.extend(line_output.stdout);
            result.stderr.extend(line_output.stderr);
            result.code = line_output.code;
            result.exited = line_output.exited;
            let action = self
                .batch
                .as_mut()
                .expect("batch context exists")
                .action
                .take();
            self.apply_batch_action(action, &mut result, host, execution_depth)?;
            if result.exited {
                break;
            }
        }
        Ok(CmdResult {
            stdout: result.stdout,
            stderr: result.stderr,
            exit_code: result.code,
            exited: result.exited,
        })
    }

    fn apply_batch_action(
        &mut self,
        action: Option<BatchAction>,
        result: &mut CommandOutput,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), CmdError> {
        match action {
            Some(BatchAction::Goto(label)) => {
                if !self
                    .batch
                    .as_mut()
                    .expect("batch context exists")
                    .jump(&label)
                {
                    result.stderr.push(format!(
                        "The system cannot find the batch label specified - {label}"
                    ));
                    result.code = 1;
                    self.runtime.error_level = 1;
                }
            }
            Some(BatchAction::Call { label, args }) => {
                host.consume_step(Engine::Cmd, depth + 1, "calling batch subroutine")?;
                if !self
                    .batch
                    .as_mut()
                    .expect("batch context exists")
                    .call(&label, args)
                {
                    result.stderr.push(format!(
                        "The system cannot find the batch label specified - {label}"
                    ));
                    result.code = 1;
                    self.runtime.error_level = 1;
                }
            }
            Some(BatchAction::Return(code)) => {
                self.runtime.error_level = code;
                result.code = code;
                self.batch
                    .as_mut()
                    .expect("batch context exists")
                    .return_from_call();
            }
            None => {}
        }
        Ok(())
    }

    pub(crate) fn expand(&mut self, source: &str, host: &dyn Host) -> String {
        expansion::expand(
            source,
            &mut self.runtime,
            self.batch.as_ref(),
            &self.loop_variables,
            host,
        )
    }

    pub(crate) fn request_batch_action(&mut self, action: BatchAction) -> bool {
        let Some(batch) = self.batch.as_mut() else {
            return false;
        };
        batch.action = Some(action);
        true
    }

    pub(crate) fn shift_batch(&mut self) -> bool {
        let Some(batch) = self.batch.as_mut() else {
            return false;
        };
        batch.shift();
        true
    }

    pub(crate) fn has_batch_action(&self) -> bool {
        self.batch
            .as_ref()
            .is_some_and(|batch| batch.action.is_some())
    }

    pub(crate) fn execute_chain(
        &mut self,
        command: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, CmdError> {
        let document = ParsedDocument::parse(command);
        self.execute_program(&document, document.program(), host, depth)
    }

    fn execute_program(
        &mut self,
        document: &ParsedDocument,
        program: &Program,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, CmdError> {
        let parts = &program.parts;
        let mut aggregate = CommandOutput {
            code: self.runtime.error_level,
            ..CommandOutput::default()
        };
        let mut index = 0;
        while index < parts.len() {
            let part = &parts[index];
            let should_run = match part.operator {
                ChainOperator::Always | ChainOperator::Pipe => true,
                ChainOperator::OnSuccess => aggregate.code == 0,
                ChainOperator::OnFailure => aggregate.code != 0,
            };
            if !should_run {
                index += 1;
                while index < parts.len() && parts[index].operator == ChainOperator::Pipe {
                    index += 1;
                }
                continue;
            }
            let mut output = self.execute_ast_command(document, &part.command, host, depth)?;
            let previous_pipe = self.pipe_input.take();
            while index + 1 < parts.len()
                && parts[index + 1].operator == ChainOperator::Pipe
                && !output.exited
                && !self.has_batch_action()
            {
                aggregate.stderr.append(&mut output.stderr);
                self.pipe_input = Some(std::mem::take(&mut output.stdout));
                index += 1;
                output = self.execute_ast_command(document, &parts[index].command, host, depth)?;
            }
            self.pipe_input = previous_pipe;
            aggregate.stdout.append(&mut output.stdout);
            aggregate.stderr.append(&mut output.stderr);
            aggregate.code = output.code;
            aggregate.exited = output.exited;
            self.runtime.error_level = output.code;
            if output.exited || self.has_batch_action() {
                break;
            }
            index += 1;
        }
        Ok(aggregate)
    }

    fn execute_ast_command(
        &mut self,
        document: &ParsedDocument,
        command: &Command,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, CmdError> {
        let raw = render_core(document, command);
        let expanded = self.expand(&raw, host);
        let mut output = if expanded == raw {
            host.consume_step(Engine::Cmd, depth, "executing cmd command")?;
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::Cmd,
                    EventKind::Command,
                    "emulated cmd command",
                )
                .with_data("command", raw.clone()),
            );
            if let Some(group) = &command.group {
                self.execute_program(document, group, host, depth + 1)?
            } else if let CommandKind::If(statement) = &command.kind {
                self.execute_ast_if(document, statement, host, depth)?
            } else if let CommandKind::For(statement) = &command.kind {
                self.execute_ast_for(document, statement, host, depth)?
            } else if let CommandKind::Simple { command, arguments } = &command.kind {
                let command = unquote_and_unescape(document.text(*command));
                let rest = arguments
                    .iter()
                    .map(|argument| document.text(*argument))
                    .collect::<Vec<_>>()
                    .join(" ");
                builtins::execute_parts(self, &command, &rest, host, depth)?
            } else {
                unreachable!("all cmd command kinds are handled")
            }
        } else {
            let expanded_document = ParsedDocument::parse(&expanded);
            self.execute_program(&expanded_document, expanded_document.program(), host, depth)?
        };
        self.apply_ast_redirections(&mut output, document, &command.redirections, host, depth)?;
        for line in &output.stdout {
            host.emit(
                TraceEvent::new(depth, Engine::Cmd, EventKind::Output, line.clone())
                    .with_data("stream", "stdout")
                    .with_data("exit_code", output.code.to_string()),
            );
        }
        for line in &output.stderr {
            host.emit(
                TraceEvent::new(depth, Engine::Cmd, EventKind::Output, line.clone())
                    .with_data("stream", "stderr")
                    .with_data("exit_code", output.code.to_string()),
            );
        }
        Ok(output)
    }

    fn execute_ast_if(
        &mut self,
        document: &ParsedDocument,
        statement: &ast::IfCommand,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, CmdError> {
        use std::cmp::Ordering;
        let condition = match statement.condition {
            IfCondition::ErrorLevel(value) => {
                let threshold = document
                    .text(value)
                    .trim_matches('"')
                    .parse::<i32>()
                    .unwrap_or(i32::MAX);
                self.runtime.error_level >= threshold
            }

            IfCondition::Exist(path) => {
                let path = document.text(path).trim_matches('"');
                let resolved = self.runtime.resolve_path(path);
                let normalized = emulator_core::normalize_windows_path(&resolved);
                if resolved.contains(['*', '?']) {
                    let prefix = resolved.split(['*', '?']).next().unwrap_or(&resolved);
                    host.list_files(prefix, Engine::Cmd, depth)
                        .iter()
                        .any(|file| wildcard_match(file, &resolved))
                        || self
                            .runtime
                            .directories
                            .iter()
                            .any(|directory| wildcard_match(directory, &normalized))
                        || host
                            .list_directories(prefix, Engine::Cmd, depth)
                            .iter()
                            .any(|directory| wildcard_match(directory, &normalized))
                } else {
                    self.runtime.directories.contains(&normalized)
                        || host.directory_exists(&resolved)
                        || host.read_file(&resolved, Engine::Cmd, depth).is_some()
                }
            }

            IfCondition::Defined(name) => host
                .environment(document.text(name).trim_matches('"'))
                .is_some(),
            IfCondition::Equal { left, right } => {
                compare_cmd_values(
                    document.text(left).trim_matches('"'),
                    document.text(right).trim_matches('"'),
                    statement.ignore_case,
                ) == Ordering::Equal
            }
            IfCondition::Compare {
                left,
                operator,
                right,
            } => {
                let ordering = compare_cmd_values(
                    document.text(left).trim_matches('"'),
                    document.text(right).trim_matches('"'),
                    statement.ignore_case,
                );
                match document.text(operator).to_ascii_lowercase().as_str() {
                    "equ" => ordering == Ordering::Equal,
                    "neq" => ordering != Ordering::Equal,
                    "lss" => ordering == Ordering::Less,
                    "leq" => ordering != Ordering::Greater,
                    "gtr" => ordering == Ordering::Greater,
                    "geq" => ordering != Ordering::Less,
                    _ => false,
                }
            }
        };
        let condition = if statement.negate {
            !condition
        } else {
            condition
        };
        let selected = if condition {
            Some(statement.then_program.as_ref())
        } else {
            statement.else_program.as_deref()
        };
        if let Some(program) = selected {
            self.execute_program(document, program, host, depth + 1)
        } else {
            Ok(CommandOutput {
                code: self.runtime.error_level,
                ..CommandOutput::default()
            })
        }
    }

    fn execute_ast_for(
        &mut self,
        document: &ParsedDocument,
        statement: &ast::ForCommand,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, CmdError> {
        let mut prelude = CommandOutput {
            code: self.runtime.error_level,
            ..CommandOutput::default()
        };
        let set = document.text(statement.set);
        let values = match &statement.mode {
            ForMode::Simple => syntax::split_words(set)
                .into_iter()
                .map(|value| vec![value])
                .collect(),
            ForMode::Linear => control::linear_values(set, host.limits().max_loop_iterations),
            ForMode::Recursive { root } => control::recursive_values(
                self,
                root.map(|root| document.text(root).trim_matches('"'))
                    .unwrap_or_default(),
                set,
                host,
                depth,
            ),
            ForMode::Text { options } => {
                control::text_values(self, set, options, host, depth, &mut prelude)?
            }
        };
        let mut output = prelude;
        let limit = host.limits().max_loop_iterations;
        for (iteration, assignments) in values.into_iter().enumerate() {
            if iteration >= limit {
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::Cmd,
                        EventKind::LimitReached,
                        "cmd FOR iteration limit reached",
                    )
                    .with_data("limit", limit.to_string()),
                );
                return Err(CmdError::LoopLimit { limit });
            }
            host.consume_step(Engine::Cmd, depth, "executing cmd FOR iteration")?;
            let variables = control::assignments_for(statement.variable, assignments);
            let previous = variables
                .iter()
                .map(|(name, _)| (*name, self.loop_variables.get(name).cloned()))
                .collect::<Vec<_>>();
            self.loop_variables.extend(variables);
            let result = self.execute_program(document, &statement.body, host, depth + 1);
            for (name, value) in previous {
                if let Some(value) = value {
                    self.loop_variables.insert(name, value);
                } else {
                    self.loop_variables.remove(&name);
                }
            }
            let result = result?;
            output.stdout.extend(result.stdout);
            output.stderr.extend(result.stderr);
            output.code = result.code;
            output.exited = result.exited;
            if result.exited || self.has_batch_action() {
                break;
            }
        }
        Ok(output)
    }

    fn apply_ast_redirections(
        &self,
        output: &mut CommandOutput,
        document: &ParsedDocument,
        redirections: &[ast::Redirection],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), CmdError> {
        let redirections = redirections
            .iter()
            .map(|redirection| syntax::Redirection {
                stream: redirection.stream,
                target: redirection
                    .target
                    .map(|target| unquote_and_unescape(document.text(target)))
                    .unwrap_or_default(),
                append: redirection.append,
                merge_to: redirection.merge_to,
            })
            .collect();
        self.apply_redirections(output, redirections, host, depth)
    }

    fn apply_redirections(
        &self,
        output: &mut CommandOutput,
        redirections: Vec<syntax::Redirection>,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), CmdError> {
        let mut stdout_sink = OutputSink::Stdout;
        let mut stderr_sink = OutputSink::Stderr;
        for redirection in redirections {
            if let Some(to) = redirection.merge_to {
                match (redirection.stream, to) {
                    (Stream::Stderr, Stream::Stdout) => stderr_sink = stdout_sink.clone(),
                    (Stream::Stdout, Stream::Stderr) => stdout_sink = stderr_sink.clone(),
                    _ => {}
                }
                continue;
            }
            let sink = OutputSink::File {
                path: self.runtime.resolve_path(&redirection.target),
                append: redirection.append,
            };
            match redirection.stream {
                Stream::Stdout => stdout_sink = sink,
                Stream::Stderr => stderr_sink = sink,
                Stream::Stdin => {
                    host.unsupported(Engine::Cmd, depth, "cmd input redirection is not supported");
                }
            }
        }

        let stdout = std::mem::take(&mut output.stdout);
        let stderr = std::mem::take(&mut output.stderr);
        let mut files = BTreeMap::<String, (bool, Vec<String>)>::new();
        route_output(stdout, stdout_sink, output, &mut files);
        route_output(stderr, stderr_sink, output, &mut files);
        for (path, (append, lines)) in files {
            let mut bytes = lines.join("\r\n").into_bytes();
            if !bytes.is_empty() {
                bytes.extend_from_slice(b"\r\n");
            }
            host.write_file(&path, &bytes, append, Engine::Cmd, depth)?;
        }
        Ok(())
    }
}

fn route_output(
    lines: Vec<String>,
    sink: OutputSink,
    output: &mut CommandOutput,
    files: &mut BTreeMap<String, (bool, Vec<String>)>,
) {
    match sink {
        OutputSink::Stdout => output.stdout.extend(lines),
        OutputSink::Stderr => output.stderr.extend(lines),
        OutputSink::File { path, append } => {
            let entry = files.entry(path).or_insert_with(|| (append, Vec::new()));
            entry.1.extend(lines);
        }
    }
}

fn render_core(document: &ParsedDocument, command: &Command) -> String {
    command
        .core_ranges
        .iter()
        .map(|range| document.text(*range))
        .collect::<String>()
        .trim()
        .to_string()
}

fn compare_cmd_values(left: &str, right: &str, ignore_case: bool) -> std::cmp::Ordering {
    match (left.parse::<i64>(), right.parse::<i64>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ if ignore_case => left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase()),
        _ => left.cmp(right),
    }
}

fn wildcard_match(value: &str, pattern: &str) -> bool {
    wildcard_bytes(
        value.to_ascii_lowercase().as_bytes(),
        pattern.to_ascii_lowercase().as_bytes(),
    )
}

fn wildcard_bytes(value: &[u8], pattern: &[u8]) -> bool {
    match pattern {
        [] => value.is_empty(),
        [b'*', rest @ ..] => {
            wildcard_bytes(value, rest)
                || (!value.is_empty() && wildcard_bytes(&value[1..], pattern))
        }
        [b'?', rest @ ..] => !value.is_empty() && wildcard_bytes(&value[1..], rest),
        [first, rest @ ..] => value.first() == Some(first) && wildcard_bytes(&value[1..], rest),
    }
}
