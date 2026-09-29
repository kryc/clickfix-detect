mod ast;
mod builtins;
mod expansion;
mod parser;
mod runtime;

pub mod tokenizer;

use ast::{Command, ListOperator, Pipeline, Program, RedirectKind, Redirection, SimpleCommand};
use emulator_core::{Engine, EventKind, Host, HostError, ProcessIntent, ProcessResult, TraceEvent};
use parser::ParsedDocument;
use runtime::{FlowControl, Runtime};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BashResult {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub exit_code: i32,
    pub exited: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BashParseSummary {
    pub bytes: usize,
    pub tokens: usize,
    pub commands: usize,
    pub diagnostics: Vec<String>,
    pub detailed_diagnostics: Vec<BashParseDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BashParseDiagnostic {
    pub start: usize,
    pub end: usize,
    pub message: String,
    pub fatal: bool,
}

#[derive(Debug, Error)]
pub enum BashError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("bash input exceeds the {MAX_INPUT_BYTES} byte limit")]
    InputTooLarge,
    #[error("bash parsing failed: {0}")]
    Parser(String),
    #[error("bash loop iteration limit {limit} reached")]
    LoopLimit { limit: usize },
}

#[derive(Debug, Clone, Default)]
pub struct BashEmulator {
    runtime: Runtime,
    pipe_input: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CommandOutput {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub code: i32,
}

impl BashEmulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn current_directory(&self) -> &str {
        &self.runtime.current_directory
    }

    #[must_use]
    pub fn last_status(&self) -> i32 {
        self.runtime.last_status
    }

    pub fn set_arguments<S: AsRef<str>>(&mut self, script_name: &str, arguments: &[S]) {
        self.runtime.script_name = script_name.into();
        self.runtime.positional = arguments
            .iter()
            .map(|argument| argument.as_ref().into())
            .collect();
    }

    #[must_use]
    pub fn parse(source: &str) -> BashParseSummary {
        let document = ParsedDocument::parse(source);
        BashParseSummary {
            bytes: source.len(),
            tokens: document.tokens().len(),
            commands: count_commands(document.program()),
            diagnostics: document
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.message.clone())
                .collect(),
            detailed_diagnostics: document
                .diagnostics()
                .iter()
                .map(|diagnostic| BashParseDiagnostic {
                    start: diagnostic.span.start,
                    end: diagnostic.span.end,
                    message: diagnostic.message.clone(),
                    fatal: diagnostic.fatal,
                })
                .collect(),
        }
    }

    /// Parse and emulate Bash source against a hermetic host.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing fails or a configured host resource limit is reached.
    pub fn emulate(
        &mut self,
        source: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<BashResult, BashError> {
        self.emulate_with_args(source, "bash", &[] as &[String], host, depth)
    }

    /// Parse and emulate a Bash script with positional arguments.
    ///
    /// # Errors
    ///
    /// Returns an error when parsing fails or a configured host resource limit is reached.
    pub fn emulate_with_args<S: AsRef<str>>(
        &mut self,
        source: &str,
        script_name: &str,
        arguments: &[S],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<BashResult, BashError> {
        if source.len() > MAX_INPUT_BYTES {
            return Err(BashError::InputTooLarge);
        }
        if !self.runtime.initialized_from_host {
            if let Some(directory) = host.environment("PWD").or_else(|| host.environment("HOME")) {
                self.runtime.current_directory = directory.into();
            }
            self.runtime.initialized_from_host = true;
        }
        self.set_arguments(script_name, arguments);
        self.runtime.flow = FlowControl::None;
        let output = self.execute_source(source, host, depth)?;
        let exited = matches!(self.runtime.flow, FlowControl::Exit(_));
        let exit_code = match self.runtime.flow {
            FlowControl::Exit(code) | FlowControl::Return(code) => code,
            _ => output.code,
        };
        self.runtime.last_status = exit_code;
        Ok(BashResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code,
            exited,
        })
    }

    pub(crate) fn execute_source(
        &mut self,
        source: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, BashError> {
        host.consume_step(Engine::Bash, depth, "parsing Bash input")?;
        let document = ParsedDocument::parse(source);
        if let Some(diagnostic) = document.diagnostics().iter().find(|item| item.fatal) {
            return Err(BashError::Parser(diagnostic.message.clone()));
        }
        host.emit(
            TraceEvent::new(
                depth,
                Engine::Bash,
                EventKind::Parse,
                "tokenized Bash input",
            )
            .with_data("bytes", source.len().to_string())
            .with_data("tokens", document.tokens().len().to_string()),
        );
        for diagnostic in document.diagnostics() {
            host.unsupported(
                Engine::Bash,
                depth,
                &format!("Bash structural diagnostic: {}", diagnostic.message),
            );
        }
        self.execute_program(&document, document.program(), host, depth)
    }

    pub(crate) fn execute_substitution(
        &mut self,
        source: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, BashError> {
        let mut nested = self.clone();
        nested.runtime.flow = FlowControl::None;
        let output = nested.execute_source(source, host, depth)?;
        Ok(output.stdout.join("\n").trim_end_matches('\n').into())
    }

    fn execute_program(
        &mut self,
        document: &ParsedDocument,
        program: &Program,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, BashError> {
        let mut aggregate = CommandOutput {
            code: self.runtime.last_status,
            ..CommandOutput::default()
        };
        for item in &program.items {
            if !matches!(self.runtime.flow, FlowControl::None) {
                break;
            }
            let should_run = match item.operator {
                ListOperator::Always | ListOperator::Background => true,
                ListOperator::OnSuccess => aggregate.code == 0,
                ListOperator::OnFailure => aggregate.code != 0,
            };
            if !should_run {
                continue;
            }
            if item.operator == ListOperator::Background {
                host.unsupported(
                    Engine::Bash,
                    depth,
                    "background command was emulated synchronously",
                );
            }
            let mut output = self.execute_pipeline(document, &item.pipeline, host, depth)?;
            aggregate.stdout.append(&mut output.stdout);
            aggregate.stderr.append(&mut output.stderr);
            aggregate.code = output.code;
            self.runtime.last_status = output.code;
        }
        Ok(aggregate)
    }

    fn execute_pipeline(
        &mut self,
        document: &ParsedDocument,
        pipeline: &Pipeline,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, BashError> {
        let previous_input = self.pipe_input.take();
        let mut aggregate_stderr = Vec::new();
        let mut output = CommandOutput::default();
        for (index, command) in pipeline.commands.iter().enumerate() {
            output = if pipeline.commands.len() > 1 {
                let mut stage = self.clone();
                stage.pipe_input = self.pipe_input.take();
                stage.execute_command(document, command, host, depth)?
            } else {
                self.execute_command(document, command, host, depth)?
            };
            aggregate_stderr.append(&mut output.stderr);
            if index + 1 < pipeline.commands.len() {
                self.pipe_input = Some(std::mem::take(&mut output.stdout));
            }
        }
        self.pipe_input = previous_input;
        output.stderr = aggregate_stderr;
        if pipeline.negated {
            output.code = i32::from(output.code == 0);
        }
        Ok(output)
    }

    #[allow(clippy::too_many_lines)]
    fn execute_command(
        &mut self,
        document: &ParsedDocument,
        command: &Command,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, BashError> {
        host.consume_step(Engine::Bash, depth, "executing Bash command")?;
        let output = match command {
            Command::Simple(command) => self.execute_simple(document, command, host, depth)?,
            Command::If {
                branches,
                else_body,
            } => {
                let mut selected = None;
                let mut aggregate = CommandOutput::default();
                for (condition, body) in branches {
                    let mut condition_output =
                        self.execute_program(document, condition, host, depth + 1)?;
                    aggregate.stdout.append(&mut condition_output.stdout);
                    aggregate.stderr.append(&mut condition_output.stderr);
                    if condition_output.code == 0 {
                        selected = Some(body);
                        break;
                    }
                }
                if let Some(body) = selected.or(else_body.as_ref()) {
                    let mut body_output = self.execute_program(document, body, host, depth + 1)?;
                    aggregate.stdout.append(&mut body_output.stdout);
                    aggregate.stderr.append(&mut body_output.stderr);
                    aggregate.code = body_output.code;
                }
                aggregate
            }
            Command::Case { word, arms } => {
                let value = self.expand_word(document, word, host, depth)?;
                let mut selected = None;
                for arm in arms {
                    let mut matched = false;
                    for pattern in &arm.patterns {
                        let pattern = self.expand_word(document, pattern, host, depth)?;
                        if shell_pattern_matches(&value, &pattern) {
                            matched = true;
                            break;
                        }
                    }
                    if matched {
                        selected = Some(&arm.body);
                        break;
                    }
                }
                if let Some(body) = selected {
                    self.execute_program(document, body, host, depth + 1)?
                } else {
                    CommandOutput::default()
                }
            }
            Command::For { name, words, body } => {
                let values = if words.is_empty() {
                    self.runtime.positional.clone()
                } else {
                    let mut values = Vec::new();
                    for word in words {
                        values.extend(self.expand_word_values(document, word, host, depth)?);
                    }
                    values
                };
                let mut aggregate = CommandOutput::default();
                for (index, value) in values.into_iter().enumerate() {
                    if index >= host.limits().max_loop_iterations {
                        return Err(BashError::LoopLimit {
                            limit: host.limits().max_loop_iterations,
                        });
                    }
                    self.runtime.variables.insert(name.clone(), value);
                    let mut iteration = self.execute_program(document, body, host, depth + 1)?;
                    aggregate.stdout.append(&mut iteration.stdout);
                    aggregate.stderr.append(&mut iteration.stderr);
                    aggregate.code = iteration.code;
                    match self.runtime.flow {
                        FlowControl::Break => {
                            self.runtime.flow = FlowControl::None;
                            break;
                        }
                        FlowControl::Continue => self.runtime.flow = FlowControl::None,
                        FlowControl::Return(_) | FlowControl::Exit(_) => break,
                        FlowControl::None => {}
                    }
                }
                aggregate
            }
            Command::ForArithmetic {
                initializer,
                condition,
                update,
                body,
            } => {
                self.evaluate_arithmetic_expression(initializer, host);
                let mut aggregate = CommandOutput::default();
                for index in 0..host.limits().max_loop_iterations {
                    if !condition.is_empty()
                        && self.evaluate_arithmetic_expression(condition, host) == 0
                    {
                        break;
                    }
                    let mut iteration = self.execute_program(document, body, host, depth + 1)?;
                    aggregate.stdout.append(&mut iteration.stdout);
                    aggregate.stderr.append(&mut iteration.stderr);
                    aggregate.code = iteration.code;
                    match self.runtime.flow {
                        FlowControl::Break => {
                            self.runtime.flow = FlowControl::None;
                            break;
                        }
                        FlowControl::Continue => self.runtime.flow = FlowControl::None,
                        FlowControl::Return(_) | FlowControl::Exit(_) => break,
                        FlowControl::None => {}
                    }
                    self.evaluate_arithmetic_expression(update, host);
                    if index + 1 == host.limits().max_loop_iterations {
                        return Err(BashError::LoopLimit {
                            limit: host.limits().max_loop_iterations,
                        });
                    }
                }
                aggregate
            }
            Command::While {
                condition,
                body,
                until,
            } => {
                let mut aggregate = CommandOutput::default();
                for index in 0..host.limits().max_loop_iterations {
                    let mut condition_output =
                        self.execute_program(document, condition, host, depth + 1)?;
                    aggregate.stdout.append(&mut condition_output.stdout);
                    aggregate.stderr.append(&mut condition_output.stderr);
                    let selected = if *until {
                        condition_output.code != 0
                    } else {
                        condition_output.code == 0
                    };
                    if !selected {
                        break;
                    }
                    let mut iteration = self.execute_program(document, body, host, depth + 1)?;
                    aggregate.stdout.append(&mut iteration.stdout);
                    aggregate.stderr.append(&mut iteration.stderr);
                    aggregate.code = iteration.code;
                    match self.runtime.flow {
                        FlowControl::Break => {
                            self.runtime.flow = FlowControl::None;
                            break;
                        }
                        FlowControl::Continue => self.runtime.flow = FlowControl::None,
                        FlowControl::Return(_) | FlowControl::Exit(_) => break,
                        FlowControl::None => {}
                    }
                    if index + 1 == host.limits().max_loop_iterations {
                        return Err(BashError::LoopLimit {
                            limit: host.limits().max_loop_iterations,
                        });
                    }
                }
                aggregate
            }
            Command::Function { name, body } => {
                self.runtime.functions.insert(name.clone(), *body.clone());
                CommandOutput::default()
            }
            Command::Arithmetic { expression } => CommandOutput {
                code: i32::from(self.evaluate_arithmetic_expression(expression, host) == 0),
                ..CommandOutput::default()
            },
            Command::Conditional { expression } => {
                let matched = self.evaluate_conditional(expression, host, depth)?;
                CommandOutput {
                    code: i32::from(!matched),
                    ..CommandOutput::default()
                }
            }
            Command::Group { body, subshell } => {
                if *subshell {
                    let mut nested = self.clone();
                    nested.execute_program(document, body, host, depth + 1)?
                } else {
                    self.execute_program(document, body, host, depth + 1)?
                }
            }
            Command::Redirected {
                command,
                redirections,
            } => {
                let previous_input = self.pipe_input.take();
                let mut input = previous_input.clone().unwrap_or_default();
                self.apply_input_redirections(document, redirections, &mut input, host, depth)?;
                self.pipe_input = Some(input);
                let mut output = self.execute_command(document, command, host, depth + 1)?;
                self.pipe_input = previous_input;
                self.apply_output_redirections(document, redirections, &mut output, host, depth)?;
                output
            }
        };
        Ok(output)
    }

    fn evaluate_conditional(
        &mut self,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<bool, BashError> {
        let expression = self.expand_text(expression, host, depth)?;
        let expression = trim_condition_group(&expression);
        if let Some((left, right)) = split_condition_operator(expression, "||") {
            return Ok(self.evaluate_conditional(left, host, depth)?
                || self.evaluate_conditional(right, host, depth)?);
        }
        if let Some((left, right)) = split_condition_operator(expression, "&&") {
            return Ok(self.evaluate_conditional(left, host, depth)?
                && self.evaluate_conditional(right, host, depth)?);
        }
        let words = split_condition_words(expression);
        let result = match words.as_slice() {
            [operator, value]
                if matches!(operator.as_str(), "-n" | "-z" | "-e" | "-f" | "-d" | "-x") =>
            {
                match operator.as_str() {
                    "-n" => !value.is_empty(),
                    "-z" => value.is_empty(),
                    "-e" => {
                        let path = self.runtime.resolve_path(value);
                        host.directory_exists(&path)
                            || host.read_file(&path, Engine::Bash, depth).is_some()
                    }
                    "-f" => host
                        .read_file(&self.runtime.resolve_path(value), Engine::Bash, depth)
                        .is_some(),
                    "-d" => host.directory_exists(&self.runtime.resolve_path(value)),
                    "-x" => host.is_executable(&self.runtime.resolve_path(value)),
                    _ => false,
                }
            }
            [value] => !value.is_empty(),
            [negation, rest @ ..] if negation == "!" => {
                !self.evaluate_conditional(&rest.join(" "), host, depth)?
            }
            [left, operator, right] => match operator.as_str() {
                "=" | "==" => shell_pattern_matches(left, right),
                "!=" => !shell_pattern_matches(left, right),
                "=~" => left.contains(right),
                "-eq" => numeric_condition(left) == numeric_condition(right),
                "-ne" => numeric_condition(left) != numeric_condition(right),
                "-lt" => numeric_condition(left) < numeric_condition(right),
                "-le" => numeric_condition(left) <= numeric_condition(right),
                "-gt" => numeric_condition(left) > numeric_condition(right),
                "-ge" => numeric_condition(left) >= numeric_condition(right),
                _ => false,
            },
            _ => false,
        };
        Ok(result)
    }

    fn execute_simple(
        &mut self,
        document: &ParsedDocument,
        command: &SimpleCommand,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, BashError> {
        let mut words = Vec::new();
        for word in &command.words {
            words.extend(self.expand_word_values(document, word, host, depth)?);
        }
        let mut assignment_count = 0;
        for word in &words {
            if let Some((name, value)) = parse_assignment(word) {
                self.runtime.variables.insert(name.into(), value.into());
                if self.runtime.exported.contains(name) {
                    host.set_environment(name, value);
                }
                host.emit(
                    TraceEvent::new(
                        depth,
                        Engine::Bash,
                        EventKind::VariableAssignment,
                        format!("assigned shell variable {name}"),
                    )
                    .with_data("value", value),
                );
                assignment_count += 1;
            } else {
                break;
            }
        }
        let arguments = &words[assignment_count..];
        let mut input = self.pipe_input.take().unwrap_or_default();
        self.apply_input_redirections(document, &command.redirections, &mut input, host, depth)?;
        let mut output = if let Some((name, arguments)) = arguments.split_first() {
            host.emit(
                TraceEvent::new(
                    depth,
                    Engine::Bash,
                    EventKind::Command,
                    format!("emulating Bash command {name}"),
                )
                .with_data("arguments", arguments.join(" ")),
            );
            if let Some(function) = self.runtime.functions.get(name).cloned() {
                let previous = std::mem::replace(&mut self.runtime.positional, arguments.to_vec());
                let saved_flow = self.runtime.flow.clone();
                self.runtime.flow = FlowControl::None;
                let mut output = self.execute_command(document, &function, host, depth + 1)?;
                match self.runtime.flow {
                    FlowControl::Return(code) => {
                        output.code = code;
                        self.runtime.flow = saved_flow;
                    }
                    FlowControl::None => self.runtime.flow = saved_flow,
                    FlowControl::Break | FlowControl::Continue | FlowControl::Exit(_) => {}
                }
                self.runtime.positional = previous;
                output
            } else if let Some(output) =
                builtins::execute(self, name, arguments, &input, host, depth)?
            {
                output
            } else {
                self.execute_external(name, arguments, input, host, depth)?
            }
        } else {
            CommandOutput::default()
        };
        self.apply_output_redirections(document, &command.redirections, &mut output, host, depth)?;
        for line in &output.stdout {
            host.emit(
                TraceEvent::new(depth, Engine::Bash, EventKind::Output, line.clone())
                    .with_data("stream", "stdout")
                    .with_data("exit_code", output.code.to_string()),
            );
        }
        for line in &output.stderr {
            host.emit(
                TraceEvent::new(depth, Engine::Bash, EventKind::Output, line.clone())
                    .with_data("stream", "stderr")
                    .with_data("exit_code", output.code.to_string()),
            );
        }
        self.pipe_input = None;
        Ok(output)
    }

    fn apply_input_redirections(
        &mut self,
        document: &ParsedDocument,
        redirections: &[Redirection],
        input: &mut Vec<String>,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), BashError> {
        for redirection in redirections {
            if redirection.fd != 0 {
                continue;
            }
            match redirection.kind {
                RedirectKind::Input => {
                    let Some(target) = &redirection.target else {
                        continue;
                    };
                    let target = self.expand_word(document, target, host, depth)?;
                    let path = self.runtime.resolve_path(&target);
                    if let Some(bytes) = host.read_file(&path, Engine::Bash, depth) {
                        *input = String::from_utf8_lossy(&bytes)
                            .lines()
                            .map(str::to_owned)
                            .collect();
                    }
                }
                RedirectKind::HereString => {
                    let Some(target) = &redirection.target else {
                        continue;
                    };
                    *input = vec![self.expand_word(document, target, host, depth)?];
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn apply_output_redirections(
        &mut self,
        document: &ParsedDocument,
        redirections: &[Redirection],
        output: &mut CommandOutput,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<(), BashError> {
        for redirection in redirections {
            if redirection.kind == RedirectKind::Merge {
                if redirection.fd == 2 && redirection.merge_fd == Some(1) {
                    output.stdout.append(&mut output.stderr);
                } else if redirection.fd == 1 && redirection.merge_fd == Some(2) {
                    output.stderr.append(&mut output.stdout);
                }
                continue;
            }
            if !matches!(
                redirection.kind,
                RedirectKind::Output | RedirectKind::Append
            ) {
                continue;
            }
            let Some(target) = &redirection.target else {
                continue;
            };
            let target = self.expand_word(document, target, host, depth)?;
            let path = self.runtime.resolve_path(&target);
            let lines = if redirection.fd == 2 {
                std::mem::take(&mut output.stderr)
            } else {
                std::mem::take(&mut output.stdout)
            };
            let bytes = if lines.is_empty() {
                Vec::new()
            } else {
                format!("{}\n", lines.join("\n")).into_bytes()
            };
            host.write_file(
                &path,
                &bytes,
                redirection.kind == RedirectKind::Append,
                Engine::Bash,
                depth,
            )?;
        }
        Ok(())
    }

    fn execute_external(
        &mut self,
        program: &str,
        arguments: &[String],
        input: Vec<String>,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, BashError> {
        let command_line = std::iter::once(quote_shell(program))
            .chain(arguments.iter().map(|argument| quote_shell(argument)))
            .collect::<Vec<_>>()
            .join(" ");
        let intent = ProcessIntent {
            program: program.into(),
            args: arguments.to_vec(),
            command_line,
            origin: "Bash external command".into(),
            depth: depth + 1,
            stdin: input,
            current_directory: self.runtime.current_directory.clone(),
        };
        match host.process_request(intent)? {
            Some(ProcessResult {
                stdout,
                stderr,
                exit_code,
            }) => Ok(CommandOutput {
                stdout,
                stderr,
                code: exit_code,
            }),
            None => Ok(CommandOutput {
                stderr: vec![format!("bash: {program}: command not found")],
                code: 127,
                ..CommandOutput::default()
            }),
        }
    }

    pub(crate) fn execute_file(
        &mut self,
        path: &str,
        arguments: &[String],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, BashError> {
        let path = self.runtime.resolve_path(path);
        let Some(bytes) = host.read_file(&path, Engine::Bash, depth) else {
            return Ok(CommandOutput {
                stderr: vec![format!("bash: {path}: No such file or directory")],
                code: 1,
                ..CommandOutput::default()
            });
        };
        let previous_name = std::mem::replace(&mut self.runtime.script_name, path);
        let previous_args = std::mem::replace(&mut self.runtime.positional, arguments.to_vec());
        let output = self.execute_source(&String::from_utf8_lossy(&bytes), host, depth + 1);
        self.runtime.script_name = previous_name;
        self.runtime.positional = previous_args;
        output
    }
}

fn parse_assignment(word: &str) -> Option<(&str, &str)> {
    let (name, value) = word.split_once('=')?;
    if name.is_empty()
        || !name
            .chars()
            .enumerate()
            .all(|(index, ch)| ch == '_' || ch.is_alphanumeric() && (index > 0 || !ch.is_numeric()))
    {
        return None;
    }
    Some((name, value))
}

fn quote_shell(value: &str) -> String {
    if value.is_empty() || value.contains(|ch: char| ch.is_whitespace() || "'\"$;&|()".contains(ch))
    {
        format!("'{}'", value.replace('\'', "'\\''"))
    } else {
        value.into()
    }
}

fn shell_pattern_matches(value: &str, pattern: &str) -> bool {
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

fn trim_condition_group(expression: &str) -> &str {
    let expression = expression.trim();
    expression
        .strip_prefix('(')
        .and_then(|value| value.strip_suffix(')'))
        .map_or(expression, str::trim)
}

fn split_condition_operator<'a>(expression: &'a str, operator: &str) -> Option<(&'a str, &'a str)> {
    let mut quote = None;
    let mut depth = 0_usize;
    let mut offset = 0;
    while offset < expression.len() {
        let ch = expression[offset..].chars().next()?;
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else if ch == '\\' && delimiter != '\'' {
                offset += ch.len_utf8();
                if offset < expression.len() {
                    offset += expression[offset..].chars().next()?.len_utf8();
                    continue;
                }
            }
        } else if matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth = depth.saturating_sub(1);
        } else if depth == 0 && expression[offset..].starts_with(operator) {
            return Some((
                expression[..offset].trim(),
                expression[offset + operator.len()..].trim(),
            ));
        }
        offset += ch.len_utf8();
    }
    None
}

fn split_condition_words(expression: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in expression.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            } else {
                current.push(ch);
            }
        } else if matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if ch.is_whitespace() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
        } else if !matches!(ch, '(' | ')') {
            current.push(ch);
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn numeric_condition(value: &str) -> i64 {
    value.parse().unwrap_or(0)
}

fn count_commands(program: &Program) -> usize {
    program
        .items
        .iter()
        .map(|item| item.pipeline.commands.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulator_core::{AnalysisLimits, VirtualHost};

    #[test]
    fn expands_variables_control_flow_and_command_substitution() {
        let mut host = VirtualHost::macos(AnalysisLimits::default());
        let mut emulator = BashEmulator::new();
        let result = emulator
            .emulate(
                "name=world; if true; then echo \"hello $name $(printf ok)\"; fi",
                &mut host,
                0,
            )
            .unwrap();

        assert_eq!(result.stdout, ["hello world ok"]);
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn writes_and_reads_virtual_files_through_pipelines() {
        let mut host = VirtualHost::macos(AnalysisLimits::default());
        let mut emulator = BashEmulator::new();
        let result = emulator
            .emulate(
                "printf 'alpha\\nbeta\\n' > /tmp/data; cat /tmp/data | grep beta",
                &mut host,
                0,
            )
            .unwrap();

        assert_eq!(result.stdout, ["beta"]);
        assert_eq!(host.virtual_file("/tmp/data"), Some(&b"alpha\nbeta\n"[..]));
    }
}
