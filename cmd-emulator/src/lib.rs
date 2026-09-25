mod batch;
mod builtins;
mod control;
mod expansion;
mod runtime;
mod syntax;

pub mod tokenizer;

use batch::{BatchAction, BatchContext};
use emulator_core::{Engine, EventKind, Host, HostError, TraceEvent};
use runtime::Runtime;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use syntax::{parse_redirections, split_chain, strip_outer_group, ChainOperator, Stream};
use thiserror::Error;

const MAX_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CmdResult {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub exit_code: i32,
    pub exited: bool,
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
        let tokenization = tokenizer::tokenize(command);
        host.emit(
            TraceEvent::new(depth, Engine::Cmd, EventKind::Parse, "tokenized cmd input")
                .with_data("bytes", command.len().to_string())
                .with_data("tokens", tokenization.tokens.len().to_string()),
        );
        for diagnostic in tokenization.diagnostics {
            host.unsupported(
                Engine::Cmd,
                depth,
                &format!("cmd tokenizer diagnostic: {}", diagnostic.message),
            );
        }
        let output = self.execute_chain(command, host, depth)?;
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
            let trimmed = line.trim();
            if trimmed.is_empty() || BatchContext::is_label(trimmed) || trimmed.starts_with("::") {
                continue;
            }
            let line_output = self.execute_chain(trimmed, host, execution_depth)?;
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
        let parts = split_chain(command);
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
            let expanded = self.expand(&part.command, host);
            let mut output = self.execute_one(&expanded, host, depth)?;
            let previous_pipe = self.pipe_input.take();
            while index + 1 < parts.len()
                && parts[index + 1].operator == ChainOperator::Pipe
                && !output.exited
                && !self.has_batch_action()
            {
                aggregate.stderr.append(&mut output.stderr);
                self.pipe_input = Some(std::mem::take(&mut output.stdout));
                index += 1;
                let expanded = self.expand(&parts[index].command, host);
                output = self.execute_one(&expanded, host, depth)?;
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

    fn execute_one(
        &mut self,
        command: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<CommandOutput, CmdError> {
        host.consume_step(Engine::Cmd, depth, "executing cmd command")?;
        let (command, redirections) = parse_redirections(command);
        host.emit(
            TraceEvent::new(
                depth,
                Engine::Cmd,
                EventKind::Command,
                "emulated cmd command",
            )
            .with_data("command", command.clone()),
        );
        let mut output = if let Some(inner) = strip_outer_group(&command) {
            self.execute_chain(inner, host, depth + 1)?
        } else if let Some(output) = control::execute(self, &command, host, depth)? {
            output
        } else {
            builtins::execute(self, &command, host, depth)?
        };
        self.apply_redirections(&mut output, redirections, host, depth)?;
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
