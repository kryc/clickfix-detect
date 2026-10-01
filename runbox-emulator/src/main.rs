use clap::{Parser, ValueEnum};
use cmd_emulator::{CmdEmulator, CmdResult};
use emulator_core::{AnalysisLimits, Host, HostSnapshot, NetworkPolicy};
use powershell_emulator::{
    tokenizer::{tokenize, Delimiter, TokenKind},
    PowerShellEmulator,
};
use runbox_emulator::Runbox;
use rustyline::{error::ReadlineError, DefaultEditor};
use std::io::{self, BufRead, IsTerminal, Read};
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Debug, Clone)]
struct EnvironmentOverride {
    name: String,
    value: String,
}

impl FromStr for EnvironmentOverride {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((name, value)) = value.split_once('=') else {
            return Err("environment overrides must use NAME=VALUE".into());
        };
        if name.trim().is_empty() {
            return Err("environment variable name must not be empty".into());
        }
        Ok(Self {
            name: name.trim().into(),
            value: value.into(),
        })
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "runbox-emulator",
    about = "Interactive Windows shell backed by cross-emulator Runbox dispatch"
)]
#[allow(clippy::struct_excessive_bools)]
struct Arguments {
    /// Select the persistent interactive shell language.
    #[arg(long, value_enum, default_value = "cmd")]
    shell: ShellMode,

    /// Command supplied directly as a positional argument.
    #[arg(value_name = "COMMAND", conflicts_with_all = ["command", "file"])]
    positional: Option<String>,

    /// Command supplied as a command string.
    #[arg(short = 'c', long, value_name = "COMMAND", conflicts_with_all = ["positional", "file"])]
    command: Option<String>,

    /// Read batch input from a file. File access occurs before emulation.
    #[arg(short = 'f', long, value_name = "PATH", conflicts_with_all = ["positional", "command"])]
    file: Option<PathBuf>,

    /// Batch argument exposed through `%1` and later positions. May be repeated.
    #[arg(long = "arg", value_name = "VALUE", requires = "file")]
    file_args: Vec<String>,

    /// Force interactive mode, including when standard input is piped.
    #[arg(
        short = 'i',
        long,
        conflicts_with_all = ["positional", "command", "file"]
    )]
    interactive: bool,

    /// Enable delayed !VAR! expansion.
    #[arg(long)]
    delayed_expansion: bool,

    /// Allow bounded public HTTP(S) requests from nested emulators.
    #[arg(long)]
    allow_network: bool,

    /// Print new emulation trace events to standard error.
    #[arg(long)]
    trace: bool,

    /// Override a virtual environment variable. May be repeated.
    #[arg(long = "env", value_name = "NAME=VALUE")]
    environment: Vec<EnvironmentOverride>,

    /// Maximum emulation steps.
    #[arg(long, default_value_t = 20_000)]
    max_steps: usize,

    /// Maximum recursive execution depth.
    #[arg(long, default_value_t = 12)]
    max_depth: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ShellMode {
    Cmd,
    Powershell,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("runbox-emulator: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    if arguments.interactive
        || (arguments.positional.is_none()
            && arguments.command.is_none()
            && arguments.file.is_none()
            && io::stdin().is_terminal())
    {
        return run_interactive(&arguments);
    }

    let (input, batch_name) = read_input(&arguments)?;
    let mut runbox = create_runbox(&arguments);
    match arguments.shell {
        ShellMode::Cmd => {
            let mut emulator =
                CmdEmulator::new().with_delayed_expansion(arguments.delayed_expansion);
            let result = execute_cmd(
                &mut emulator,
                &mut runbox,
                &input,
                batch_name.as_deref(),
                &arguments.file_args,
            )?;
            print_cmd_result(&result);
        }
        ShellMode::Powershell => {
            if !arguments.file_args.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--arg is only supported by the cmd shell",
                )
                .into());
            }
            let mut emulator = PowerShellEmulator::new();
            execute_powershell(&mut emulator, &mut runbox, &input)?;
        }
    }
    if arguments.trace {
        print_trace(&runbox.host().snapshot(), 0);
    }
    Ok(())
}

fn run_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    match (arguments.shell, io::stdin().is_terminal()) {
        (ShellMode::Cmd, true) => run_terminal_interactive(arguments),
        (ShellMode::Cmd, false) => run_stream_interactive(arguments),
        (ShellMode::Powershell, true) => run_powershell_terminal_interactive(arguments),
        (ShellMode::Powershell, false) => run_powershell_stream_interactive(arguments),
    }
}

fn run_terminal_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let mut runbox = create_runbox(arguments);
    let mut emulator = CmdEmulator::new().with_delayed_expansion(arguments.delayed_expansion);
    let mut editor = DefaultEditor::new()?;
    let mut trace_index = 0;
    loop {
        let prompt = format!("{}> ", emulator.current_directory());
        match editor.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if matches_ignore_ascii_case(trimmed, &["exit", "quit"]) {
                    break;
                }
                if !trimmed.is_empty() {
                    editor.add_history_entry(trimmed)?;
                    evaluate_interactive(
                        trimmed,
                        &mut emulator,
                        &mut runbox,
                        arguments.trace,
                        &mut trace_index,
                    );
                }
            }
            Err(ReadlineError::Interrupted) => {}
            Err(ReadlineError::Eof) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn run_stream_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut runbox = create_runbox(arguments);
    let mut emulator = CmdEmulator::new().with_delayed_expansion(arguments.delayed_expansion);
    let mut trace_index = 0;
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if matches_ignore_ascii_case(trimmed, &["exit", "quit"]) {
            break;
        }
        if !trimmed.is_empty() {
            evaluate_interactive(
                trimmed,
                &mut emulator,
                &mut runbox,
                arguments.trace,
                &mut trace_index,
            );
        }
    }
    Ok(())
}

fn run_powershell_terminal_interactive(
    arguments: &Arguments,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut runbox = create_runbox(arguments);
    let mut emulator = PowerShellEmulator::new();
    let mut editor = DefaultEditor::new()?;
    let mut buffer = String::new();
    let mut trace_index = 0;
    loop {
        let prompt = if buffer.is_empty() { "PS> " } else { ">> " };
        match editor.readline(prompt) {
            Ok(line) => match accept_powershell_line(&line, &mut buffer) {
                PowerShellReplAction::Continue => {}
                PowerShellReplAction::Help => {
                    println!("Enter PowerShell code. Use exit, quit, :exit, or Ctrl-D to leave.");
                }
                PowerShellReplAction::Exit => break,
                PowerShellReplAction::Evaluate => {
                    let entry = buffer.trim_end().to_owned();
                    if !entry.is_empty() {
                        editor.add_history_entry(entry)?;
                    }
                    evaluate_powershell_interactive(
                        &buffer,
                        &mut emulator,
                        &mut runbox,
                        arguments.trace,
                        &mut trace_index,
                    );
                    buffer.clear();
                }
            },
            Err(ReadlineError::Interrupted) => buffer.clear(),
            Err(ReadlineError::Eof) => {
                if !buffer.trim().is_empty() {
                    evaluate_powershell_interactive(
                        &buffer,
                        &mut emulator,
                        &mut runbox,
                        arguments.trace,
                        &mut trace_index,
                    );
                }
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn run_powershell_stream_interactive(
    arguments: &Arguments,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut runbox = create_runbox(arguments);
    let mut emulator = PowerShellEmulator::new();
    let mut buffer = String::new();
    let mut trace_index = 0;
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            if !buffer.trim().is_empty() {
                evaluate_powershell_interactive(
                    &buffer,
                    &mut emulator,
                    &mut runbox,
                    arguments.trace,
                    &mut trace_index,
                );
            }
            break;
        }
        match accept_powershell_line(&line, &mut buffer) {
            PowerShellReplAction::Continue => {}
            PowerShellReplAction::Help => {
                println!("Enter PowerShell code. Use exit, quit, :exit, or Ctrl-D to leave.");
            }
            PowerShellReplAction::Exit => break,
            PowerShellReplAction::Evaluate => {
                evaluate_powershell_interactive(
                    &buffer,
                    &mut emulator,
                    &mut runbox,
                    arguments.trace,
                    &mut trace_index,
                );
                buffer.clear();
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PowerShellReplAction {
    Continue,
    Help,
    Exit,
    Evaluate,
}

fn accept_powershell_line(line: &str, buffer: &mut String) -> PowerShellReplAction {
    let trimmed = line.trim();
    if buffer.is_empty() && matches!(trimmed, "exit" | "quit" | ":exit" | ":quit") {
        return PowerShellReplAction::Exit;
    }
    if buffer.is_empty() && trimmed == ":help" {
        return PowerShellReplAction::Help;
    }
    buffer.push_str(line);
    if !line.ends_with('\n') {
        buffer.push('\n');
    }
    if powershell_input_is_complete(buffer) {
        PowerShellReplAction::Evaluate
    } else {
        PowerShellReplAction::Continue
    }
}

fn evaluate_powershell_interactive(
    script: &str,
    emulator: &mut PowerShellEmulator,
    runbox: &mut Runbox,
    trace: bool,
    trace_index: &mut usize,
) {
    if let Err(error) = execute_powershell(emulator, runbox, script) {
        eprintln!("runbox-emulator: {error}");
    }
    let snapshot = runbox.host().snapshot();
    if trace {
        print_trace(&snapshot, *trace_index);
    }
    *trace_index = snapshot.trace.len();
}

fn evaluate_interactive(
    command: &str,
    emulator: &mut CmdEmulator,
    runbox: &mut Runbox,
    trace: bool,
    trace_index: &mut usize,
) {
    match execute_cmd(emulator, runbox, command, None, &[]) {
        Ok(result) => print_cmd_result(&result),
        Err(error) => eprintln!("runbox-emulator: {error}"),
    }
    let snapshot = runbox.host().snapshot();
    if trace {
        print_trace(&snapshot, *trace_index);
    }
    *trace_index = snapshot.trace.len();
}

fn execute_powershell(
    emulator: &mut PowerShellEmulator,
    runbox: &mut Runbox,
    script: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = emulator.emulate(script, runbox, 0);
    let stdout = emulator.drain_stdout();
    let drain_result = runbox.drain_pending_processes();
    for line in stdout {
        println!("{line}");
    }
    result?;
    drain_result?;
    Ok(())
}

fn execute_cmd(
    emulator: &mut CmdEmulator,
    runbox: &mut Runbox,
    input: &str,
    batch_name: Option<&str>,
    file_args: &[String],
) -> Result<CmdResult, Box<dyn std::error::Error>> {
    let result = if let Some(batch_name) = batch_name {
        emulator.emulate_batch_with_args(input, batch_name, file_args, runbox, 0)?
    } else {
        emulator.emulate(input, runbox, 0)?
    };
    runbox.drain_pending_processes()?;
    Ok(result)
}

fn print_cmd_result(result: &CmdResult) {
    for line in &result.stdout {
        println!("{line}");
    }
    for line in &result.stderr {
        eprintln!("{line}");
    }
}

fn print_trace(snapshot: &HostSnapshot, start: usize) {
    for event in snapshot.trace.iter().skip(start) {
        eprintln!(
            "[{:04}] {:?}/{:?}: {}",
            event.sequence, event.engine, event.kind, event.message
        );
    }
}

fn powershell_input_is_complete(source: &str) -> bool {
    let tokenization = tokenize(source);
    if tokenization
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("unterminated"))
    {
        return false;
    }

    let mut parentheses = 0_usize;
    let mut braces = 0_usize;
    let mut brackets = 0_usize;
    let mut last_significant = None;
    for token in tokenization.tokens {
        match token.kind {
            TokenKind::Delimiter(Delimiter::LeftParenthesis) => parentheses += 1,
            TokenKind::Delimiter(Delimiter::RightParenthesis) => {
                parentheses = parentheses.saturating_sub(1);
            }
            TokenKind::Delimiter(Delimiter::LeftBrace) => braces += 1,
            TokenKind::Delimiter(Delimiter::RightBrace) => {
                braces = braces.saturating_sub(1);
            }
            TokenKind::Delimiter(Delimiter::LeftBracket) => brackets += 1,
            TokenKind::Delimiter(Delimiter::RightBracket) => {
                brackets = brackets.saturating_sub(1);
            }
            _ => {}
        }
        if !matches!(
            token.kind,
            TokenKind::Whitespace | TokenKind::NewLine | TokenKind::Comment(_)
        ) {
            last_significant = Some((token.kind, token.text(source).to_owned()));
        }
    }

    let continued = last_significant.is_some_and(|(kind, text)| {
        kind == TokenKind::LineContinuation
            || (kind == TokenKind::Operator
                && matches!(text.as_str(), "|" | "&&" | "||" | "+" | "-" | "," | "="))
    });
    parentheses == 0 && braces == 0 && brackets == 0 && !continued
}

fn create_runbox(arguments: &Arguments) -> Runbox {
    let limits = AnalysisLimits {
        max_steps: arguments.max_steps,
        max_depth: arguments.max_depth,
        ..AnalysisLimits::default()
    };
    let mut runbox = Runbox::new(limits);
    if arguments.allow_network {
        runbox
            .host_mut()
            .set_network_policy(NetworkPolicy::public_http());
    }
    for variable in &arguments.environment {
        runbox
            .host_mut()
            .set_environment(&variable.name, &variable.value);
    }
    runbox
}

fn read_input(arguments: &Arguments) -> Result<(String, Option<String>), io::Error> {
    if let Some(path) = &arguments.file {
        return std::fs::read_to_string(path)
            .map(|input| (input, Some(path.to_string_lossy().into_owned())));
    }
    if let Some(command) = &arguments.command {
        return Ok((command.clone(), None));
    }
    if let Some(command) = &arguments.positional {
        return Ok((command.clone(), None));
    }
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok((input, Some("<stdin>".into())))
}

fn matches_ignore_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}
