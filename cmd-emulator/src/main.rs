use clap::Parser;
use cmd_emulator::CmdEmulator;
use emulator_core::{AnalysisLimits, Host, HostSnapshot, VirtualHost};
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
    name = "cmd-emulator",
    about = "Hermetically emulate Windows cmd commands and batch files"
)]
struct Arguments {
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

    /// Print the emulation trace to standard error.
    #[arg(long)]
    trace: bool,

    /// Override a virtual environment variable. May be specified repeatedly.
    #[arg(long = "env", value_name = "NAME=VALUE")]
    environment: Vec<EnvironmentOverride>,

    /// Maximum emulation steps.
    #[arg(long, default_value_t = 20_000)]
    max_steps: usize,

    /// Maximum recursive execution depth.
    #[arg(long, default_value_t = 12)]
    max_depth: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("cmd-emulator: {error}");
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
    let mut host = create_host(&arguments);
    let mut emulator = CmdEmulator::new().with_delayed_expansion(arguments.delayed_expansion);
    let result = if let Some(batch_name) = batch_name {
        emulator.emulate_batch_with_args(&input, &batch_name, &arguments.file_args, &mut host, 0)?
    } else {
        emulator.emulate(&input, &mut host, 0)?
    };
    print_result(&result);
    if arguments.trace {
        print_trace(&host.snapshot(), 0);
    }
    Ok(())
}

fn run_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    if io::stdin().is_terminal() {
        run_terminal_interactive(arguments)
    } else {
        run_stream_interactive(arguments)
    }
}

fn run_terminal_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let mut host = create_host(arguments);
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
                        &mut host,
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
    let mut host = create_host(arguments);
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
                &mut host,
                arguments.trace,
                &mut trace_index,
            );
        }
    }
    Ok(())
}

fn evaluate_interactive(
    command: &str,
    emulator: &mut CmdEmulator,
    host: &mut VirtualHost,
    trace: bool,
    trace_index: &mut usize,
) {
    match emulator.emulate(command, host, 0) {
        Ok(result) => print_result(&result),
        Err(error) => eprintln!("cmd-emulator: {error}"),
    }
    let snapshot = host.snapshot();
    if trace {
        print_trace(&snapshot, *trace_index);
    }
    *trace_index = snapshot.trace.len();
}

fn print_result(result: &cmd_emulator::CmdResult) {
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

fn create_host(arguments: &Arguments) -> VirtualHost {
    let limits = AnalysisLimits {
        max_steps: arguments.max_steps,
        max_depth: arguments.max_depth,
        ..AnalysisLimits::default()
    };
    let mut host = VirtualHost::new(limits);
    for variable in &arguments.environment {
        host.set_environment(&variable.name, &variable.value);
    }
    host
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustyline::history::{History, SearchDirection};

    #[test]
    fn line_editor_retains_history() {
        let mut editor = DefaultEditor::new().unwrap();
        editor.add_history_entry("echo one").unwrap();
        editor.add_history_entry("echo two").unwrap();
        let result = editor
            .history()
            .search("echo", 1, SearchDirection::Reverse)
            .unwrap()
            .unwrap();
        assert_eq!(result.entry.as_ref(), "echo two");
    }
}
