use bash_emulator::BashEmulator;
use clap::{Parser, ValueEnum};
use emulator_core::{AnalysisLimits, Host, HostPlatform, HostSnapshot, VirtualHost};
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
        if name.is_empty() {
            return Err("environment variable name must not be empty".into());
        }
        Ok(Self {
            name: name.into(),
            value: value.into(),
        })
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "bash-emulator",
    about = "Hermetically emulate Bash scripts on a virtual macOS host"
)]
struct Arguments {
    /// Script supplied directly as a positional argument.
    #[arg(value_name = "SCRIPT", conflicts_with_all = ["command", "file"])]
    positional: Option<String>,

    /// Script supplied as a command string.
    #[arg(short = 'c', long, value_name = "SCRIPT", conflicts_with_all = ["positional", "file"])]
    command: Option<String>,

    /// Read script input from a file. File access occurs before emulation.
    #[arg(short = 'f', long, value_name = "PATH", conflicts_with_all = ["positional", "command"])]
    file: Option<PathBuf>,

    /// Positional script argument. May be repeated.
    #[arg(long = "arg", value_name = "VALUE")]
    file_args: Vec<String>,

    /// Force interactive mode, including when standard input is piped.
    #[arg(
        short = 'i',
        long,
        conflicts_with_all = ["positional", "command", "file"]
    )]
    interactive: bool,

    /// Print the emulation trace to standard error.
    #[arg(long)]
    trace: bool,

    /// Select the deterministic POSIX host environment.
    #[arg(long, value_enum, default_value = "macos")]
    platform: ShellPlatform,

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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ShellPlatform {
    Macos,
    Linux,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("bash-emulator: {error}");
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
    let (source, script_name) = read_input(&arguments)?;
    let mut host = create_host(&arguments);
    let mut emulator = BashEmulator::new();
    let result =
        emulator.emulate_with_args(&source, &script_name, &arguments.file_args, &mut host, 0)?;
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
    let mut emulator = BashEmulator::new();
    let mut editor = DefaultEditor::new()?;
    let mut trace_index = 0;
    loop {
        let host_name = match host.platform() {
            HostPlatform::MacOs => "mac",
            HostPlatform::Linux => "linux",
            HostPlatform::Windows => "windows",
        };
        let prompt = format!("analysis@{host_name}:{}$ ", emulator.current_directory());
        match editor.readline(&prompt) {
            Ok(line) => {
                let trimmed = line.trim();
                if matches!(trimmed, "exit" | "quit" | ":exit" | ":quit") {
                    break;
                }
                if !trimmed.is_empty() {
                    editor.add_history_entry(trimmed)?;
                    evaluate(
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
    let mut emulator = BashEmulator::new();
    let mut trace_index = 0;
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim();
        if matches!(trimmed, "exit" | "quit" | ":exit" | ":quit") {
            break;
        }
        if !trimmed.is_empty() {
            evaluate(
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

fn evaluate(
    source: &str,
    emulator: &mut BashEmulator,
    host: &mut VirtualHost,
    trace: bool,
    trace_index: &mut usize,
) {
    match emulator.emulate(source, host, 0) {
        Ok(result) => print_result(&result),
        Err(error) => eprintln!("bash-emulator: {error}"),
    }
    let snapshot = host.snapshot();
    if trace {
        print_trace(&snapshot, *trace_index);
    }
    *trace_index = snapshot.trace.len();
}

fn create_host(arguments: &Arguments) -> VirtualHost {
    let limits = AnalysisLimits {
        max_steps: arguments.max_steps,
        max_depth: arguments.max_depth,
        ..AnalysisLimits::default()
    };
    let mut host = match arguments.platform {
        ShellPlatform::Macos => VirtualHost::macos(limits),
        ShellPlatform::Linux => VirtualHost::linux(limits),
    };
    for variable in &arguments.environment {
        host.set_environment(&variable.name, &variable.value);
    }
    host
}

fn read_input(arguments: &Arguments) -> Result<(String, String), io::Error> {
    if let Some(path) = &arguments.file {
        return std::fs::read_to_string(path)
            .map(|source| (source, path.to_string_lossy().into_owned()));
    }
    if let Some(command) = &arguments.command {
        return Ok((command.clone(), "bash".into()));
    }
    if let Some(source) = &arguments.positional {
        return Ok((source.clone(), "bash".into()));
    }
    let mut source = String::new();
    io::stdin().read_to_string(&mut source)?;
    Ok((source, "<stdin>".into()))
}

fn print_result(result: &bash_emulator::BashResult) {
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
