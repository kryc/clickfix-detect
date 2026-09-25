use clap::Parser;
use emulator_core::{AnalysisLimits, EventKind, Host, HostSnapshot, NetworkPolicy, VirtualHost};
use powershell_emulator::{
    tokenizer::{tokenize, Delimiter, TokenKind},
    PowerShellEmulator, Value,
};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::collections::BTreeMap;
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
    name = "powershell-emulator",
    about = "Hermetically emulate PowerShell scripts and print captured output"
)]
struct Arguments {
    /// Script supplied directly as a positional argument.
    #[arg(value_name = "SCRIPT", conflicts_with_all = ["command", "file"])]
    script: Option<String>,

    /// Script supplied as a command string.
    #[arg(short = 'c', long, value_name = "SCRIPT", conflicts_with_all = ["script", "file"])]
    command: Option<String>,

    /// Read the script from a file. File access occurs before emulation.
    #[arg(short = 'f', long, value_name = "PATH", conflicts_with_all = ["script", "command"])]
    file: Option<PathBuf>,

    /// Print the emulation trace to standard error.
    #[arg(long)]
    trace: bool,

    /// Maximum emulation steps.
    #[arg(long, default_value_t = 20_000)]
    max_steps: usize,

    /// Maximum recursive execution depth.
    #[arg(long, default_value_t = 12)]
    max_depth: usize,

    /// Fixed text returned by every blocked web request without an exact fixture.
    #[arg(long, value_name = "TEXT", default_value = "")]
    web_response: String,

    /// Allow real outbound public HTTP(S) requests with SSRF and size limits.
    #[arg(long)]
    allow_network: bool,

    /// Override a virtual environment variable. May be specified repeatedly.
    #[arg(long = "env", value_name = "NAME=VALUE")]
    environment: Vec<EnvironmentOverride>,

    /// Force interactive mode, including when standard input is piped.
    #[arg(
        short = 'i',
        long,
        conflicts_with_all = ["script", "command", "file"]
    )]
    interactive: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("powershell-emulator: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    if arguments.interactive
        || (arguments.script.is_none()
            && arguments.command.is_none()
            && arguments.file.is_none()
            && io::stdin().is_terminal())
    {
        return run_interactive(&arguments);
    }

    let script = read_script(&arguments)?;
    let mut host = create_host(&arguments);
    let mut emulator = PowerShellEmulator::new();
    let result = emulator.emulate(&script, &mut host, 0)?;

    for line in result.stdout {
        println!("{line}");
    }

    let snapshot = host.snapshot();
    print_command_errors(&snapshot, 0);
    if arguments.trace {
        for event in snapshot.trace {
            eprintln!(
                "[{:04}] {:?}/{:?}: {}",
                event.sequence, event.engine, event.kind, event.message
            );
        }
    }
    Ok(())
}

fn run_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let terminal = io::stdin().is_terminal();
    if terminal {
        run_terminal_interactive(arguments)
    } else {
        run_stream_interactive(arguments)
    }
}

fn run_terminal_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let mut host = create_host(arguments);
    let mut emulator = PowerShellEmulator::new();
    let mut editor = DefaultEditor::new()?;
    let mut buffer = String::new();
    let mut trace_index = 0;

    loop {
        let prompt = if buffer.is_empty() { "PS> " } else { ">> " };
        match editor.readline(prompt) {
            Ok(line) => match accept_interactive_line(&line, &mut buffer) {
                ReplAction::Continue => {}
                ReplAction::Help => {
                    println!("Enter PowerShell code. Use exit, quit, :exit, or Ctrl-D to leave.");
                }
                ReplAction::Exit => break,
                ReplAction::Evaluate => {
                    let entry = buffer.trim_end().to_string();
                    if !entry.is_empty() {
                        editor.add_history_entry(entry)?;
                    }
                    evaluate_interactive(
                        &buffer,
                        &mut emulator,
                        &mut host,
                        arguments.trace,
                        &mut trace_index,
                    );
                    buffer.clear();
                }
            },
            Err(ReadlineError::Interrupted) => {
                buffer.clear();
            }
            Err(ReadlineError::Eof) => {
                if !buffer.trim().is_empty() {
                    evaluate_interactive(
                        &buffer,
                        &mut emulator,
                        &mut host,
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

fn run_stream_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut host = create_host(arguments);
    let mut emulator = PowerShellEmulator::new();
    let mut buffer = String::new();
    let mut trace_index = 0;

    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            if !buffer.trim().is_empty() {
                evaluate_interactive(
                    &buffer,
                    &mut emulator,
                    &mut host,
                    arguments.trace,
                    &mut trace_index,
                );
            }
            break;
        }
        match accept_interactive_line(&line, &mut buffer) {
            ReplAction::Continue => {}
            ReplAction::Help => {
                println!("Enter PowerShell code. Use exit, quit, :exit, or Ctrl-D to leave.");
            }
            ReplAction::Exit => break,
            ReplAction::Evaluate => {
                evaluate_interactive(
                    &buffer,
                    &mut emulator,
                    &mut host,
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
enum ReplAction {
    Continue,
    Help,
    Exit,
    Evaluate,
}

fn accept_interactive_line(line: &str, buffer: &mut String) -> ReplAction {
    let trimmed = line.trim();
    if buffer.is_empty() && matches!(trimmed, "exit" | "quit" | ":exit" | ":quit") {
        return ReplAction::Exit;
    }
    if buffer.is_empty() && trimmed == ":help" {
        return ReplAction::Help;
    }
    buffer.push_str(line);
    if !line.ends_with('\n') {
        buffer.push('\n');
    }
    if input_is_complete(buffer) {
        ReplAction::Evaluate
    } else {
        ReplAction::Continue
    }
}

fn evaluate_interactive(
    script: &str,
    emulator: &mut PowerShellEmulator,
    host: &mut VirtualHost,
    trace: bool,
    trace_index: &mut usize,
) {
    let result = emulator.emulate(script, host, 0);
    let stdout = emulator.drain_stdout();
    let formatted = result
        .as_ref()
        .ok()
        .and_then(|result| result.last_value.as_ref())
        .and_then(format_interactive_value);
    if let Some(formatted) = formatted {
        println!("{formatted}");
    } else {
        for line in stdout {
            println!("{line}");
        }
    }
    if let Err(error) = result {
        eprintln!("powershell-emulator: {error}");
    }
    let snapshot = host.snapshot();
    print_command_errors(&snapshot, *trace_index);
    if trace {
        print_new_trace(&snapshot, trace_index);
    } else {
        *trace_index = snapshot.trace.len();
    }
}

fn format_interactive_value(value: &Value) -> Option<String> {
    let values = match value {
        Value::Array(values) if !values.is_empty() => values.as_slice(),
        Value::Map(_) => std::slice::from_ref(value),
        _ => return None,
    };
    if !values.iter().all(is_filesystem_info) {
        return None;
    }

    let mut groups = BTreeMap::<String, Vec<&Value>>::new();
    for value in values {
        let directory = member(value, "DirectoryName")?.as_string();
        groups.entry(directory).or_default().push(value);
    }

    let mut output = Vec::new();
    for (directory, values) in groups {
        output.push(format!("    Directory: {directory}"));
        output.push(String::new());
        output.push("Mode                 LastWriteTime         Length Name".into());
        output.push("----                 -------------         ------ ----".into());
        for value in values {
            let directory = member(value, "PSIsContainer").is_some_and(Value::truthy);
            let mode = if directory { "d-----" } else { "-a----" };
            let length = if directory {
                String::new()
            } else {
                member(value, "Length").map_or_else(String::new, Value::as_string)
            };
            let name = member(value, "Name").map_or_else(String::new, Value::as_string);
            output.push(format!(
                "{mode:<20} 01/01/2024     00:00 {length:>14} {name}"
            ));
        }
        output.push(String::new());
    }
    while output.last().is_some_and(String::is_empty) {
        output.pop();
    }
    Some(output.join("\n"))
}

fn is_filesystem_info(value: &Value) -> bool {
    member(value, "__type")
        .is_some_and(|value| value.as_string().eq_ignore_ascii_case("FileSystemInfo"))
}

fn member<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    let Value::Map(values) = value else {
        return None;
    };
    values
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn print_command_errors(snapshot: &HostSnapshot, event_index: usize) {
    for event in snapshot.trace.iter().skip(event_index) {
        if event.kind != EventKind::Unsupported {
            continue;
        }
        let Some(command) = event
            .message
            .strip_prefix("unsupported PowerShell command: ")
        else {
            continue;
        };
        eprintln!("{command}: The term '{command}' is not recognized as a PowerShell command.");
    }
}

fn print_new_trace(snapshot: &HostSnapshot, trace_index: &mut usize) {
    for event in snapshot.trace.iter().skip(*trace_index) {
        eprintln!(
            "[{:04}] {:?}/{:?}: {}",
            event.sequence, event.engine, event.kind, event.message
        );
    }
    *trace_index = snapshot.trace.len();
}

fn input_is_complete(source: &str) -> bool {
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
            last_significant = Some((token.kind, token.text(source).to_string()));
        }
    }

    let continued = last_significant.is_some_and(|(kind, text)| {
        kind == TokenKind::LineContinuation
            || (kind == TokenKind::Operator
                && matches!(text.as_str(), "|" | "&&" | "||" | "+" | "-" | "," | "="))
    });
    parentheses == 0 && braces == 0 && brackets == 0 && !continued
}

fn create_host(arguments: &Arguments) -> VirtualHost {
    let limits = AnalysisLimits {
        max_steps: arguments.max_steps,
        max_depth: arguments.max_depth,
        ..AnalysisLimits::default()
    };
    let mut host = VirtualHost::new(limits);
    host.set_default_network_response_text(arguments.web_response.clone());
    if arguments.allow_network {
        host.set_network_policy(NetworkPolicy::public_http());
    }
    for variable in &arguments.environment {
        host.set_environment(&variable.name, &variable.value);
    }
    host
}

fn read_script(arguments: &Arguments) -> Result<String, io::Error> {
    if let Some(path) = &arguments.file {
        return std::fs::read_to_string(path);
    }
    if let Some(command) = &arguments.command {
        return Ok(command.clone());
    }
    if let Some(script) = &arguments.script {
        return Ok(script.clone());
    }

    let mut script = String::new();
    io::stdin().read_to_string(&mut script)?;
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyline::history::{History, SearchDirection};

    #[test]
    fn line_editor_retains_command_history() {
        let mut editor = DefaultEditor::new().unwrap();
        editor.add_history_entry("$x = 1").unwrap();
        editor.add_history_entry("Write-Output $x").unwrap();

        assert_eq!(editor.history().len(), 2);
        assert_eq!(
            editor
                .history()
                .get(0, SearchDirection::Forward)
                .unwrap()
                .unwrap()
                .entry,
            "$x = 1"
        );
        assert_eq!(
            editor
                .history()
                .get(1, SearchDirection::Reverse)
                .unwrap()
                .unwrap()
                .entry,
            "Write-Output $x"
        );
    }

    #[test]
    fn multiline_input_is_added_as_one_repl_entry() {
        let mut buffer = String::new();
        assert_eq!(
            accept_interactive_line("function Test {\n", &mut buffer),
            ReplAction::Continue
        );
        assert_eq!(
            accept_interactive_line("Write-Output safe\n", &mut buffer),
            ReplAction::Continue
        );
        assert_eq!(
            accept_interactive_line("}\n", &mut buffer),
            ReplAction::Evaluate
        );
        assert!(buffer.contains("function Test"));
        assert!(buffer.contains("Write-Output safe"));
    }

    #[test]
    fn filesystem_values_use_powershell_table_formatting() {
        let value = Value::Array(vec![
            Value::Map(
                [
                    ("__type".into(), Value::String("FileSystemInfo".into())),
                    (
                        "DirectoryName".into(),
                        Value::String(r"c:\users\analysis".into()),
                    ),
                    ("PSIsContainer".into(), Value::Bool(true)),
                    ("Length".into(), Value::Number(0)),
                    ("Name".into(), Value::String("demo".into())),
                ]
                .into_iter()
                .collect(),
            ),
            Value::Map(
                [
                    ("__type".into(), Value::String("FileSystemInfo".into())),
                    (
                        "DirectoryName".into(),
                        Value::String(r"c:\users\analysis".into()),
                    ),
                    ("PSIsContainer".into(), Value::Bool(false)),
                    ("Length".into(), Value::Number(4)),
                    ("Name".into(), Value::String("note.txt".into())),
                ]
                .into_iter()
                .collect(),
            ),
        ]);

        let output = format_interactive_value(&value).unwrap();
        assert!(output.contains("Directory: c:\\users\\analysis"));
        assert!(output.contains("d-----"));
        assert!(output.contains("-a----"));
        assert!(output.contains("4 note.txt"));
        assert!(!output.contains("__type"));
    }
}
