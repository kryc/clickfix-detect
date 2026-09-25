#![allow(clippy::pedantic)]

use clap::Parser;
use emulator_core::{AnalysisLimits, Host, HostSnapshot, NetworkPolicy, VirtualHost};
use rustyline::{error::ReadlineError, DefaultEditor};
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use windows_script_emulator::{ScriptHost, ScriptLanguage, ScriptResult, WindowsScriptEmulator};

#[derive(Debug, Clone)]
struct EnvironmentOverride {
    name: String,
    value: String,
}

impl FromStr for EnvironmentOverride {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, value) = value
            .split_once('=')
            .ok_or_else(|| "environment overrides must use NAME=VALUE".to_owned())?;
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
    name = "windows-script-emulator",
    about = "Hermetically emulate Windows scripts"
)]
struct Arguments {
    /// Script supplied directly as a positional argument.
    #[arg(value_name = "SCRIPT", conflicts_with_all = ["command", "file"])]
    positional: Option<String>,

    /// Script supplied as a command string.
    #[arg(short = 'c', long, value_name = "SCRIPT", conflicts_with_all = ["positional", "file"])]
    command: Option<String>,

    /// Read script input from a file.
    #[arg(short = 'f', long, value_name = "PATH", conflicts_with_all = ["positional", "command"])]
    file: Option<PathBuf>,

    /// Script language: jscript or vbscript. Inferred from a file extension when omitted.
    #[arg(long, value_name = "LANGUAGE")]
    language: Option<ScriptLanguage>,

    /// Script host: wscript, cscript, mshta, or scriptlet.
    #[arg(long, value_name = "HOST")]
    host: Option<ScriptHost>,

    /// Argument exposed through WScript.Arguments. May be repeated.
    #[arg(long = "arg", value_name = "VALUE")]
    script_arguments: Vec<String>,

    /// Print typed host events to standard error.
    #[arg(long)]
    trace: bool,

    /// Fixed synthetic response body returned for every web request.
    #[arg(long, value_name = "TEXT")]
    web_response: Option<String>,

    /// Allow real outbound public HTTP(S) requests with SSRF and size limits.
    #[arg(long)]
    allow_network: bool,

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

fn main() {
    if let Err(error) = run() {
        eprintln!("windows-script-emulator: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let language = arguments
        .language
        .or_else(|| arguments.file.as_deref().and_then(language_for_path))
        .unwrap_or(ScriptLanguage::JScript);
    let host_kind = arguments
        .host
        .or_else(|| arguments.file.as_deref().and_then(host_for_path))
        .unwrap_or(ScriptHost::WScript);
    if arguments.positional.is_none()
        && arguments.command.is_none()
        && arguments.file.is_none()
        && io::stdin().is_terminal()
    {
        return interactive(&arguments, language, host_kind);
    }
    let source = read_input(&arguments)?;
    let mut host = create_host(&arguments);
    let mut emulator = WindowsScriptEmulator::new();
    let result = emulator.emulate(
        &source,
        language,
        host_kind,
        &arguments.script_arguments,
        &mut host,
        0,
    )?;
    print_result(&result);
    if arguments.trace {
        print_trace(&host.snapshot(), 0);
    }
    Ok(())
}

fn interactive(
    arguments: &Arguments,
    language: ScriptLanguage,
    host_kind: ScriptHost,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut editor = DefaultEditor::new()?;
    let mut emulator = WindowsScriptEmulator::new();
    let mut host = create_host(arguments);
    let mut trace_index = 0;
    loop {
        let prompt = match language {
            ScriptLanguage::JScript => "js> ",
            ScriptLanguage::VBScript => "vbs> ",
        };
        match editor.readline(prompt) {
            Ok(line) => {
                let line = line.trim();
                if line.eq_ignore_ascii_case("exit") || line.eq_ignore_ascii_case("quit") {
                    break;
                }
                if line.is_empty() {
                    continue;
                }
                editor.add_history_entry(line)?;
                match emulator.emulate(
                    line,
                    language,
                    host_kind,
                    &arguments.script_arguments,
                    &mut host,
                    0,
                ) {
                    Ok(result) => print_result(&result),
                    Err(error) => eprintln!("windows-script-emulator: {error}"),
                }
                let snapshot = host.snapshot();
                if arguments.trace {
                    print_trace(&snapshot, trace_index);
                }
                trace_index = snapshot.trace.len();
            }
            Err(ReadlineError::Interrupted) => {}
            Err(ReadlineError::Eof) => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn create_host(arguments: &Arguments) -> VirtualHost {
    let mut host = VirtualHost::new(AnalysisLimits {
        max_steps: arguments.max_steps,
        max_depth: arguments.max_depth,
        ..AnalysisLimits::default()
    });
    if arguments.allow_network {
        host.set_network_policy(NetworkPolicy::public_http());
    }
    if let Some(response) = &arguments.web_response {
        host.set_default_network_response_text(response);
    }
    for variable in &arguments.environment {
        host.set_environment(&variable.name, &variable.value);
    }
    host
}

fn read_input(arguments: &Arguments) -> Result<String, io::Error> {
    if let Some(path) = &arguments.file {
        return std::fs::read_to_string(path);
    }
    if let Some(command) = &arguments.command {
        return Ok(command.clone());
    }
    if let Some(command) = &arguments.positional {
        return Ok(command.clone());
    }
    let mut source = String::new();
    io::stdin().read_to_string(&mut source)?;
    Ok(source)
}

fn print_result(result: &ScriptResult) {
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

fn language_for_path(path: &Path) -> Option<ScriptLanguage> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase()
        .as_str()
    {
        "vbs" | "vbe" => Some(ScriptLanguage::VBScript),
        "js" | "jse" | "hta" | "sct" => Some(ScriptLanguage::JScript),
        _ => None,
    }
}

fn host_for_path(path: &Path) -> Option<ScriptHost> {
    match path
        .extension()
        .and_then(|extension| extension.to_str())?
        .to_ascii_lowercase()
        .as_str()
    {
        "hta" => Some(ScriptHost::Mshta),
        "sct" => Some(ScriptHost::Scriptlet),
        _ => None,
    }
}
