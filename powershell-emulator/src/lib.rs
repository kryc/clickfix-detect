mod archives;
mod bits;
mod builtins;
mod com;
mod content;
mod dotnet;
mod engine_commands;
mod engine_control;
mod engine_expression;
mod engine_operators;
mod engine_support;
mod parser;
mod pipeline;
mod provider_paths;
mod providers;
mod recon;
mod redirection;
mod runtime;
mod security_cmdlets;
mod syntax;
mod transforms;
mod value;

pub mod tokenizer;

use emulator_core::{
    sha256_hex, ArtifactKind, Engine, EventKind, Host, HostError, NetworkIntent, NetworkRequest,
    ProcessIntent, TraceEvent,
};
use parser::ParsedSource;
use regex::Regex;
use runtime::{FlowControl, FunctionDefinition};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::LazyLock;
use syntax::{
    extract_delimited, find_switch, find_top_level_binary, find_word_case_insensitive, is_quoted,
    is_variable, looks_like_script, named_or_positional, normalize_variable, parse_instance_call,
    parse_member_access, parse_named_block, parse_number, parse_redirections, parse_static_call,
    parse_static_member_access, quote_argument, split_assignment, split_compound_assignment,
    split_increment, split_index_expression, split_key_value, split_labeled_blocks,
    split_powershell_words, split_statements, split_top_level, split_windows_command_line,
    starts_word, strip_balanced_outer, strip_comments, strip_prefix_case_insensitive,
    trim_url_punctuation, NumberLiteral,
};
use thiserror::Error;
use tokenizer::{StringKind, TokenKind};
use transforms::{
    bytes_to_value, decode_ascii, decode_base64, decode_candidate, decode_utf16_be,
    decode_utf16_le, decode_utf8, encode_utf16_le, hex_decode, percent_decode, unescape_powershell,
};

pub use value::Value;

static URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\bhttps?://[^\s"'<>`]+"#).expect("valid URL regex"));
static VARIABLE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\$(?:\{([^}]+)\}|((?:[$?^]|(?:[\p{L}\p{Nd}_?]+:)?[\p{L}\p{Nd}_?]+)))")
        .expect("valid variable regex")
});
static XML_ELEMENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?s)<([A-Za-z_][A-Za-z0-9_.:-]*)[^>]*>(.*?)</[A-Za-z_][A-Za-z0-9_.:-]*>")
        .expect("valid XML element regex")
});

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PowerShellResult {
    pub stdout: Vec<String>,
    pub last_value: Option<Value>,
}

#[derive(Debug, Error)]
pub enum PowerShellError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("PowerShell parsing failed: {0}")]
    Parser(String),
    #[error("PowerShell expression could not be evaluated: {0}")]
    Evaluation(String),
}

#[derive(Debug, Clone, Default)]
pub struct PowerShellEmulator {
    variables: HashMap<String, Value>,
    functions: HashMap<String, FunctionDefinition>,
    aliases: HashMap<String, String>,
    directories: BTreeMap<String, String>,
    bits_jobs: BTreeMap<String, bits::BitsJob>,
    bits_job_counter: usize,
    current_location: String,
    location_stack: Vec<String>,
    temporary_file_counter: usize,
    web_sessions: HashMap<String, BTreeMap<String, Value>>,
    stdout: Vec<String>,
    error_output: Vec<String>,
    emitted_values: Vec<Value>,
    output_capture_depth: usize,
    flow: FlowControl,
    random_state: u64,
}

impl PowerShellEmulator {
    #[must_use]
    pub fn new() -> Self {
        let mut emulator = Self::default();
        emulator.variables.insert(
            "psversiontable".into(),
            Value::Map(
                [
                    ("PSVersion".into(), Value::String("5.1".into())),
                    ("PSEdition".into(), Value::String("Desktop".into())),
                ]
                .into_iter()
                .collect(),
            ),
        );
        emulator
            .variables
            .insert("pid".into(), Value::Number(4_242));
        emulator.variables.insert(
            "pshome".into(),
            Value::String(r"C:\Windows\System32\WindowsPowerShell\v1.0".into()),
        );
        emulator
            .variables
            .insert("pwd".into(), Value::String(r"C:\Users\analysis".into()));
        emulator.variables.insert(
            "profile".into(),
            Value::String(
                r"C:\Users\analysis\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"
                    .into(),
            ),
        );
        emulator.aliases.extend(
            [
                ("echo", "write-output"),
                ("iex", "invoke-expression"),
                ("iwr", "invoke-webrequest"),
                ("irm", "invoke-restmethod"),
                ("curl", "invoke-webrequest"),
                ("wget", "invoke-webrequest"),
                ("gc", "get-content"),
                ("cat", "get-content"),
                ("type", "get-content"),
                ("%", "foreach-object"),
                ("?", "where-object"),
                ("saps", "start-process"),
                ("gi", "get-item"),
                ("si", "set-item"),
                ("ri", "remove-item"),
                ("gci", "get-childitem"),
                ("gp", "get-itemproperty"),
                ("sp", "set-itemproperty"),
                ("rp", "remove-itemproperty"),
                ("ni", "new-item"),
                ("md", "mkdir"),
                ("mkdir", "mkdir"),
                ("ii", "invoke-item"),
                ("clc", "clear-content"),
                ("gl", "get-location"),
                ("sl", "set-location"),
            ]
            .into_iter()
            .map(|(alias, command)| (alias.into(), command.into())),
        );
        emulator.current_location = r"C:\Users\analysis".into();
        for directory in [
            r"C:\",
            r"C:\Users",
            r"C:\Users\analysis",
            r"C:\Users\analysis\AppData",
            r"C:\Users\analysis\AppData\Local",
            r"C:\Users\analysis\AppData\Local\Temp",
        ] {
            emulator.directories.insert(
                emulator_core::normalize_windows_path(directory),
                directory.into(),
            );
        }
        emulator.random_state = 0x434c_4943_4b46_4958;
        emulator
    }

    pub fn drain_stdout(&mut self) -> Vec<String> {
        std::mem::take(&mut self.stdout)
    }

    /// Parse and emulate a `PowerShell` script against the supplied virtual host.
    ///
    /// # Errors
    ///
    /// Returns an error when lexical validation fails, an expression cannot be
    /// evaluated, or the virtual host rejects an operation because a resource
    /// limit was reached.
    pub fn emulate(
        &mut self,
        script: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<PowerShellResult, PowerShellError> {
        self.flow = FlowControl::None;
        self.emitted_values.clear();
        host.consume_step(Engine::PowerShell, depth, "parsing PowerShell input")?;
        let parsed = ParsedSource::parse(script)
            .map_err(|diagnostic| PowerShellError::Parser(diagnostic.to_string()))?;
        host.emit(
            TraceEvent::new(
                depth,
                Engine::PowerShell,
                EventKind::Parse,
                "parsed PowerShell input with span tokenizer",
            )
            .with_data("bytes", script.len().to_string())
            .with_data("tokens", parsed.token_count().to_string()),
        );
        for diagnostic in parsed.diagnostics() {
            host.unsupported(
                Engine::PowerShell,
                depth,
                &format!("PowerShell structural diagnostic: {diagnostic}"),
            );
        }
        let last_value = self.execute_script(&parsed, parsed.source(), host, depth)?;
        Ok(PowerShellResult {
            stdout: self.stdout.clone(),
            last_value,
        })
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
fn numeric_binary(left: &Value, right: &Value, operation: impl Fn(f64, f64) -> f64) -> Value {
    let integer_inputs = matches!(left, Value::Number(_)) && matches!(right, Value::Number(_));
    let Some(left) = left.as_f64() else {
        return Value::Null;
    };
    let Some(right) = right.as_f64() else {
        return Value::Null;
    };
    let result = operation(left, right);
    if integer_inputs
        && result.is_finite()
        && result.fract() == 0.0
        && result <= i64::MAX as f64
        && result >= i64::MIN as f64
    {
        Value::Number(result as i64)
    } else {
        Value::Float(result)
    }
}

fn bitwise_binary(left: &Value, right: &Value, operation: impl Fn(i64, i64) -> i64) -> Value {
    match (left.as_i64(), right.as_i64()) {
        (Some(left), Some(right)) => Value::Number(operation(left, right)),
        _ => Value::Null,
    }
}

fn bitwise_shift(left: &Value, right: &Value, left_shift: bool) -> Value {
    let (Some(left), Some(right)) = (left.as_i64(), right.as_i64()) else {
        return Value::Null;
    };
    let shift = u32::try_from(right.clamp(0, 63)).unwrap_or_default();
    Value::Number(if left_shift {
        left.wrapping_shl(shift)
    } else {
        left.wrapping_shr(shift)
    })
}

fn values_equal(left: &Value, right: &Value, case_sensitive: bool) -> bool {
    if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
        return (left - right).abs() < f64::EPSILON;
    }
    let left = left.as_string();
    let right = right.as_string();
    if case_sensitive {
        left == right
    } else {
        left.eq_ignore_ascii_case(&right)
    }
}

fn compare_values(
    left: &Value,
    right: &Value,
    predicate: impl Fn(std::cmp::Ordering) -> bool,
) -> Value {
    let ordering = if let (Some(left), Some(right)) = (left.as_f64(), right.as_f64()) {
        left.partial_cmp(&right)
    } else {
        Some(
            left.as_string()
                .to_ascii_lowercase()
                .cmp(&right.as_string().to_ascii_lowercase()),
        )
    };
    Value::Bool(ordering.is_some_and(predicate))
}

fn wildcard_match(input: &str, pattern: &str, case_sensitive: bool) -> bool {
    let mut regex = String::from("^");
    for character in pattern.chars() {
        match character {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            other => regex.push_str(&regex::escape(&other.to_string())),
        }
    }
    regex.push('$');
    let mut builder = regex::RegexBuilder::new(&regex);
    builder.case_insensitive(!case_sensitive);
    builder.build().is_ok_and(|regex| regex.is_match(input))
}

fn object_map(type_name: &str, data: Value) -> Value {
    Value::Map(
        [
            ("__type".into(), Value::String(type_name.into())),
            ("data".into(), data),
        ]
        .into_iter()
        .collect(),
    )
}

fn merge_branch_variables(
    baseline: &HashMap<String, Value>,
    then_branch: &HashMap<String, Value>,
    else_branch: &HashMap<String, Value>,
) -> HashMap<String, Value> {
    let mut merged = baseline.clone();
    let keys = then_branch
        .keys()
        .chain(else_branch.keys())
        .cloned()
        .collect::<HashSet<_>>();
    for key in keys {
        let then_value = then_branch.get(&key);
        let else_value = else_branch.get(&key);
        match (then_value, else_value) {
            (Some(then_value), Some(else_value)) if then_value == else_value => {
                merged.insert(key, then_value.clone());
            }
            (None, None) => {}
            _ => {
                merged.insert(key, Value::Object("UnknownBranchValue".into()));
            }
        }
    }
    merged
}

fn parse_simple_xml(input: &str) -> Value {
    let values = XML_ELEMENT_RE
        .captures_iter(input)
        .filter_map(|captures| {
            let name = captures.get(1)?.as_str().to_string();
            let body = captures.get(2)?.as_str();
            let value = if XML_ELEMENT_RE.is_match(body) {
                parse_simple_xml(body)
            } else {
                Value::String(body.into())
            };
            Some((name, value))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    if values.is_empty() {
        Value::String(input.into())
    } else {
        Value::Map(values)
    }
}

fn index_value(base: Value, index: Value) -> Value {
    let indexes = match index {
        Value::Array(values) => values,
        other => vec![other],
    };
    if let Value::Map(values) = &base {
        let selected = indexes
            .iter()
            .filter_map(|index| {
                let key = index.as_string();
                values
                    .iter()
                    .find(|(candidate, _)| candidate.eq_ignore_ascii_case(&key))
                    .map(|(_, value)| value.clone())
            })
            .collect::<Vec<_>>();
        return if selected.len() == 1 {
            selected.into_iter().next().unwrap_or(Value::Null)
        } else {
            Value::Array(selected)
        };
    }
    let values = match base {
        Value::String(text) => text
            .chars()
            .map(|character| Value::String(character.to_string()))
            .collect::<Vec<_>>(),
        Value::Bytes(bytes) => bytes
            .into_iter()
            .map(|byte| Value::Number(i64::from(byte)))
            .collect(),
        Value::Array(values) => values,
        other => vec![other],
    };
    let selected = indexes
        .iter()
        .filter_map(|index| index.as_string().parse::<isize>().ok())
        .filter_map(|index| {
            let actual = if index < 0 {
                isize::try_from(values.len()).ok()?.checked_add(index)?
            } else {
                index
            };
            usize::try_from(actual)
                .ok()
                .and_then(|actual| values.get(actual).cloned())
        })
        .collect::<Vec<_>>();
    if selected.len() == 1 {
        selected.into_iter().next().unwrap_or(Value::Null)
    } else {
        Value::Array(selected)
    }
}

fn assign_index(target: &mut Value, index: &Value, value: &Value) {
    let indexes = match index {
        Value::Array(values) => values,
        value => std::slice::from_ref(value),
    };
    match target {
        Value::Array(values) => {
            for index in indexes {
                let Some(index) = index.as_i64() else {
                    continue;
                };
                let actual = if index < 0 {
                    i64::try_from(values.len())
                        .ok()
                        .and_then(|length| length.checked_add(index))
                } else {
                    Some(index)
                };
                if let Some(actual) = actual.and_then(|value| usize::try_from(value).ok()) {
                    if let Some(slot) = values.get_mut(actual) {
                        *slot = value.clone();
                    }
                }
            }
        }
        Value::Bytes(values) => {
            let Some(byte) = value.as_i64().and_then(|value| u8::try_from(value).ok()) else {
                return;
            };
            for index in indexes {
                if let Some(index) = index.as_i64().and_then(|value| usize::try_from(value).ok()) {
                    if let Some(slot) = values.get_mut(index) {
                        *slot = byte;
                    }
                }
            }
        }
        Value::Map(values) => {
            for index in indexes {
                values.insert(index.as_string(), value.clone());
            }
        }
        _ => {}
    }
}

fn limited(input: &str, max: usize) -> String {
    if input.len() <= max {
        input.into()
    } else {
        format!("{}...", &input[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use emulator_core::{AnalysisLimits, EventKind, VirtualHost};

    #[test]
    fn decodes_and_recursively_emulates_invoke_expression() {
        let payload = base64::engine::general_purpose::STANDARD
            .encode("Invoke-WebRequest 'https://example.invalid/a'");
        let script = format!(
            "$x = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}')); iex $x"
        );
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator.emulate(&script, &mut host, 0).unwrap();
        let snapshot = host.snapshot();

        assert!(snapshot
            .trace
            .iter()
            .any(|event| event.kind == EventKind::NetworkIntent));
        assert!(snapshot.artifacts.iter().any(|artifact| {
            artifact
                .text
                .as_deref()
                .is_some_and(|text| text.contains("Invoke-WebRequest"))
        }));
    }

    #[test]
    fn writes_only_to_the_virtual_filesystem() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator
            .emulate(
                r#"Set-Content -Path "C:\Temp\proof.txt" -Value "safe""#,
                &mut host,
                0,
            )
            .unwrap();

        let snapshot = host.snapshot();
        assert_eq!(snapshot.virtual_files.len(), 1);
        assert_eq!(snapshot.virtual_files[0].text.as_deref(), Some("safe\r\n"));
    }

    #[test]
    fn tracks_blocked_process_launches() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator
            .emulate(
                r#"Start-Process "cmd.exe" -ArgumentList "/c echo safe""#,
                &mut host,
                0,
            )
            .unwrap();

        assert_eq!(host.take_process_intents().len(), 1);
    }

    #[test]
    fn preserves_native_arguments_after_stop_parsing_token() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator
            .emulate("cmd.exe --% /c echo %PATH% & literal", &mut host, 0)
            .unwrap();

        let intents = host.take_process_intents();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0].args, ["/c echo %PATH% & literal"]);
    }

    #[test]
    fn removes_end_of_parameters_marker_and_preserves_dash_arguments() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator
            .emulate("Write-Output -- -InputObject", &mut host, 0)
            .unwrap();

        assert_eq!(emulator.drain_stdout(), ["-InputObject"]);
    }

    #[test]
    fn tokenizer_based_statement_splitting_keeps_here_strings_atomic() {
        let script =
            "$x = @\"\nline one; still data\nline two\n\"@\nWrite-Output $x\nWrite-Output 'a;b'";
        let parser = ParsedSource::parse(script).expect("valid source");
        let statements = split_statements(&parser, script)
            .into_iter()
            .filter(|statement| !statement.trim().is_empty())
            .collect::<Vec<_>>();

        assert_eq!(statements.len(), 3);
        assert!(statements[0].contains("line one; still data"));
        assert_eq!(statements[2].trim(), "Write-Output 'a;b'");
    }

    #[test]
    fn tokenizer_based_comment_removal_preserves_hashes_in_strings() {
        let statement = r##"Write-Output "#safe" # trailing comment"##;
        let parser = ParsedSource::parse(statement).expect("valid source");

        assert_eq!(
            strip_comments(&parser, statement).trim(),
            r##"Write-Output "#safe""##
        );
    }

    #[test]
    fn emulation_tokenizes_source_once() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();
        tokenizer::reset_tokenize_calls();

        emulator
            .emulate("$x = 1 + 2; Write-Output $x", &mut host, 0)
            .unwrap();

        assert_eq!(tokenizer::tokenize_calls(), 1);
        assert_eq!(emulator.drain_stdout(), ["3"]);
    }

    #[test]
    fn lexical_errors_stop_before_behavioral_emulation() {
        for (script, expected) in [
            (
                "Invoke-WebRequest https://example.invalid/payload '",
                "unterminated string literal",
            ),
            ("Invoke-Expression <# payload", "unterminated block comment"),
            ("$payload = @\"\ncommand", "unterminated here-string"),
            ("${payload", "unterminated braced variable"),
        ] {
            let mut host = VirtualHost::new(AnalysisLimits::default());
            let mut emulator = PowerShellEmulator::new();

            let error = emulator.emulate(script, &mut host, 0).unwrap_err();

            assert!(error.to_string().contains(expected));
            let snapshot = host.snapshot();
            assert!(snapshot.trace.is_empty());
            assert!(snapshot.virtual_files.is_empty());
            assert!(host.take_process_intents().is_empty());
        }
    }

    #[test]
    fn evaluates_unicode_variable_names_case_insensitively() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator
            .emulate(
                "$végösszeg = 'safe'; Write-Output \"$VÉGÖSSZEG\"",
                &mut host,
                0,
            )
            .unwrap();

        assert_eq!(emulator.drain_stdout(), ["safe"]);
    }

    #[test]
    fn evaluates_smart_quotes_and_unicode_dash_operators() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator
            .emulate(
                "Write-Output –NoEnumerate “safe”\nWrite-Output (3 – 2)",
                &mut host,
                0,
            )
            .unwrap();

        assert_eq!(emulator.drain_stdout(), ["safe", "1"]);
    }

    #[test]
    fn evaluates_statements_inside_expandable_string_subexpressions() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator
            .emulate(
                "Write-Output \"result: $(if ($true) { 'yes' } else { 'no' })\"",
                &mut host,
                0,
            )
            .unwrap();

        assert_eq!(emulator.drain_stdout(), ["result: yes"]);
    }

    #[test]
    fn evaluates_here_strings_with_trailing_pipeline_syntax() {
        let mut host = VirtualHost::new(AnalysisLimits::default());
        let mut emulator = PowerShellEmulator::new();

        emulator
            .emulate("Write-Output (@' \nsafe\n'@)", &mut host, 0)
            .unwrap();

        assert_eq!(emulator.drain_stdout(), ["safe"]);
    }
}
