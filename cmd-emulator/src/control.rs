use crate::syntax::split_words;
use crate::{CmdEmulator, CmdError, CommandOutput};
use emulator_core::{Engine, EventKind, Host, TraceEvent};
use std::cmp::Ordering;

pub(crate) fn execute(
    emulator: &mut CmdEmulator,
    source: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<Option<CommandOutput>, CmdError> {
    let trimmed = source.trim_start_matches('@').trim_start();
    if let Some(rest) = strip_word(trimmed, "if") {
        return execute_if(emulator, rest, host, depth).map(Some);
    }
    if let Some(rest) = strip_word(trimmed, "for") {
        return execute_for(emulator, rest, host, depth).map(Some);
    }
    Ok(None)
}

fn execute_if(
    emulator: &mut CmdEmulator,
    source: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let mut rest = source.trim_start();
    let mut ignore_case = false;
    if let Some(after) = strip_word(rest, "/i") {
        ignore_case = true;
        rest = after;
    }
    let mut negate = false;
    if let Some(after) = strip_word(rest, "not") {
        negate = true;
        rest = after;
    }
    let (condition, command) = parse_condition(emulator, rest, host, depth, ignore_case);
    let condition = if negate { !condition } else { condition };
    let (then_command, else_command) = split_else(command);
    let selected = if condition {
        Some(then_command)
    } else {
        else_command
    };
    if let Some(selected) = selected.filter(|value| !value.trim().is_empty()) {
        emulator.execute_chain(selected.trim(), host, depth + 1)
    } else {
        Ok(CommandOutput {
            code: emulator.runtime.error_level,
            ..CommandOutput::default()
        })
    }
}

fn parse_condition<'a>(
    emulator: &mut CmdEmulator,
    source: &'a str,
    host: &mut dyn Host,
    depth: usize,
    ignore_case: bool,
) -> (bool, &'a str) {
    if let Some(rest) = strip_word(source, "errorlevel") {
        let (value, command) = take_word(rest);
        let threshold = value.parse::<i32>().unwrap_or(i32::MAX);
        return (emulator.runtime.error_level >= threshold, command);
    }
    if let Some(rest) = strip_word(source, "exist") {
        let (path, command) = take_word(rest);
        let resolved = emulator.runtime.resolve_path(path.trim_matches('"'));
        let normalized = emulator_core::normalize_windows_path(&resolved);
        let exists = if resolved.contains(['*', '?']) {
            let prefix = resolved.split(['*', '?']).next().unwrap_or(&resolved);
            host.list_files(prefix, Engine::Cmd, depth)
                .iter()
                .any(|file| wildcard_match(file, &resolved))
                || emulator
                    .runtime
                    .directories
                    .iter()
                    .any(|directory| wildcard_match(directory, &normalized))
                || host
                    .list_directories(prefix, Engine::Cmd, depth)
                    .iter()
                    .any(|directory| wildcard_match(directory, &normalized))
        } else {
            emulator.runtime.directories.contains(&normalized)
                || host.directory_exists(&resolved)
                || host.read_file(&resolved, Engine::Cmd, depth).is_some()
        };
        return (exists, command);
    }
    if let Some(rest) = strip_word(source, "defined") {
        let (name, command) = take_word(rest);
        return (host.environment(name.trim_matches('"')).is_some(), command);
    }
    if let Some(equal) = find_unquoted(source, "==") {
        let left = source[..equal].trim().trim_matches('"');
        let (right, command) = take_word(&source[equal + 2..]);
        return (
            compare_strings(left, right.trim_matches('"'), ignore_case) == Ordering::Equal,
            command,
        );
    }
    let (left, rest) = take_word(source);
    let (operator, rest) = take_word(rest);
    let (right, command) = take_word(rest);
    let ordering = compare_values(left.trim_matches('"'), right.trim_matches('"'), ignore_case);
    let condition = match operator.to_ascii_lowercase().as_str() {
        "equ" => ordering == Ordering::Equal,
        "neq" => ordering != Ordering::Equal,
        "lss" => ordering == Ordering::Less,
        "leq" => ordering != Ordering::Greater,
        "gtr" => ordering == Ordering::Greater,
        "geq" => ordering != Ordering::Less,
        _ => false,
    };
    (condition, command)
}

fn compare_values(left: &str, right: &str, ignore_case: bool) -> Ordering {
    match (left.parse::<i64>(), right.parse::<i64>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => compare_strings(left, right, ignore_case),
    }
}

fn compare_strings(left: &str, right: &str, ignore_case: bool) -> Ordering {
    if ignore_case {
        left.to_ascii_lowercase().cmp(&right.to_ascii_lowercase())
    } else {
        left.cmp(right)
    }
}

fn execute_for(
    emulator: &mut CmdEmulator,
    source: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Result<CommandOutput, CmdError> {
    let parsed = parse_for(source)
        .ok_or_else(|| CmdError::Syntax("The syntax of the command is incorrect.".into()))?;
    let mut prelude = CommandOutput {
        code: emulator.runtime.error_level,
        ..CommandOutput::default()
    };
    let values = match parsed.mode {
        ForMode::Simple => split_words(&parsed.set)
            .into_iter()
            .map(|value| vec![value])
            .collect(),
        ForMode::Linear => linear_values(&parsed.set, host.limits().max_loop_iterations),
        ForMode::Recursive { root } => recursive_values(emulator, &root, &parsed.set, host, depth),
        ForMode::Text { options } => {
            text_values(emulator, &parsed.set, &options, host, depth, &mut prelude)?
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
        let variables = assignments_for(parsed.variable, assignments);
        let previous = variables
            .iter()
            .map(|(name, _)| (*name, emulator.loop_variables.get(name).cloned()))
            .collect::<Vec<_>>();
        emulator.loop_variables.extend(variables);
        let result = emulator.execute_chain(&parsed.body, host, depth + 1);
        for (name, value) in previous {
            if let Some(value) = value {
                emulator.loop_variables.insert(name, value);
            } else {
                emulator.loop_variables.remove(&name);
            }
        }
        let result = result?;
        output.stdout.extend(result.stdout);
        output.stderr.extend(result.stderr);
        output.code = result.code;
        output.exited = result.exited;
        if result.exited || emulator.has_batch_action() {
            break;
        }
    }
    Ok(output)
}

#[derive(Debug)]
enum ForMode {
    Simple,
    Linear,
    Recursive { root: String },
    Text { options: ForTextOptions },
}

#[derive(Debug)]
struct ParsedFor {
    mode: ForMode,
    variable: char,
    set: String,
    body: String,
}

fn parse_for(source: &str) -> Option<ParsedFor> {
    let mut rest = source.trim_start();
    let mut mode_name = "";
    if rest.starts_with('/') {
        let (mode, after) = take_word(rest);
        mode_name = mode;
        rest = after;
    }
    let mut options = String::new();
    let mut parsed_variable = None;
    if mode_name.eq_ignore_ascii_case("/f") && rest.starts_with('"') {
        let (value, after) = take_word(rest);
        options = value.trim_matches('"').into();
        rest = after;
    } else if mode_name.eq_ignore_ascii_case("/f") {
        loop {
            let (value, after) = take_word(rest);
            if value.starts_with('%') {
                parsed_variable = Some((value, after));
                break;
            }
            if !is_for_text_option(value) {
                break;
            }
            if !options.is_empty() {
                options.push(' ');
            }
            options.push_str(value);
            rest = after;
        }
    }
    let mut root = String::new();
    let (mut variable, mut after) = parsed_variable.unwrap_or_else(|| take_word(rest));
    if mode_name.eq_ignore_ascii_case("/r") && !variable.starts_with('%') {
        root = variable.trim_matches('"').into();
        (variable, after) = take_word(after);
    }

    let variable = variable.trim_start_matches('%').chars().next()?;
    rest = strip_word(after, "in")?;
    let (set, after_set) = take_parenthesized(rest)?;
    rest = strip_word(after_set, "do")?;
    let mode = if mode_name.eq_ignore_ascii_case("/l") {
        ForMode::Linear
    } else if mode_name.eq_ignore_ascii_case("/r") {
        ForMode::Recursive { root }
    } else if mode_name.eq_ignore_ascii_case("/f") {
        ForMode::Text {
            options: ForTextOptions::parse(&options),
        }
    } else {
        ForMode::Simple
    };
    Some(ParsedFor {
        mode,
        variable: variable.to_ascii_uppercase(),
        set: set.into(),
        body: rest.trim().into(),
    })
}

fn is_for_text_option(value: &str) -> bool {
    ["tokens=", "delims=", "skip=", "eol="]
        .iter()
        .any(|option| value.to_ascii_lowercase().starts_with(option))
}

fn take_parenthesized(source: &str) -> Option<(&str, &str)> {
    let trimmed = source.trim_start();
    let after_open = trimmed.strip_prefix('(')?;
    let mut depth = 1_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, ch) in after_open.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '^' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if !quoted && ch == '(' {
            depth += 1;
        } else if !quoted && ch == ')' {
            depth -= 1;
            if depth == 0 {
                return Some((&after_open[..offset], &after_open[offset + 1..]));
            }
        }
    }
    None
}

fn linear_values(source: &str, limit: usize) -> Vec<Vec<String>> {
    let numbers = source
        .split(',')
        .map(|value| value.trim().parse::<i64>())
        .collect::<Result<Vec<_>, _>>();
    let Ok(numbers) = numbers else {
        return Vec::new();
    };
    if numbers.len() != 3 {
        return Vec::new();
    }
    let (mut value, step, end) = (numbers[0], numbers[1], numbers[2]);
    let mut values = Vec::new();
    if step == 0 && value <= end {
        for _ in 0..=limit {
            values.push(vec![value.to_string()]);
        }
        return values;
    }
    while (step >= 0 && value <= end) || (step < 0 && value >= end) {
        values.push(vec![value.to_string()]);
        if values.len() > limit {
            break;
        }
        value = value.saturating_add(step);
    }
    values
}

fn recursive_values(
    emulator: &CmdEmulator,
    root: &str,
    set: &str,
    host: &mut dyn Host,
    depth: usize,
) -> Vec<Vec<String>> {
    let root = if root.is_empty() {
        emulator.runtime.current_directory.clone()
    } else {
        emulator.runtime.resolve_path(root)
    };
    let patterns = split_words(set);
    host.list_files(&root, Engine::Cmd, depth)
        .into_iter()
        .filter(|path| {
            let name = path.rsplit('\\').next().unwrap_or(path);
            patterns.iter().any(|pattern| wildcard_match(name, pattern))
        })
        .map(|path| vec![path])
        .collect()
}

#[derive(Debug)]
struct ForTextOptions {
    tokens: Vec<usize>,
    remainder: bool,
    delimiters: String,
    skip: usize,
    eol: Option<char>,
}

impl ForTextOptions {
    fn parse(source: &str) -> Self {
        let mut options = Self {
            tokens: vec![1],
            remainder: false,
            delimiters: " \t".into(),
            skip: 0,
            eol: Some(';'),
        };
        for option in split_words(source) {
            let lower = option.to_ascii_lowercase();
            if lower.starts_with("tokens=") {
                let value = &option["tokens=".len()..];
                options.tokens.clear();
                for token in value.split(',') {
                    if token == "*" {
                        options.remainder = true;
                    } else if let Ok(index) = token.parse() {
                        options.tokens.push(index);
                    }
                }
            } else if lower.starts_with("delims=") {
                let value = &option["delims=".len()..];
                options.delimiters = value.into();
            } else if lower.starts_with("skip=") {
                let value = &option["skip=".len()..];
                options.skip = value.parse().unwrap_or(0);
            } else if lower.starts_with("eol=") {
                let value = &option["eol=".len()..];
                options.eol = value.chars().next();
            }
        }
        options
    }
}

fn text_values(
    emulator: &mut CmdEmulator,
    source: &str,
    options: &ForTextOptions,
    host: &mut dyn Host,
    depth: usize,
    prelude: &mut CommandOutput,
) -> Result<Vec<Vec<String>>, CmdError> {
    let trimmed = source.trim();
    let lines = if let Some(command) = trimmed
        .strip_prefix('\'')
        .and_then(|value| value.strip_suffix('\''))
    {
        let result = emulator.execute_chain(command, host, depth + 1)?;
        prelude.stderr.extend(result.stderr);
        result.stdout
    } else if let Some(literal) = trimmed
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
    {
        literal.lines().map(str::to_string).collect()
    } else {
        let mut lines = Vec::new();
        for file in split_words(trimmed) {
            let path = emulator.runtime.resolve_path(&file);
            if let Some(bytes) = host.read_file(&path, Engine::Cmd, depth) {
                lines.extend(
                    String::from_utf8_lossy(&bytes)
                        .replace("\r\n", "\n")
                        .lines()
                        .map(str::to_string),
                );
            }
        }
        lines
    };
    Ok(lines
        .into_iter()
        .skip(options.skip)
        .filter(|line| {
            options
                .eol
                .is_none_or(|eol| !line.trim_start().starts_with(eol))
        })
        .map(|line| tokenize_for_f(&line, options))
        .filter(|values| !values.is_empty())
        .collect())
}

fn tokenize_for_f(line: &str, options: &ForTextOptions) -> Vec<String> {
    if options.delimiters.is_empty() {
        return vec![line.into()];
    }
    let fields = line
        .split(|ch| options.delimiters.contains(ch))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let mut selected = options
        .tokens
        .iter()
        .filter_map(|index| fields.get(index.saturating_sub(1)).copied())
        .map(str::to_string)
        .collect::<Vec<_>>();
    if options.remainder {
        let start = options.tokens.iter().copied().max().unwrap_or(0);
        if start < fields.len() {
            selected.push(fields[start..].join(" "));
        }
    }
    selected
}

fn assignments_for(variable: char, values: Vec<String>) -> Vec<(char, String)> {
    values
        .into_iter()
        .enumerate()
        .filter_map(|(offset, value)| {
            let offset = u32::try_from(offset).ok()?;
            char::from_u32(u32::from(variable).saturating_add(offset)).map(|name| (name, value))
        })
        .collect()
}

fn split_else(source: &str) -> (&str, Option<&str>) {
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, ch) in source.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '^' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if !quoted && ch == '(' {
            depth += 1;
        } else if !quoted && ch == ')' {
            depth = depth.saturating_sub(1);
        } else if !quoted
            && depth == 0
            && source[offset..]
                .get(..4)
                .is_some_and(|word| word.eq_ignore_ascii_case("else"))
            && source[..offset]
                .chars()
                .next_back()
                .is_none_or(char::is_whitespace)
            && source[offset + 4..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace)
        {
            return (&source[..offset], Some(&source[offset + 4..]));
        }
    }
    (source, None)
}

fn take_word(source: &str) -> (&str, &str) {
    let trimmed = source.trim_start();
    let mut quoted = false;
    let mut escaped = false;
    for (offset, ch) in trimmed.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '^' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if ch.is_whitespace() && !quoted {
            return (&trimmed[..offset], trimmed[offset..].trim_start());
        }
    }
    (trimmed, "")
}

fn strip_word<'a>(source: &'a str, word: &str) -> Option<&'a str> {
    let trimmed = source.trim_start();
    let prefix = trimmed.get(..word.len())?;
    if !prefix.eq_ignore_ascii_case(word) {
        return None;
    }
    let rest = &trimmed[word.len()..];
    (rest.is_empty() || rest.starts_with(char::is_whitespace)).then(|| rest.trim_start())
}

fn find_unquoted(source: &str, needle: &str) -> Option<usize> {
    let mut quoted = false;
    let mut escaped = false;
    for (offset, ch) in source.char_indices() {
        if escaped {
            escaped = false;
        } else if ch == '^' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if !quoted && source[offset..].starts_with(needle) {
            return Some(offset);
        }
    }
    None
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
