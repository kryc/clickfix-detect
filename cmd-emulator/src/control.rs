use crate::ast::ForTextOptions;
use crate::syntax::split_words;
use crate::{CmdEmulator, CmdError, CommandOutput};
use emulator_core::{Engine, Host};

pub(crate) fn linear_values(source: &str, limit: usize) -> Vec<Vec<String>> {
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

pub(crate) fn recursive_values(
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

pub(crate) fn text_values(
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

pub(crate) fn assignments_for(variable: char, values: Vec<String>) -> Vec<(char, String)> {
    values
        .into_iter()
        .enumerate()
        .filter_map(|(offset, value)| {
            let offset = u32::try_from(offset).ok()?;
            char::from_u32(u32::from(variable).saturating_add(offset)).map(|name| (name, value))
        })
        .collect()
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
