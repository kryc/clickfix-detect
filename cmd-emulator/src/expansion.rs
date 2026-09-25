use crate::batch::BatchContext;
use crate::runtime::Runtime;
use emulator_core::Host;
use std::collections::BTreeMap;

pub(crate) fn expand(
    source: &str,
    runtime: &mut Runtime,
    batch: Option<&BatchContext>,
    loop_variables: &BTreeMap<char, String>,
    host: &dyn Host,
) -> String {
    let percent = expand_percent(source, runtime, batch, loop_variables, host);
    if runtime.delayed_expansion {
        expand_delayed(&percent, runtime, host)
    } else {
        percent
    }
}

fn expand_percent(
    source: &str,
    runtime: &mut Runtime,
    batch: Option<&BatchContext>,
    loop_variables: &BTreeMap<char, String>,
    host: &dyn Host,
) -> String {
    let mut output = String::new();
    let mut offset = 0;
    while offset < source.len() {
        let Some(relative) = source[offset..].find('%') else {
            output.push_str(&source[offset..]);
            break;
        };
        let start = offset + relative;
        output.push_str(&source[offset..start]);
        if let Some((value, consumed)) =
            expand_percent_at(&source[start..], runtime, batch, loop_variables, host)
        {
            output.push_str(&value);
            offset = start + consumed;
        } else {
            output.push('%');
            offset = start + 1;
        }
    }
    output
}

fn expand_percent_at(
    source: &str,
    runtime: &mut Runtime,
    batch: Option<&BatchContext>,
    loop_variables: &BTreeMap<char, String>,
    host: &dyn Host,
) -> Option<(String, usize)> {
    let after = source.strip_prefix('%')?;
    let first = after.chars().next()?;
    if first == '%' {
        let remaining = &after[first.len_utf8()..];
        if let Some(variable) = remaining.chars().next() {
            if let Some(value) = loop_variables.get(&variable.to_ascii_uppercase()) {
                return Some((value.clone(), 2 + variable.len_utf8()));
            }
        }
        return Some(("%".into(), 2));
    }
    if first == '*' {
        return batch.map(|context| (context.all_arguments(), 2));
    }
    if first.is_ascii_digit() {
        let index = first.to_digit(10).unwrap_or_default() as usize;
        return batch.map(|context| (context.argument(index), 2));
    }
    if first == '~' {
        return expand_modified(after, runtime, batch, loop_variables);
    }
    if first.is_ascii_alphabetic() {
        let key = first.to_ascii_uppercase();
        if let Some(value) = loop_variables.get(&key) {
            return Some((value.clone(), 1 + first.len_utf8()));
        }
        let following = &after[first.len_utf8()..];
        if following
            .chars()
            .next()
            .is_none_or(|ch| ch != '%' && !is_environment_name_character(ch))
        {
            return Some((format!("%{first}"), 1 + first.len_utf8()));
        }
    }

    let end = after.find('%')?;
    let expression = &after[..end];
    Some((
        expand_environment_expression(expression, runtime, host),
        end + 2,
    ))
}

fn expand_modified(
    after_percent: &str,
    runtime: &Runtime,
    batch: Option<&BatchContext>,
    loop_variables: &BTreeMap<char, String>,
) -> Option<(String, usize)> {
    let after_tilde = after_percent.strip_prefix('~')?;
    let characters = after_tilde.chars().collect::<Vec<_>>();
    let terminator = characters
        .iter()
        .position(|ch| ch.is_ascii_digit() || !is_path_modifier(*ch))
        .unwrap_or_else(|| characters.len().saturating_sub(1));
    let variable = *characters.get(terminator)?;
    let modifiers = characters[..terminator]
        .iter()
        .map(char::to_ascii_lowercase)
        .collect::<String>();
    let value = if variable.is_ascii_digit() {
        batch.map(|context| context.argument(variable.to_digit(10).unwrap_or_default() as usize))?
    } else {
        loop_variables.get(&variable.to_ascii_uppercase())?.clone()
    };
    let consumed = 2 + characters[..=terminator]
        .iter()
        .map(|ch| ch.len_utf8())
        .sum::<usize>();
    Some((apply_path_modifiers(&value, &modifiers, runtime), consumed))
}

fn is_path_modifier(ch: char) -> bool {
    matches!(ch.to_ascii_lowercase(), 'f' | 'd' | 'p' | 'n' | 'x')
}

fn apply_path_modifiers(value: &str, modifiers: &str, runtime: &Runtime) -> String {
    let unquoted = value.trim_matches('"');
    if modifiers.is_empty() {
        return unquoted.into();
    }
    let full = runtime.resolve_path(unquoted);
    if modifiers == "f" {
        return full;
    }
    let drive = full.get(..2).unwrap_or_default();
    let (parent, file) = full.rsplit_once('\\').unwrap_or(("", full.as_str()));
    let path = full
        .get(2..full.len().saturating_sub(file.len()))
        .unwrap_or_default();
    let (name, extension) = file
        .rfind('.')
        .filter(|index| *index > 0)
        .map_or((file, ""), |index| (&file[..index], &file[index..]));
    let mut output = String::new();
    for modifier in modifiers.chars() {
        match modifier {
            'f' => output.push_str(&full),
            'd' => output.push_str(drive),
            'p' => {
                let _ = parent;
                output.push_str(path);
            }
            'n' => output.push_str(name),
            'x' => output.push_str(extension),
            _ => {}
        }
    }
    output
}

fn expand_environment_expression(
    expression: &str,
    runtime: &mut Runtime,
    host: &dyn Host,
) -> String {
    let (name, transform) = expression
        .split_once(':')
        .map_or((expression, None), |(name, value)| (name, Some(value)));
    let value = runtime.variable(name, host);
    match transform {
        Some(slice) if slice.starts_with('~') => substring(&value, &slice[1..]),
        Some(replacement) => replace(&value, replacement),
        None => value,
    }
}

fn substring(value: &str, specification: &str) -> String {
    let (start, length) = specification
        .split_once(',')
        .map_or((specification, None), |(start, length)| {
            (start, Some(length))
        });
    let chars = value.chars().collect::<Vec<_>>();
    let start = parse_index(start, chars.len()).min(chars.len());
    let end = length.map_or(chars.len(), |length| {
        let parsed = length.trim().parse::<isize>().unwrap_or(0);
        if parsed < 0 {
            chars.len().saturating_sub(parsed.unsigned_abs())
        } else {
            start
                .saturating_add(usize::try_from(parsed).unwrap_or_default())
                .min(chars.len())
        }
    });
    chars[start..end.max(start)].iter().collect()
}

fn parse_index(value: &str, length: usize) -> usize {
    let parsed = value.trim().parse::<isize>().unwrap_or(0);
    if parsed < 0 {
        length.saturating_sub(parsed.unsigned_abs())
    } else {
        usize::try_from(parsed).unwrap_or_default()
    }
}

fn is_environment_name_character(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '~')
}

fn replace(value: &str, specification: &str) -> String {
    let Some((old, new)) = specification.split_once('=') else {
        return value.into();
    };
    value.replace(old, new)
}

fn expand_delayed(source: &str, runtime: &mut Runtime, host: &dyn Host) -> String {
    let mut output = String::new();
    let mut rest = source;
    while let Some(start) = rest.find('!') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let Some(end) = after.find('!') else {
            output.push_str(&rest[start..]);
            return output;
        };
        output.push_str(&runtime.variable(&after[..end], host));
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    output
}
