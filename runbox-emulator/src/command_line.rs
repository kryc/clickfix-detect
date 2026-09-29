use std::path::Path;

pub(crate) use emulator_core::windows::split_windows_command_line;

pub(crate) fn expand_environment_variables(
    input: &str,
    environment: &[(String, String)],
) -> String {
    environment
        .iter()
        .fold(input.to_owned(), |value, (name, replacement)| {
            replace_ascii_case_insensitive(&value, &format!("%{name}%"), replacement)
        })
}

pub(crate) fn find_argument(arguments: &[String], names: &[&str]) -> Option<usize> {
    arguments
        .iter()
        .position(|argument| names.iter().any(|name| argument.eq_ignore_ascii_case(name)))
}

pub(crate) fn basename(path: &str) -> &str {
    path.trim_matches('"')
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
}

pub(crate) fn has_script_extension(path: &str) -> bool {
    matches!(
        extension(path).as_str(),
        "ps1" | "cmd" | "bat" | "js" | "vbs" | "hta" | "sh" | "command"
    )
}

pub(crate) fn resolve_process_path(current_directory: &str, path: &str) -> String {
    let path = path.trim_matches('"').replace('/', "\\");
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        path
    } else {
        let current_directory = if current_directory.is_empty() {
            r"C:\Users\analysis"
        } else {
            current_directory
        };
        format!(
            "{}\\{}",
            current_directory.trim_end_matches('\\'),
            path.trim_start_matches('\\')
        )
    }
}

pub(crate) fn wildcard_match(value: &str, pattern: &str) -> bool {
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

pub(crate) fn extension(path: &str) -> String {
    Path::new(path.trim_matches('"'))
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

pub(crate) fn infer_http_method(arguments: &[String]) -> String {
    find_argument(arguments, &["-x", "--request"])
        .and_then(|index| arguments.get(index + 1))
        .map_or_else(|| "GET".into(), |value| value.to_ascii_uppercase())
}

pub(crate) fn trim_url_punctuation(input: &str) -> String {
    input
        .trim_end_matches(|character: char| ".,;:)]}".contains(character))
        .into()
}

pub(crate) fn quote_argument(input: &str) -> String {
    if input.contains(char::is_whitespace) || input.contains('"') {
        format!("\"{}\"", input.replace('"', "\\\""))
    } else {
        input.into()
    }
}

pub(crate) fn limited(input: &str, max: usize) -> String {
    if input.len() <= max {
        input.into()
    } else {
        format!("{}...", &input[..max])
    }
}

fn replace_ascii_case_insensitive(source: &str, needle: &str, replacement: &str) -> String {
    let mut output = String::new();
    let mut remaining = source;
    let lower_needle = needle.to_ascii_lowercase();
    while let Some(position) = remaining.to_ascii_lowercase().find(&lower_needle) {
        output.push_str(&remaining[..position]);
        output.push_str(replacement);
        remaining = &remaining[position + needle.len()..];
    }
    output.push_str(remaining);
    output
}
