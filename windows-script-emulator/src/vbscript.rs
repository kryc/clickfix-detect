use crate::runtime::{Flow, FunctionDef, Runtime};
use crate::value::Value;
use crate::{ScriptError, ScriptLanguage};
use emulator_core::Host;

pub(crate) fn execute(
    source: &str,
    runtime: &mut Runtime,
    host: &mut dyn Host,
    depth: usize,
) -> Result<Flow, ScriptError> {
    let lines = logical_lines(source);
    execute_range(&lines, 0, lines.len(), runtime, host, depth)
}

fn execute_range(
    lines: &[String],
    start: usize,
    end: usize,
    runtime: &mut Runtime,
    host: &mut dyn Host,
    depth: usize,
) -> Result<Flow, ScriptError> {
    let mut index = start;
    while index < end {
        if runtime.exited() {
            break;
        }
        let line = lines[index].trim();
        if line.is_empty() || line.starts_with('\'') || starts_with_word(line, "rem") {
            index += 1;
            continue;
        }
        if starts_with_word(line, "function") || starts_with_word(line, "sub") {
            let is_sub = starts_with_word(line, "sub");
            let keyword = if is_sub { "sub" } else { "function" };
            let (name, params) = parse_signature(line[keyword.len()..].trim())?;
            let terminator = if is_sub { "end sub" } else { "end function" };
            let block_end = find_terminator(lines, index + 1, end, terminator)?;
            runtime.define_function(
                &name,
                FunctionDef {
                    params,
                    body: lines[index + 1..block_end].join("\n"),
                    language: ScriptLanguage::VBScript,
                    is_sub,
                },
            );
            index = block_end + 1;
            continue;
        }
        if starts_with_word(line, "if") {
            let then_position = find_ascii_case_insensitive(line, " then")
                .ok_or_else(|| ScriptError::Syntax("VBScript If requires Then".into()))?;
            let condition = line[2..then_position].trim();
            let tail = line[then_position + 5..].trim();
            if !tail.is_empty() {
                let (truthy, falsey) = split_inline_else(tail);
                let selected = if evaluate_condition(condition, runtime, host, depth)? {
                    truthy
                } else {
                    falsey.unwrap_or("")
                };
                let flow = execute(selected, runtime, host, depth)?;
                if flow != Flow::Continue {
                    return Ok(flow);
                }
                index += 1;
                continue;
            }
            let (else_index, block_end) = find_if_bounds(lines, index + 1, end)?;
            let condition_true = evaluate_condition(condition, runtime, host, depth)?;
            let flow = if condition_true {
                execute_range(
                    lines,
                    index + 1,
                    else_index.unwrap_or(block_end),
                    runtime,
                    host,
                    depth,
                )?
            } else if let Some(else_index) = else_index {
                execute_range(lines, else_index + 1, block_end, runtime, host, depth)?
            } else {
                Flow::Continue
            };
            if flow != Flow::Continue {
                return Ok(flow);
            }
            index = block_end + 1;
            continue;
        }
        if starts_with_word(line, "for each") {
            let rest = line[8..].trim();
            let in_position = find_ascii_case_insensitive(rest, " in ")
                .ok_or_else(|| ScriptError::Syntax("For Each requires In".into()))?;
            let name = rest[..in_position].trim();
            let collection = runtime.evaluate(
                rest[in_position + 4..].trim(),
                ScriptLanguage::VBScript,
                host,
                depth,
            )?;
            let block_end = find_terminator(lines, index + 1, end, "next")?;
            let values = match collection {
                Value::Array(values) => values,
                Value::Object(values) => values.into_values().collect(),
                _ => Vec::new(),
            };
            for value in values.into_iter().take(host.limits().max_loop_iterations) {
                runtime.set_variable(name, value, host, depth);
                match execute_range(lines, index + 1, block_end, runtime, host, depth)? {
                    Flow::Continue => {}
                    Flow::Break => break,
                    flow => return Ok(flow),
                }
            }
            index = block_end + 1;
            continue;
        }
        if starts_with_word(line, "for") {
            let rest = line[3..].trim();
            let (name, range) = rest
                .split_once('=')
                .ok_or_else(|| ScriptError::Syntax("For requires assignment".into()))?;
            let to_position = find_ascii_case_insensitive(range, " to ")
                .ok_or_else(|| ScriptError::Syntax("For requires To".into()))?;
            let start_expression = range[..to_position].trim();
            let remaining = range[to_position + 4..].trim();
            let (end_expression, step_expression) =
                if let Some(position) = find_ascii_case_insensitive(remaining, " step ") {
                    (
                        remaining[..position].trim(),
                        Some(remaining[position + 6..].trim()),
                    )
                } else {
                    (remaining, None)
                };
            let mut value = runtime
                .evaluate(start_expression, ScriptLanguage::VBScript, host, depth)?
                .number();
            let limit = runtime
                .evaluate(end_expression, ScriptLanguage::VBScript, host, depth)?
                .number();
            let step = if let Some(expression) = step_expression {
                runtime
                    .evaluate(expression, ScriptLanguage::VBScript, host, depth)?
                    .number()
            } else {
                1.0
            };
            let block_end = find_terminator(lines, index + 1, end, "next")?;
            let mut iterations = 0;
            while iterations < host.limits().max_loop_iterations
                && ((step >= 0.0 && value <= limit) || (step < 0.0 && value >= limit))
            {
                runtime.set_variable(name.trim(), Value::Number(value), host, depth);
                match execute_range(lines, index + 1, block_end, runtime, host, depth)? {
                    Flow::Continue => {}
                    Flow::Break => break,
                    flow => return Ok(flow),
                }
                value += step;
                iterations += 1;
            }
            index = block_end + 1;
            continue;
        }
        if starts_with_word(line, "while")
            || starts_with_word(line, "do while")
            || starts_with_word(line, "do until")
            || line.eq_ignore_ascii_case("do")
        {
            let (condition, invert, terminator) = if starts_with_word(line, "do while") {
                (line[8..].trim(), false, "loop")
            } else if starts_with_word(line, "do until") {
                (line[8..].trim(), true, "loop")
            } else if line.eq_ignore_ascii_case("do") {
                ("True", false, "loop")
            } else {
                (line[5..].trim(), false, "wend")
            };
            let block_end = find_terminator(lines, index + 1, end, terminator)?;
            let mut completed = false;
            for _ in 0..host.limits().max_loop_iterations {
                if evaluate_condition(condition, runtime, host, depth)? == invert {
                    completed = true;
                    break;
                }
                match execute_range(lines, index + 1, block_end, runtime, host, depth)? {
                    Flow::Continue => {}
                    Flow::Break => {
                        completed = true;
                        break;
                    }
                    flow => return Ok(flow),
                }
            }
            if !completed && evaluate_condition(condition, runtime, host, depth)? != invert {
                return Err(ScriptError::LoopLimit {
                    limit: host.limits().max_loop_iterations,
                });
            }
            index = block_end + 1;
            continue;
        }
        if starts_with_word(line, "exit for") || starts_with_word(line, "exit do") {
            return Ok(Flow::Break);
        }
        if starts_with_word(line, "exit function") || starts_with_word(line, "exit sub") {
            return Ok(Flow::Return(Value::Undefined));
        }
        execute_simple(line, runtime, host, depth)?;
        index += 1;
    }
    Ok(Flow::Continue)
}

fn execute_simple(
    line: &str,
    runtime: &mut Runtime,
    host: &mut dyn Host,
    depth: usize,
) -> Result<(), ScriptError> {
    let mut line = line.trim();
    if starts_with_word(line, "on error") || line.eq_ignore_ascii_case("err.clear") {
        return Ok(());
    }
    if starts_with_word(line, "dim") || starts_with_word(line, "const") {
        line = line.split_once(' ').map_or("", |(_, rest)| rest).trim();
        for declaration in split_arguments(line) {
            if let Some((name, expression)) = split_assignment(&declaration) {
                let value = runtime.evaluate(expression, ScriptLanguage::VBScript, host, depth)?;
                runtime.set_variable(name, value, host, depth);
            } else {
                runtime.set_variable(declaration.trim(), Value::Undefined, host, depth);
            }
        }
        return Ok(());
    }
    if starts_with_word(line, "set") {
        line = line[3..].trim();
    }
    if starts_with_word(line, "execute") && !line.contains('(') {
        let expression = line
            .split_once(' ')
            .map_or("", |(_, expression)| expression)
            .trim();
        let source = runtime
            .evaluate(expression, ScriptLanguage::VBScript, host, depth)?
            .string();
        runtime.execute_decoded(&source, host, depth + 1)?;
        return Ok(());
    }
    if let Some((name, expression)) = split_assignment(line) {
        let value = runtime.evaluate(expression, ScriptLanguage::VBScript, host, depth)?;
        if is_simple_name(name) {
            runtime.set_variable(name, value, host, depth);
        } else {
            runtime.assign_target(name, value, ScriptLanguage::VBScript, host, depth)?;
        }
        return Ok(());
    }
    let line = line.strip_prefix("Call ").unwrap_or(line);
    if let Some((callee, arguments)) = split_call_without_parentheses(line) {
        let expression = format!("{callee}({arguments})");
        runtime.evaluate(&expression, ScriptLanguage::VBScript, host, depth)?;
    } else if line.contains('.') && !line.contains(char::is_whitespace) && !line.ends_with(')') {
        runtime.evaluate(&format!("{line}()"), ScriptLanguage::VBScript, host, depth)?;
    } else {
        runtime.evaluate(line, ScriptLanguage::VBScript, host, depth)?;
    }
    Ok(())
}

fn logical_lines(source: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut continued = String::new();
    for physical in source.lines() {
        let stripped = strip_comment(physical);
        let trimmed = stripped.trim_end();
        if let Some(prefix) = trimmed.strip_suffix(" _") {
            continued.push_str(prefix);
            continued.push(' ');
            continue;
        }
        continued.push_str(trimmed);
        lines.extend(split_colons(&continued));
        continued.clear();
    }
    if !continued.is_empty() {
        lines.extend(split_colons(&continued));
    }
    lines
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    let mut previous_quote = false;
    for (index, ch) in line.char_indices() {
        if ch == '"' {
            if quoted && previous_quote {
                previous_quote = false;
                continue;
            }
            previous_quote = quoted;
            quoted = !quoted;
        } else {
            previous_quote = false;
            if ch == '\'' && !quoted {
                return &line[..index];
            }
        }
    }
    line
}

fn split_colons(line: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    for (index, ch) in line.char_indices() {
        if ch == '"' {
            quoted = !quoted;
        } else if ch == ':' && !quoted {
            output.push(line[start..index].trim().to_owned());
            start = index + 1;
        }
    }
    output.push(line[start..].trim().to_owned());
    output
}

fn find_terminator(
    lines: &[String],
    start: usize,
    end: usize,
    terminator: &str,
) -> Result<usize, ScriptError> {
    let mut nesting = 0_usize;
    for (index, line) in lines.iter().enumerate().take(end).skip(start) {
        let line = line.trim();
        if (terminator == "next" && starts_with_word(line, "for"))
            || (terminator == "wend" && starts_with_word(line, "while"))
            || (terminator == "loop" && starts_with_word(line, "do"))
        {
            nesting += 1;
        } else if starts_with_word(line, terminator) {
            if nesting == 0 {
                return Ok(index);
            }
            nesting -= 1;
        }
    }
    Err(ScriptError::Syntax(format!("missing {terminator}")))
}

fn find_if_bounds(
    lines: &[String],
    start: usize,
    end: usize,
) -> Result<(Option<usize>, usize), ScriptError> {
    let mut nesting = 0_usize;
    let mut else_index = None;
    for (index, line) in lines.iter().enumerate().take(end).skip(start) {
        let line = line.trim();
        if starts_with_word(line, "if") && line.to_ascii_lowercase().ends_with(" then") {
            nesting += 1;
        } else if line.eq_ignore_ascii_case("end if") {
            if nesting == 0 {
                return Ok((else_index, index));
            }
            nesting -= 1;
        } else if nesting == 0 && line.eq_ignore_ascii_case("else") {
            else_index = Some(index);
        }
    }
    Err(ScriptError::Syntax("missing End If".into()))
}

fn parse_signature(source: &str) -> Result<(String, Vec<String>), ScriptError> {
    if let Some(open) = source.find('(') {
        let close = source
            .rfind(')')
            .ok_or_else(|| ScriptError::Syntax("unterminated parameter list".into()))?;
        Ok((
            source[..open].trim().into(),
            split_arguments(&source[open + 1..close])
                .into_iter()
                .map(|param| {
                    param
                        .trim()
                        .trim_start_matches("ByVal ")
                        .trim_start_matches("ByRef ")
                        .to_owned()
                })
                .collect(),
        ))
    } else {
        Ok((source.trim().into(), Vec::new()))
    }
}

fn split_assignment(source: &str) -> Option<(&str, &str)> {
    let mut quoted = false;
    let mut nesting = 0_i32;
    for (index, ch) in source.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '(' if !quoted => nesting += 1,
            ')' if !quoted => nesting -= 1,
            '=' if !quoted && nesting == 0 => {
                let previous = source[..index].chars().next_back();
                let next = source[index + 1..].chars().next();
                if previous != Some('<') && previous != Some('>') && next != Some('=') {
                    return Some((source[..index].trim(), source[index + 1..].trim()));
                }
            }
            _ => {}
        }
    }
    None
}

fn split_arguments(source: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut nesting = 0_i32;
    for (index, ch) in source.char_indices() {
        match ch {
            '"' => quoted = !quoted,
            '(' if !quoted => nesting += 1,
            ')' if !quoted => nesting -= 1,
            ',' if !quoted && nesting == 0 => {
                output.push(source[start..index].trim().to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    output.push(source[start..].trim().to_owned());
    output
}

fn split_call_without_parentheses(source: &str) -> Option<(&str, &str)> {
    let position = source.find(char::is_whitespace)?;
    let callee = source[..position].trim();
    if callee.contains('.') || is_simple_name(callee) {
        Some((callee, source[position..].trim()))
    } else {
        None
    }
}

fn split_inline_else(source: &str) -> (&str, Option<&str>) {
    if let Some(position) = find_ascii_case_insensitive(source, " else ") {
        (&source[..position], Some(&source[position + 6..]))
    } else {
        (source, None)
    }
}

fn evaluate_condition(
    expression: &str,
    runtime: &mut Runtime,
    host: &mut dyn Host,
    depth: usize,
) -> Result<bool, ScriptError> {
    Ok(runtime
        .evaluate(expression, ScriptLanguage::VBScript, host, depth)?
        .truthy())
}

fn starts_with_word(source: &str, word: &str) -> bool {
    source
        .get(..word.len())
        .is_some_and(|value| value.eq_ignore_ascii_case(word))
        && source[word.len()..]
            .chars()
            .next()
            .is_none_or(|ch| ch.is_whitespace() || matches!(ch, '(' | ':'))
}

fn find_ascii_case_insensitive(source: &str, needle: &str) -> Option<usize> {
    source
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

fn is_simple_name(source: &str) -> bool {
    !source.is_empty()
        && source
            .chars()
            .all(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '.'))
        && !source.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_line_parser_preserves_string_colons() {
        assert_eq!(
            logical_lines("x = \"a:b\": y = 2"),
            ["x = \"a:b\"", "y = 2"]
        );
    }
}
