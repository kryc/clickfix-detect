use crate::ast::Word;
use crate::parser::ParsedDocument;
use crate::{BashEmulator, BashError};
use emulator_core::{Engine, EventKind, Host, TraceEvent};

impl BashEmulator {
    pub(crate) fn expand_word_values(
        &mut self,
        document: &ParsedDocument,
        word: &Word,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Vec<String>, BashError> {
        let raw = word
            .fragments
            .iter()
            .map(|span| &document.source()[span.start..span.end])
            .collect::<String>();
        if raw.contains("=(") && raw.ends_with(')') {
            return Ok(vec![self.expand_word(document, word, host, depth)?]);
        }
        if let Some(values) = self.expand_array_word(&raw, host) {
            return Ok(values);
        }
        let value = self.expand_word(document, word, host, depth)?;
        let values = Self::expand_braces(&value, host.limits().max_loop_iterations.max(1));
        if word_is_quoted(&raw) {
            return Ok(values);
        }
        let mut expanded = Vec::new();
        for value in values {
            for field in self.split_fields(&value, host) {
                expanded.extend(self.expand_glob(&field, host, depth));
            }
        }
        Ok(expanded)
    }

    pub(crate) fn evaluate_arithmetic_expression(&self, expression: &str, host: &dyn Host) -> i64 {
        evaluate_arithmetic(expression, |name| {
            self.runtime
                .variable(name, host.environment(name))
                .parse()
                .unwrap_or(0)
        })
    }

    pub(crate) fn execute_arithmetic_statement(
        &mut self,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> i64 {
        let mut value = 0;
        for statement in split_arithmetic_statements(expression) {
            let statement = statement.trim();
            if statement.is_empty() {
                continue;
            }
            if let Some(name) = statement.strip_suffix("++").map(str::trim) {
                value = self.update_arithmetic_variable(name, 1, host, depth);
            } else if let Some(name) = statement.strip_suffix("--").map(str::trim) {
                value = self.update_arithmetic_variable(name, -1, host, depth);
            } else if let Some(name) = statement.strip_prefix("++").map(str::trim) {
                value = self.update_arithmetic_variable(name, 1, host, depth);
            } else if let Some(name) = statement.strip_prefix("--").map(str::trim) {
                value = self.update_arithmetic_variable(name, -1, host, depth);
            } else if let Some((name, operator, right)) = arithmetic_assignment(statement) {
                let right = self.evaluate_arithmetic_expression(right, host);
                let current = self.evaluate_arithmetic_expression(name, host);
                value = match operator {
                    "+=" => current.wrapping_add(right),
                    "-=" => current.wrapping_sub(right),
                    "*=" => current.wrapping_mul(right),
                    "/=" => {
                        if right == 0 {
                            0
                        } else {
                            current / right
                        }
                    }
                    "%=" => {
                        if right == 0 {
                            0
                        } else {
                            current % right
                        }
                    }
                    _ => right,
                };
                self.assign_arithmetic_variable(name, value, host, depth);
            } else {
                value = self.evaluate_arithmetic_expression(statement, host);
            }
        }
        value
    }

    fn update_arithmetic_variable(
        &mut self,
        name: &str,
        delta: i64,
        host: &mut dyn Host,
        depth: usize,
    ) -> i64 {
        let value = self
            .evaluate_arithmetic_expression(name, host)
            .wrapping_add(delta);
        self.assign_arithmetic_variable(name, value, host, depth);
        value
    }

    fn assign_arithmetic_variable(
        &mut self,
        name: &str,
        value: i64,
        host: &mut dyn Host,
        depth: usize,
    ) {
        let name = name.trim();
        if !is_arithmetic_variable(name) {
            return;
        }
        let value = value.to_string();
        self.runtime.variables.insert(name.into(), value.clone());
        if self.runtime.exported.contains(name) {
            host.set_environment(name, &value);
        }
        host.emit(
            TraceEvent::new(
                depth,
                Engine::Bash,
                EventKind::VariableAssignment,
                format!("assigned arithmetic shell variable {name}"),
            )
            .with_data("value", value),
        );
    }

    fn expand_braces(value: &str, limit: usize) -> Vec<String> {
        let Some(open) = value.find('{') else {
            return vec![value.into()];
        };
        let Some(relative_close) = value[open + 1..].find('}') else {
            return vec![value.into()];
        };
        let close = open + 1 + relative_close;
        let prefix = &value[..open];
        let body = &value[open + 1..close];
        let suffix = &value[close + 1..];
        let mut replacements = Vec::new();
        let range = body.split("..").collect::<Vec<_>>();
        if matches!(range.len(), 2 | 3) {
            let step = range
                .get(2)
                .and_then(|value| value.parse::<i64>().ok())
                .filter(|value| *value != 0);
            if let (Ok(start), Ok(end)) = (range[0].parse::<i64>(), range[1].parse::<i64>()) {
                let step = step.unwrap_or(if start <= end { 1 } else { -1 });
                let mut current = start;
                while replacements.len() < limit
                    && if step > 0 {
                        current <= end
                    } else {
                        current >= end
                    }
                {
                    replacements.push(current.to_string());
                    current = current.saturating_add(step);
                }
            } else if range[0].chars().count() == 1 && range[1].chars().count() == 1 {
                let start = range[0].chars().next().unwrap_or_default() as i64;
                let end = range[1].chars().next().unwrap_or_default() as i64;
                let step = step.unwrap_or(if start <= end { 1 } else { -1 });
                let mut current = start;
                while replacements.len() < limit
                    && if step > 0 {
                        current <= end
                    } else {
                        current >= end
                    }
                {
                    if let Some(ch) = char::from_u32(u32::try_from(current).unwrap_or_default()) {
                        replacements.push(ch.to_string());
                    }
                    current = current.saturating_add(step);
                }
            }
        } else if body.contains(',') {
            replacements.extend(body.split(',').take(limit).map(str::to_owned));
        }
        if replacements.is_empty() {
            return vec![value.into()];
        }
        replacements
            .into_iter()
            .flat_map(|replacement| {
                Self::expand_braces(&format!("{prefix}{replacement}{suffix}"), limit)
            })
            .take(limit)
            .collect()
    }

    pub(crate) fn expand_word(
        &mut self,
        document: &ParsedDocument,
        word: &Word,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, BashError> {
        let mut output = String::new();
        for span in &word.fragments {
            let fragment = &document.source()[span.start..span.end];
            if fragment.starts_with('\'') {
                output.push_str(fragment.trim_matches('\''));
            } else if fragment.starts_with('"') {
                let inner = fragment
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(fragment);
                output.push_str(&self.expand_text(inner, host, depth)?);
            } else if fragment.starts_with('\\') {
                output.push_str(fragment.strip_prefix('\\').unwrap_or(fragment));
            } else if fragment.starts_with('`') {
                let command = fragment
                    .strip_prefix('`')
                    .and_then(|value| value.strip_suffix('`'))
                    .unwrap_or_default();
                output.push_str(&self.execute_substitution(command, host, depth + 1)?);
            } else if fragment.starts_with("<(") {
                let command = &fragment[2..fragment.len().saturating_sub(1)];
                let content = self.execute_substitution(command, host, depth + 1)?;
                self.runtime.temporary_file_counter += 1;
                let path = self.temporary_process_path(host);
                let bytes = if content.is_empty() {
                    Vec::new()
                } else {
                    format!("{content}\n").into_bytes()
                };
                host.write_file(&path, &bytes, false, emulator_core::Engine::Bash, depth)?;
                output.push_str(&path);
            } else if fragment.starts_with(">(") {
                let command = &fragment[2..fragment.len().saturating_sub(1)];
                self.runtime.temporary_file_counter += 1;
                let path = self.temporary_process_path(host);
                host.write_file(&path, &[], false, emulator_core::Engine::Bash, depth)?;
                self.runtime
                    .output_process_substitutions
                    .insert(path.clone(), command.into());
                output.push_str(&path);
            } else {
                output.push_str(&self.expand_text(fragment, host, depth)?);
            }
        }
        if output == "~" {
            Ok(self
                .runtime
                .variable("HOME", host.environment("HOME"))
                .to_string())
        } else if let Some(rest) = output.strip_prefix("~/") {
            Ok(format!(
                "{}/{}",
                self.runtime.variable("HOME", host.environment("HOME")),
                rest
            ))
        } else {
            Ok(output)
        }
    }

    pub(crate) fn expand_text(
        &mut self,
        source: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, BashError> {
        let mut output = String::new();
        let mut offset = 0;
        while offset < source.len() {
            if source[offset..].starts_with("$((") {
                if let Some(end) = source[offset + 3..].find("))") {
                    let expression = &source[offset + 3..offset + 3 + end];
                    output.push_str(
                        &self
                            .evaluate_arithmetic_expression(expression, host)
                            .to_string(),
                    );
                    offset += 3 + end + 2;
                    continue;
                }
            }
            if source[offset..].starts_with("$(") {
                if let Some((command, consumed)) = balanced_substitution(&source[offset + 2..]) {
                    output.push_str(&self.execute_substitution(command, host, depth + 1)?);
                    offset += consumed + 2;
                    continue;
                }
            }
            if source.as_bytes()[offset] == b'$' {
                let remaining = &source[offset + 1..];
                if let Some(braced) = remaining.strip_prefix('{') {
                    if let Some(end) = braced.find('}') {
                        output.push_str(&self.expand_parameter(&braced[..end], host, depth)?);
                        offset += end + 3;
                        continue;
                    }
                }
                let length = remaining
                    .char_indices()
                    .take_while(|(index, character)| {
                        if *index == 0 {
                            character.is_alphanumeric()
                                || matches!(character, '_' | '?' | '$' | '#' | '@' | '*')
                        } else {
                            character.is_alphanumeric() || *character == '_'
                        }
                    })
                    .map(|(index, character)| index + character.len_utf8())
                    .last()
                    .unwrap_or(0);
                if length > 0 {
                    let name = &remaining[..length];
                    output.push_str(&self.runtime.variable(name, host.environment(name)));
                    offset += length + 1;
                    continue;
                }
            }
            if source.as_bytes()[offset] == b'`' {
                if let Some(end) = source[offset + 1..].find('`') {
                    let command = &source[offset + 1..offset + 1 + end];
                    output.push_str(&self.execute_substitution(command, host, depth + 1)?);
                    offset += end + 2;
                    continue;
                }
            }
            let ch = source[offset..]
                .chars()
                .next()
                .expect("offset is in expansion source");
            if ch == '\\' {
                offset += 1;
                if offset < source.len() {
                    let escaped = source[offset..].chars().next().expect("escaped character");
                    output.push(escaped);
                    offset += escaped.len_utf8();
                }
            } else {
                output.push(ch);
                offset += ch.len_utf8();
            }
        }
        Ok(output)
    }

    fn expand_parameter(
        &mut self,
        expression: &str,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<String, BashError> {
        if let Some(name) = expression.strip_prefix('#') {
            if let Some((name, index)) = array_reference(name) {
                if matches!(index, "@" | "*") {
                    return Ok(self
                        .runtime
                        .arrays
                        .get(name)
                        .map_or(0, Vec::len)
                        .to_string());
                }
            }
            return Ok(self
                .runtime
                .variable(name, host.environment(name))
                .chars()
                .count()
                .to_string());
        }
        if let Some((name, fallback)) = expression.split_once(":-") {
            let value = self.runtime.variable(name, host.environment(name));
            return if value.is_empty() {
                self.expand_text(fallback, host, depth)
            } else {
                Ok(value)
            };
        }
        if let Some((name, fallback)) = expression.split_once(":=") {
            let value = self.runtime.variable(name, host.environment(name));
            if value.is_empty() {
                let value = self.expand_text(fallback, host, depth)?;
                self.runtime.variables.insert(name.into(), value.clone());
                return Ok(value);
            }
            return Ok(value);
        }
        if let Some((name, alternate)) = expression.split_once(":+") {
            let value = self.runtime.variable(name, host.environment(name));
            return if value.is_empty() {
                Ok(String::new())
            } else {
                self.expand_text(alternate, host, depth)
            };
        }
        Ok(self
            .runtime
            .variable(expression, host.environment(expression)))
    }

    fn expand_array_word(&self, raw: &str, host: &dyn Host) -> Option<Vec<String>> {
        let (quoted, expression) = strip_outer_quotes(raw);
        let expression = expression.strip_prefix("${")?.strip_suffix('}')?;
        let (name, index) = array_reference(expression)?;
        let values = self.runtime.arrays.get(name).cloned().unwrap_or_default();
        match index {
            "@" => Some(values),
            "*" => {
                let separator = self.ifs(host).chars().next().unwrap_or(' ');
                Some(vec![values.join(&separator.to_string())])
            }
            index => Some(vec![index
                .parse::<usize>()
                .ok()
                .and_then(|index| values.get(index))
                .cloned()
                .unwrap_or_default()])
            .filter(|_| quoted || !values.is_empty()),
        }
    }

    fn split_fields(&self, value: &str, host: &dyn Host) -> Vec<String> {
        let Some(ifs) = self.ifs_value(host) else {
            return vec![value.into()];
        };
        if ifs.is_empty() {
            return vec![value.into()];
        }
        value
            .split(|character| ifs.contains(character))
            .filter(|field| !field.is_empty())
            .map(str::to_owned)
            .collect()
    }

    fn expand_glob(&self, pattern: &str, host: &mut dyn Host, depth: usize) -> Vec<String> {
        if !pattern.contains(['*', '?']) {
            return vec![pattern.into()];
        }
        let (parent, name_pattern, absolute) = match pattern.rsplit_once('/') {
            Some(("", name)) => ("/".into(), name, true),
            Some((parent, name)) => (self.runtime.resolve_path(parent), name, true),
            None => (self.runtime.current_directory.clone(), pattern, false),
        };
        let include_hidden = name_pattern.starts_with('.');
        let mut matches = host
            .list_files(&parent, Engine::Bash, depth)
            .into_iter()
            .chain(host.list_directories(&parent, Engine::Bash, depth))
            .filter_map(|candidate| {
                let name = direct_child_name(&parent, &candidate)?.to_owned();
                if !include_hidden && name.starts_with('.') {
                    return None;
                }
                crate::shell_pattern_matches(&name, name_pattern).then_some({
                    if absolute {
                        candidate
                    } else {
                        name
                    }
                })
            })
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        if matches.is_empty() {
            vec![pattern.into()]
        } else {
            matches
        }
    }

    fn ifs(&self, host: &dyn Host) -> String {
        self.ifs_value(host).unwrap_or_else(|| " \t\n".into())
    }

    fn ifs_value(&self, host: &dyn Host) -> Option<String> {
        self.runtime
            .variables
            .get("IFS")
            .cloned()
            .or_else(|| host.environment("IFS").map(str::to_owned))
            .or_else(|| Some(" \t\n".into()))
    }

    fn temporary_process_path(&self, host: &dyn Host) -> String {
        let directory = host.environment("TMPDIR").unwrap_or("/tmp");
        format!(
            "{}/bash-process-{}",
            directory.trim_end_matches('/'),
            self.runtime.temporary_file_counter
        )
    }
}

fn strip_outer_quotes(value: &str) -> (bool, &str) {
    if let Some(value) = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
    {
        (true, value)
    } else {
        (false, value)
    }
}

fn word_is_quoted(value: &str) -> bool {
    matches!(value.chars().next(), Some('\'' | '"'))
}

fn array_reference(name: &str) -> Option<(&str, &str)> {
    let open = name.find('[')?;
    let close = name.strip_suffix(']')?;
    Some((&name[..open], &close[open + 1..]))
}

fn direct_child_name<'a>(parent: &str, candidate: &'a str) -> Option<&'a str> {
    let prefix = if parent == "/" {
        "/".into()
    } else {
        format!("{}/", parent.trim_end_matches('/'))
    };
    let rest = candidate.strip_prefix(&prefix)?;
    (!rest.is_empty() && !rest.contains('/')).then_some(rest)
}

fn balanced_substitution(source: &str) -> Option<(&str, usize)> {
    let mut depth = 1_usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in source.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if ch == delimiter {
                quote = None;
            }
            continue;
        }
        if matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some((&source[..index], index + ch.len_utf8()));
            }
        }
    }
    None
}

fn evaluate_arithmetic(expression: &str, variable: impl Fn(&str) -> i64) -> i64 {
    ArithmeticParser::new(expression, variable).parse_logical_or()
}

struct ArithmeticParser<'a, F> {
    source: &'a str,
    offset: usize,
    variable: F,
}

impl<'a, F: Fn(&str) -> i64> ArithmeticParser<'a, F> {
    fn new(source: &'a str, variable: F) -> Self {
        Self {
            source,
            offset: 0,
            variable,
        }
    }

    fn parse_logical_or(&mut self) -> i64 {
        let mut value = self.parse_logical_and();
        while self.consume_str("||") {
            let right = self.parse_logical_and();
            value = i64::from(value != 0 || right != 0);
        }
        value
    }

    fn parse_logical_and(&mut self) -> i64 {
        let mut value = self.parse_comparison();
        while self.consume_str("&&") {
            let right = self.parse_comparison();
            value = i64::from(value != 0 && right != 0);
        }
        value
    }

    fn parse_comparison(&mut self) -> i64 {
        let mut value = self.parse_expression();
        loop {
            let comparison = if self.consume_str("==") {
                Some("==")
            } else if self.consume_str("!=") {
                Some("!=")
            } else if self.consume_str("<=") {
                Some("<=")
            } else if self.consume_str(">=") {
                Some(">=")
            } else if self.consume('<') {
                Some("<")
            } else if self.consume('>') {
                Some(">")
            } else {
                None
            };
            let Some(comparison) = comparison else {
                break;
            };
            let right = self.parse_expression();
            value = i64::from(match comparison {
                "==" => value == right,
                "!=" => value != right,
                "<=" => value <= right,
                ">=" => value >= right,
                "<" => value < right,
                ">" => value > right,
                _ => false,
            });
        }
        value
    }

    fn parse_expression(&mut self) -> i64 {
        let mut value = self.parse_term();
        loop {
            self.skip_spaces();
            if self.consume('+') {
                value = value.wrapping_add(self.parse_term());
            } else if self.consume('-') {
                value = value.wrapping_sub(self.parse_term());
            } else {
                break;
            }
        }
        value
    }

    fn parse_term(&mut self) -> i64 {
        let mut value = self.parse_factor();
        loop {
            self.skip_spaces();
            if self.consume('*') {
                value = value.wrapping_mul(self.parse_factor());
            } else if self.consume('/') {
                let divisor = self.parse_factor();
                value = if divisor == 0 { 0 } else { value / divisor };
            } else if self.consume('%') {
                let divisor = self.parse_factor();
                value = if divisor == 0 { 0 } else { value % divisor };
            } else {
                break;
            }
        }
        value
    }

    fn parse_factor(&mut self) -> i64 {
        self.skip_spaces();
        if self.consume('(') {
            let value = self.parse_logical_or();
            self.consume(')');
            return value;
        }
        if self.consume('!') {
            return i64::from(self.parse_factor() == 0);
        }
        if self.consume('+') {
            return self.parse_factor();
        }
        if self.consume('-') {
            return self.parse_factor().wrapping_neg();
        }
        let start = self.offset;
        while self.offset < self.source.len()
            && (self.current().is_alphanumeric() || self.current() == '_')
        {
            self.offset += self.current().len_utf8();
        }
        let value = &self.source[start..self.offset];
        value.parse().unwrap_or_else(|_| (self.variable)(value))
    }

    fn skip_spaces(&mut self) {
        while self.offset < self.source.len() && self.current().is_whitespace() {
            self.offset += self.current().len_utf8();
        }
    }

    fn consume(&mut self, expected: char) -> bool {
        self.skip_spaces();
        if self.offset < self.source.len() && self.current() == expected {
            self.offset += expected.len_utf8();
            true
        } else {
            false
        }
    }

    fn consume_str(&mut self, expected: &str) -> bool {
        self.skip_spaces();
        if self.source[self.offset..].starts_with(expected) {
            self.offset += expected.len();
            true
        } else {
            false
        }
    }

    fn current(&self) -> char {
        self.source[self.offset..]
            .chars()
            .next()
            .expect("arithmetic offset is in source")
    }
}

fn split_arithmetic_statements(expression: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0_usize;
    let mut start = 0_usize;
    for (offset, character) in expression.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&expression[start..offset]);
                start = offset + character.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&expression[start..]);
    parts
}

fn arithmetic_assignment(expression: &str) -> Option<(&str, &str, &str)> {
    let bytes = expression.as_bytes();
    let mut depth = 0_usize;
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => {
                for operator in ["+=", "-=", "*=", "/=", "%=", "="] {
                    if expression[index..].starts_with(operator) {
                        if operator == "="
                            && (bytes
                                .get(index.wrapping_sub(1))
                                .is_some_and(|byte| matches!(byte, b'!' | b'<' | b'>' | b'='))
                                || bytes.get(index + 1) == Some(&b'='))
                        {
                            continue;
                        }
                        let name = expression[..index].trim();
                        if is_arithmetic_variable(name) {
                            return Some((
                                name,
                                operator,
                                expression[index + operator.len()..].trim(),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

fn is_arithmetic_variable(name: &str) -> bool {
    !name.is_empty()
        && name.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphanumeric() && (index > 0 || !character.is_ascii_digit())
        })
}
