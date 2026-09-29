use crate::ast::Word;
use crate::parser::ParsedDocument;
use crate::{BashEmulator, BashError};
use emulator_core::Host;

impl BashEmulator {
    pub(crate) fn expand_word_values(
        &mut self,
        document: &ParsedDocument,
        word: &Word,
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<Vec<String>, BashError> {
        let value = self.expand_word(document, word, host, depth)?;
        Ok(Self::expand_braces(
            &value,
            host.limits().max_loop_iterations.max(1),
        ))
    }

    pub(crate) fn evaluate_arithmetic_expression(&self, expression: &str, host: &dyn Host) -> i64 {
        evaluate_arithmetic(expression, |name| {
            self.runtime
                .variable(name, host.environment(name))
                .parse()
                .unwrap_or(0)
        })
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
            } else if fragment.starts_with("<(") || fragment.starts_with(">(") {
                let command = &fragment[2..fragment.len().saturating_sub(1)];
                let content = self.execute_substitution(command, host, depth + 1)?;
                self.runtime.temporary_file_counter += 1;
                let path = format!(
                    "/private/tmp/bash-process-{}",
                    self.runtime.temporary_file_counter
                );
                let bytes = if content.is_empty() {
                    Vec::new()
                } else {
                    format!("{content}\n").into_bytes()
                };
                host.write_file(&path, &bytes, false, emulator_core::Engine::Bash, depth)?;
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
    ArithmeticParser::new(expression, variable).parse_expression()
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
            let value = self.parse_expression();
            self.consume(')');
            return value;
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

    fn current(&self) -> char {
        self.source[self.offset..]
            .chars()
            .next()
            .expect("arithmetic offset is in source")
    }
}
