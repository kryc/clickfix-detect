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
    let mut parser = Parser {
        source,
        cursor: 0,
        runtime,
        host,
        depth,
    };
    parser.execute_until_end()
}

struct Parser<'a> {
    source: &'a str,
    cursor: usize,
    runtime: &'a mut Runtime,
    host: &'a mut dyn Host,
    depth: usize,
}

impl Parser<'_> {
    fn execute_until_end(&mut self) -> Result<Flow, ScriptError> {
        while self.skip_trivia() {
            if self.runtime.exited() {
                break;
            }
            let flow = self.execute_statement()?;
            if flow != Flow::Continue {
                return Ok(flow);
            }
        }
        Ok(Flow::Continue)
    }

    fn execute_statement(&mut self) -> Result<Flow, ScriptError> {
        if self.peek_keyword("function") {
            return self.parse_function();
        }
        if self.peek_keyword("if") {
            return self.parse_if();
        }
        if self.peek_keyword("while") {
            return self.parse_while();
        }
        if self.peek_keyword("for") {
            return self.parse_for();
        }
        if self.peek_keyword("return") {
            self.take_keyword("return");
            let expression = self.take_statement_text();
            let value = if expression.trim().is_empty() {
                Value::Undefined
            } else {
                self.runtime.evaluate(
                    &expression,
                    ScriptLanguage::JScript,
                    self.host,
                    self.depth,
                )?
            };
            return Ok(Flow::Return(value));
        }
        if self.peek_keyword("break") {
            self.take_keyword("break");
            self.take_statement_text();
            return Ok(Flow::Break);
        }
        if self.peek_keyword("var") || self.peek_keyword("let") || self.peek_keyword("const") {
            self.take_word();
            let declarations = self.take_statement_text();
            for declaration in split_top_level(&declarations, ',') {
                let (name, expression) = declaration
                    .split_once('=')
                    .map_or((declaration.trim(), None), |(name, expression)| {
                        (name.trim(), Some(expression.trim()))
                    });
                let value = if let Some(expression) = expression {
                    self.runtime.evaluate(
                        expression,
                        ScriptLanguage::JScript,
                        self.host,
                        self.depth,
                    )?
                } else {
                    Value::Undefined
                };
                self.runtime
                    .set_variable(name, value, self.host, self.depth);
            }
            return Ok(Flow::Continue);
        }
        if self.current_char() == Some('{') {
            let body = self.take_braced()?;
            return execute(&body, self.runtime, self.host, self.depth);
        }
        let statement = self.take_statement_text();
        if statement.trim().is_empty() {
            return Ok(Flow::Continue);
        }
        if let Some(name) = statement.trim().strip_suffix("++") {
            let value = self.runtime.get_variable(name.trim()).number() + 1.0;
            self.runtime
                .set_variable(name.trim(), Value::Number(value), self.host, self.depth);
        } else if let Some(name) = statement.trim().strip_suffix("--") {
            let value = self.runtime.get_variable(name.trim()).number() - 1.0;
            self.runtime
                .set_variable(name.trim(), Value::Number(value), self.host, self.depth);
        } else {
            self.runtime.evaluate(
                statement.trim(),
                ScriptLanguage::JScript,
                self.host,
                self.depth,
            )?;
        }
        Ok(Flow::Continue)
    }

    fn parse_function(&mut self) -> Result<Flow, ScriptError> {
        self.take_keyword("function");
        self.skip_spaces();
        let name = self.take_word();
        self.skip_spaces();
        let parameters = self.take_parenthesized()?;
        self.skip_trivia();
        let body = self.take_braced()?;
        self.runtime.define_function(
            &name,
            FunctionDef {
                params: split_top_level(&parameters, ',')
                    .into_iter()
                    .map(|value| value.trim().to_owned())
                    .filter(|value| !value.is_empty())
                    .collect(),
                body,
                language: ScriptLanguage::JScript,
                is_sub: false,
            },
        );
        Ok(Flow::Continue)
    }

    fn parse_if(&mut self) -> Result<Flow, ScriptError> {
        self.take_keyword("if");
        self.skip_spaces();
        let condition = self.take_parenthesized()?;
        self.skip_trivia();
        let truthy = self.take_body()?;
        self.skip_trivia();
        let falsey = if self.peek_keyword("else") {
            self.take_keyword("else");
            self.skip_trivia();
            Some(self.take_body()?)
        } else {
            None
        };
        if self
            .runtime
            .evaluate(&condition, ScriptLanguage::JScript, self.host, self.depth)?
            .truthy()
        {
            execute(&truthy, self.runtime, self.host, self.depth)
        } else if let Some(falsey) = falsey {
            execute(&falsey, self.runtime, self.host, self.depth)
        } else {
            Ok(Flow::Continue)
        }
    }

    fn parse_while(&mut self) -> Result<Flow, ScriptError> {
        self.take_keyword("while");
        self.skip_spaces();
        let condition = self.take_parenthesized()?;
        self.skip_trivia();
        let body = self.take_body()?;
        for _ in 0..self.host.limits().max_loop_iterations {
            if !self
                .runtime
                .evaluate(&condition, ScriptLanguage::JScript, self.host, self.depth)?
                .truthy()
            {
                return Ok(Flow::Continue);
            }
            match execute(&body, self.runtime, self.host, self.depth)? {
                Flow::Continue => {}
                Flow::Break => return Ok(Flow::Continue),
                flow => return Ok(flow),
            }
        }
        Err(ScriptError::LoopLimit {
            limit: self.host.limits().max_loop_iterations,
        })
    }

    fn parse_for(&mut self) -> Result<Flow, ScriptError> {
        self.take_keyword("for");
        self.skip_spaces();
        let controls = self.take_parenthesized()?;
        self.skip_trivia();
        let body = self.take_body()?;
        if let Some((binding, collection)) = split_for_in(&controls) {
            let name = binding
                .trim()
                .trim_start_matches("var ")
                .trim_start_matches("let ")
                .trim();
            let values = self.runtime.evaluate(
                collection,
                ScriptLanguage::JScript,
                self.host,
                self.depth,
            )?;
            let values = match values {
                Value::Array(values) => values,
                Value::Object(values) => values.keys().cloned().map(Value::String).collect(),
                _ => Vec::new(),
            };
            for value in values
                .into_iter()
                .take(self.host.limits().max_loop_iterations)
            {
                self.runtime
                    .set_variable(name, value, self.host, self.depth);
                if execute(&body, self.runtime, self.host, self.depth)? == Flow::Break {
                    break;
                }
            }
            return Ok(Flow::Continue);
        }
        let parts = split_top_level(&controls, ';');
        let initializer = parts.first().map_or("", String::as_str).trim();
        let condition = parts.get(1).map_or("true", String::as_str).trim();
        let increment = parts.get(2).map_or("", String::as_str).trim();
        if let Some(declaration) = initializer
            .strip_prefix("var ")
            .or_else(|| initializer.strip_prefix("let "))
        {
            if let Some((name, expression)) = declaration.split_once('=') {
                let value = self.runtime.evaluate(
                    expression,
                    ScriptLanguage::JScript,
                    self.host,
                    self.depth,
                )?;
                self.runtime
                    .set_variable(name.trim(), value, self.host, self.depth);
            }
        } else if !initializer.is_empty() {
            self.runtime
                .evaluate(initializer, ScriptLanguage::JScript, self.host, self.depth)?;
        }
        for _ in 0..self.host.limits().max_loop_iterations {
            if !self
                .runtime
                .evaluate(condition, ScriptLanguage::JScript, self.host, self.depth)?
                .truthy()
            {
                return Ok(Flow::Continue);
            }
            match execute(&body, self.runtime, self.host, self.depth)? {
                Flow::Continue => {}
                Flow::Break => return Ok(Flow::Continue),
                flow => return Ok(flow),
            }
            execute(increment, self.runtime, self.host, self.depth)?;
        }
        Err(ScriptError::LoopLimit {
            limit: self.host.limits().max_loop_iterations,
        })
    }

    fn take_body(&mut self) -> Result<String, ScriptError> {
        if self.current_char() == Some('{') {
            self.take_braced()
        } else {
            Ok(self.take_statement_text())
        }
    }

    fn take_parenthesized(&mut self) -> Result<String, ScriptError> {
        self.take_balanced('(', ')')
    }

    fn take_braced(&mut self) -> Result<String, ScriptError> {
        self.take_balanced('{', '}')
    }

    fn take_balanced(&mut self, open: char, close: char) -> Result<String, ScriptError> {
        if self.current_char() != Some(open) {
            return Err(ScriptError::Syntax(format!("expected {open}")));
        }
        let start = self.cursor + open.len_utf8();
        let mut index = start;
        let mut nesting = 1_usize;
        let mut quote = None;
        let bytes = self.source.as_bytes();
        while index < self.source.len() {
            let ch = self.source[index..]
                .chars()
                .next()
                .expect("character exists");
            if let Some(active) = quote {
                if ch == '\\' {
                    index += ch.len_utf8();
                    if index < self.source.len() {
                        index += self.source[index..]
                            .chars()
                            .next()
                            .expect("character exists")
                            .len_utf8();
                    }
                    continue;
                }
                if ch == active {
                    quote = None;
                }
            } else if matches!(ch, '\'' | '"') {
                quote = Some(ch);
            } else if ch == open {
                nesting += 1;
            } else if ch == close {
                nesting -= 1;
                if nesting == 0 {
                    let value = self.source[start..index].to_owned();
                    self.cursor = index + ch.len_utf8();
                    return Ok(value);
                }
            } else if ch == '/' && bytes.get(index + 1) == Some(&b'/') {
                while index < self.source.len() && !matches!(bytes[index], b'\r' | b'\n') {
                    index += 1;
                }
                continue;
            }
            index += ch.len_utf8();
        }
        Err(ScriptError::Syntax(format!("unterminated {open} block")))
    }

    fn take_statement_text(&mut self) -> String {
        let start = self.cursor;
        let mut nesting = 0_i32;
        let mut quote = None;
        while self.cursor < self.source.len() {
            let ch = self.current_char().expect("character exists");
            if let Some(active) = quote {
                self.cursor += ch.len_utf8();
                if ch == '\\' && self.cursor < self.source.len() {
                    self.cursor += self
                        .current_char()
                        .expect("escaped character exists")
                        .len_utf8();
                } else if ch == active {
                    quote = None;
                }
                continue;
            }
            match ch {
                '\'' | '"' => quote = Some(ch),
                '(' | '[' | '{' => nesting += 1,
                ')' | ']' | '}' => nesting -= 1,
                ';' if nesting == 0 => {
                    let value = self.source[start..self.cursor].to_owned();
                    self.cursor += 1;
                    return value;
                }
                '\r' | '\n' if nesting == 0 => {
                    return self.source[start..self.cursor].to_owned();
                }
                _ => {}
            }
            self.cursor += ch.len_utf8();
        }
        self.source[start..].to_owned()
    }

    fn skip_trivia(&mut self) -> bool {
        loop {
            self.skip_spaces();
            if self.source[self.cursor..].starts_with("//") {
                while let Some(ch) = self.current_char() {
                    self.cursor += ch.len_utf8();
                    if matches!(ch, '\r' | '\n') {
                        break;
                    }
                }
            } else if self.source[self.cursor..].starts_with("/*") {
                if let Some(end) = self.source[self.cursor + 2..].find("*/") {
                    self.cursor += end + 4;
                } else {
                    self.cursor = self.source.len();
                }
            } else {
                break;
            }
        }
        self.cursor < self.source.len()
    }

    fn skip_spaces(&mut self) {
        while self
            .current_char()
            .is_some_and(|ch| ch.is_whitespace() || ch == ';')
        {
            self.cursor += self.current_char().expect("character exists").len_utf8();
        }
    }

    fn peek_keyword(&self, keyword: &str) -> bool {
        let rest = &self.source[self.cursor..];
        rest.get(..keyword.len())
            .is_some_and(|value| value.eq_ignore_ascii_case(keyword))
            && rest[keyword.len()..]
                .chars()
                .next()
                .is_none_or(|ch| !(ch.is_alphanumeric() || matches!(ch, '_' | '$')))
    }

    fn take_keyword(&mut self, keyword: &str) {
        self.cursor += keyword.len();
    }

    fn take_word(&mut self) -> String {
        let start = self.cursor;
        while self
            .current_char()
            .is_some_and(|ch| ch.is_alphanumeric() || matches!(ch, '_' | '$'))
        {
            self.cursor += self.current_char().expect("character exists").len_utf8();
        }
        self.source[start..self.cursor].to_owned()
    }

    fn current_char(&self) -> Option<char> {
        self.source[self.cursor..].chars().next()
    }
}

fn split_top_level(source: &str, separator: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut nesting = 0_i32;
    let mut quote = None;
    let mut escaped = false;
    for (index, ch) in source.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' | '[' | '{' => nesting += 1,
            ')' | ']' | '}' => nesting -= 1,
            _ if ch == separator && nesting == 0 => {
                parts.push(source[start..index].to_owned());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(source[start..].to_owned());
    parts
}

fn split_for_in(source: &str) -> Option<(&str, &str)> {
    let lower = source.to_ascii_lowercase();
    let position = lower.find(" in ")?;
    Some((&source[..position], &source[position + 4..]))
}
