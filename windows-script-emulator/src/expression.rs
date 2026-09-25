use crate::tokenizer::{tokenize, TokenKind};
use crate::value::Value;
use crate::{ScriptError, ScriptLanguage};

#[derive(Debug, Clone)]
pub(crate) enum Expr {
    Value(Value),
    Ident(String),
    Array(Vec<Expr>),
    Object(Vec<(String, Expr)>),
    Unary(String, Box<Expr>),
    Binary(String, Box<Expr>, Box<Expr>),
    Assign(String, Box<Expr>, Box<Expr>),
    Member(Box<Expr>, String),
    Index(Box<Expr>, Box<Expr>),
    Call(Box<Expr>, Vec<Expr>),
    New(Box<Expr>, Vec<Expr>),
    Conditional(Box<Expr>, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone)]
struct Item {
    text: String,
    kind: TokenKind,
}

pub(crate) fn parse(source: &str, language: ScriptLanguage) -> Result<Expr, ScriptError> {
    let tokenization = tokenize(source, language);
    let items = tokenization
        .tokens
        .into_iter()
        .filter(|token| {
            !matches!(
                token.kind,
                TokenKind::Whitespace | TokenKind::Comment | TokenKind::Newline
            )
        })
        .map(|token| Item {
            text: token.text(source).into(),
            kind: token.kind,
        })
        .collect();
    let mut parser = Parser {
        items,
        cursor: 0,
        language,
    };
    if parser.items.is_empty() {
        return Ok(Expr::Value(Value::Undefined));
    }
    parser.parse_expression(0)
}

struct Parser {
    items: Vec<Item>,
    cursor: usize,
    language: ScriptLanguage,
}

impl Parser {
    fn parse_expression(&mut self, minimum: u8) -> Result<Expr, ScriptError> {
        let mut left = self.parse_prefix()?;
        loop {
            if self.take("(") {
                let arguments = self.parse_list(")")?;
                left = Expr::Call(Box::new(left), arguments);
                continue;
            }
            if self.take(".") {
                left = Expr::Member(Box::new(left), self.require_word()?);
                continue;
            }
            if self.take("[") {
                let index = self.parse_expression(0)?;
                self.require("]")?;
                left = Expr::Index(Box::new(left), Box::new(index));
                continue;
            }
            if self.peek_is("?") && minimum == 0 {
                self.cursor += 1;
                let truthy = self.parse_expression(0)?;
                self.require(":")?;
                let falsey = self.parse_expression(0)?;
                left = Expr::Conditional(Box::new(left), Box::new(truthy), Box::new(falsey));
                continue;
            }
            let Some(operator) = self.peek().map(|item| item.text.to_ascii_lowercase()) else {
                break;
            };
            let (precedence, right_associative) = precedence(&operator, self.language);
            if precedence == 0 || precedence < minimum {
                break;
            }
            self.cursor += 1;
            let right = self.parse_expression(if right_associative {
                precedence
            } else {
                precedence + 1
            })?;
            left = if is_assignment(&operator, self.language) {
                Expr::Assign(operator, Box::new(left), Box::new(right))
            } else {
                Expr::Binary(operator, Box::new(left), Box::new(right))
            };
        }
        Ok(left)
    }

    fn parse_prefix(&mut self) -> Result<Expr, ScriptError> {
        let Some(item) = self.items.get(self.cursor).cloned() else {
            return Err(ScriptError::Syntax("expected expression".into()));
        };
        self.cursor += 1;
        let lower = item.text.to_ascii_lowercase();
        if matches!(lower.as_str(), "!" | "~" | "+" | "-" | "not") {
            return Ok(Expr::Unary(lower, Box::new(self.parse_expression(14)?)));
        }
        if lower == "new" {
            let target = self.parse_prefix()?;
            if self.take("(") {
                let args = self.parse_list(")")?;
                return Ok(Expr::New(Box::new(target), args));
            }
            return Ok(Expr::New(Box::new(target), Vec::new()));
        }
        if item.text == "(" {
            let expression = self.parse_expression(0)?;
            self.require(")")?;
            return Ok(expression);
        }
        if item.text == "[" {
            return Ok(Expr::Array(self.parse_list("]")?));
        }
        if item.text == "{" {
            let mut entries = Vec::new();
            while !self.take("}") {
                let key = self.require_word_or_string()?;
                self.require(":")?;
                entries.push((key, self.parse_expression(0)?));
                if !self.take(",") {
                    self.require("}")?;
                    break;
                }
            }
            return Ok(Expr::Object(entries));
        }
        if item.kind == TokenKind::String {
            return Ok(Expr::Value(Value::String(decode_string(
                &item.text,
                self.language,
            ))));
        }
        if item.kind == TokenKind::Number {
            let number = parse_number(&item.text, self.language);
            return Ok(Expr::Value(Value::Number(number)));
        }
        match lower.as_str() {
            "true" => Ok(Expr::Value(Value::Bool(true))),
            "false" => Ok(Expr::Value(Value::Bool(false))),
            "null" | "nothing" => Ok(Expr::Value(Value::Null)),
            "undefined" | "empty" => Ok(Expr::Value(Value::Undefined)),
            _ => Ok(Expr::Ident(item.text)),
        }
    }

    fn parse_list(&mut self, end: &str) -> Result<Vec<Expr>, ScriptError> {
        let mut values = Vec::new();
        if self.take(end) {
            return Ok(values);
        }
        loop {
            values.push(self.parse_expression(0)?);
            if self.take(end) {
                break;
            }
            self.require(",")?;
        }
        Ok(values)
    }

    fn require_word(&mut self) -> Result<String, ScriptError> {
        let Some(item) = self.items.get(self.cursor) else {
            return Err(ScriptError::Syntax("expected identifier".into()));
        };
        if !matches!(item.kind, TokenKind::Identifier | TokenKind::Keyword) {
            return Err(ScriptError::Syntax(format!(
                "expected identifier, found {}",
                item.text
            )));
        }
        self.cursor += 1;
        Ok(item.text.clone())
    }

    fn require_word_or_string(&mut self) -> Result<String, ScriptError> {
        let Some(item) = self.items.get(self.cursor).cloned() else {
            return Err(ScriptError::Syntax("expected object key".into()));
        };
        self.cursor += 1;
        if item.kind == TokenKind::String {
            Ok(decode_string(&item.text, self.language))
        } else {
            Ok(item.text)
        }
    }

    fn require(&mut self, expected: &str) -> Result<(), ScriptError> {
        if self.take(expected) {
            Ok(())
        } else {
            Err(ScriptError::Syntax(format!("expected {expected}")))
        }
    }

    fn take(&mut self, expected: &str) -> bool {
        if self.peek_is(expected) {
            self.cursor += 1;
            true
        } else {
            false
        }
    }

    fn peek_is(&self, expected: &str) -> bool {
        self.peek()
            .is_some_and(|item| item.text.eq_ignore_ascii_case(expected))
    }

    fn peek(&self) -> Option<&Item> {
        self.items.get(self.cursor)
    }
}

fn precedence(operator: &str, language: ScriptLanguage) -> (u8, bool) {
    match operator {
        "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" => (1, true),
        "or" | "||" => (2, false),
        "xor" => (3, false),
        "and" | "&&" => (4, false),
        "|" => (5, false),
        "^" => (6, false),
        "&" if language == ScriptLanguage::JScript => (7, false),
        "==" | "===" | "!=" | "!==" | "<>" => (8, false),
        "<" | "<=" | ">" | ">=" | "in" => (9, false),
        "<<" | ">>" | ">>>" => (10, false),
        "+" | "-" | "&" => (11, false),
        "*" | "/" | "%" | "mod" => (12, false),
        _ => (0, false),
    }
}

fn is_assignment(operator: &str, language: ScriptLanguage) -> bool {
    language == ScriptLanguage::JScript
        && matches!(
            operator,
            "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^="
        )
}

fn parse_number(text: &str, language: ScriptLanguage) -> f64 {
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).map_or(f64::NAN, |value| value as f64);
    }
    if language == ScriptLanguage::VBScript {
        if let Some(hex) = text.strip_prefix("&h").or_else(|| text.strip_prefix("&H")) {
            return u64::from_str_radix(hex, 16).map_or(f64::NAN, |value| value as f64);
        }
    }
    text.parse().unwrap_or(f64::NAN)
}

fn decode_string(text: &str, language: ScriptLanguage) -> String {
    if text.len() < 2 {
        return text.into();
    }
    let inner = &text[1..text.len() - 1];
    if language == ScriptLanguage::VBScript {
        return inner.replace("\"\"", "\"");
    }
    let mut output = String::new();
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            output.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            break;
        };
        match escaped {
            'n' => output.push('\n'),
            'r' => output.push('\r'),
            't' => output.push('\t'),
            '0' => output.push('\0'),
            'x' => push_hex_escape(&mut output, &mut chars, 2),
            'u' => push_hex_escape(&mut output, &mut chars, 4),
            other => output.push(other),
        }
    }
    output
}

fn push_hex_escape(output: &mut String, chars: &mut impl Iterator<Item = char>, digits: usize) {
    let value = chars.take(digits).collect::<String>();
    if let Ok(codepoint) = u32::from_str_radix(&value, 16) {
        if let Some(ch) = char::from_u32(codepoint) {
            output.push(ch);
        }
    }
}
