use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operator {
    Semicolon,
    And,
    Or,
    Pipe,
    Background,
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Redirect {
    Input,
    Output,
    Append,
    HereDoc,
    HereString,
    Merge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    Whitespace,
    Newline,
    Comment,
    Word,
    SingleQuoted,
    DoubleQuoted,
    Parameter,
    CommandSubstitution,
    ArithmeticSubstitution,
    ArithmeticCommand,
    ProcessSubstitution,
    ConditionalExpression,
    ArrayAssignment,
    BacktickSubstitution,
    HereDocBody,
    Escape,
    Operator(Operator),
    Redirect { fd: Option<u8>, kind: Redirect },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    #[must_use]
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        &source[self.span.start..self.span.end]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub span: Span,
    pub message: String,
    pub fatal: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokenization {
    pub tokens: Vec<Token>,
    pub diagnostics: Vec<Diagnostic>,
}

#[must_use]
pub fn tokenize(source: &str) -> Tokenization {
    Tokenizer::new(source).tokenize()
}

struct Tokenizer<'a> {
    source: &'a str,
    offset: usize,
    command_start: bool,
    expected_heredoc: Option<bool>,
    pending_heredocs: Vec<(String, bool)>,
    result: Tokenization,
}

impl<'a> Tokenizer<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            offset: 0,
            command_start: true,
            expected_heredoc: None,
            pending_heredocs: Vec::new(),
            result: Tokenization::default(),
        }
    }

    fn tokenize(mut self) -> Tokenization {
        while self.offset < self.source.len() {
            let start = self.offset;
            let ch = self.current();
            let kind = match ch {
                '\r' | '\n' => self.newline(),
                ' ' | '\t' => self.whitespace(),
                '#' if self.comment_start() => {
                    self.consume_until_newline();
                    TokenKind::Comment
                }
                '\'' => self.quoted('\'', TokenKind::SingleQuoted),
                '"' => self.double_quoted(),
                '`' => self.quoted('`', TokenKind::BacktickSubstitution),
                '\\' => {
                    self.advance();
                    if self.offset < self.source.len() {
                        self.advance();
                    }
                    TokenKind::Escape
                }
                '$' => self.dollar(),
                '[' if self.source[self.offset..].starts_with("[[") => self.conditional(),
                ';' => {
                    self.advance();
                    TokenKind::Operator(Operator::Semicolon)
                }
                '&' => {
                    self.advance();
                    if self.peek('&') {
                        self.advance();
                        TokenKind::Operator(Operator::And)
                    } else {
                        TokenKind::Operator(Operator::Background)
                    }
                }
                '|' => {
                    self.advance();
                    if self.peek('|') {
                        self.advance();
                        TokenKind::Operator(Operator::Or)
                    } else {
                        TokenKind::Operator(Operator::Pipe)
                    }
                }
                '<' | '>' if self.is_process_substitution() => self.process_substitution(),
                '(' if self.source[self.offset..].starts_with("((") => {
                    let start = self.offset;
                    self.offset += 2;
                    self.consume_balanced(start, "((", "))");
                    TokenKind::ArithmeticCommand
                }
                '(' => {
                    self.advance();
                    TokenKind::Operator(Operator::LeftParen)
                }
                ')' => {
                    self.advance();
                    TokenKind::Operator(Operator::RightParen)
                }
                '{' if self.is_group_brace('{') => {
                    self.advance();
                    TokenKind::Operator(Operator::LeftBrace)
                }
                '}' if self.is_group_brace('}') => {
                    self.advance();
                    TokenKind::Operator(Operator::RightBrace)
                }
                '0'..='9' if self.redirect_after_digits() => self.redirect(),
                '<' | '>' => self.redirect(),
                _ if self.is_array_assignment_start() => self.array_assignment(),
                _ => self.word(),
            };
            let end = self.offset;
            self.result.tokens.push(Token {
                kind,
                span: Span { start, end },
            });
            self.track_heredoc(kind, start, end);
            self.command_start = matches!(
                kind,
                TokenKind::Newline
                    | TokenKind::Operator(
                        Operator::Semicolon
                            | Operator::And
                            | Operator::Or
                            | Operator::Pipe
                            | Operator::Background
                            | Operator::LeftBrace
                            | Operator::LeftParen
                    )
            ) || matches!(kind, TokenKind::Whitespace) && self.command_start;
            if kind == TokenKind::Newline && !self.pending_heredocs.is_empty() {
                self.consume_heredoc_bodies();
            }
        }
        self.result
    }

    fn current(&self) -> char {
        self.source[self.offset..]
            .chars()
            .next()
            .expect("tokenizer offset is in source")
    }

    fn advance(&mut self) {
        self.offset += self.current().len_utf8();
    }

    fn peek(&self, expected: char) -> bool {
        self.source[self.offset..].starts_with(expected)
    }

    fn newline(&mut self) -> TokenKind {
        if self.source[self.offset..].starts_with("\r\n") {
            self.offset += 2;
        } else {
            self.advance();
        }
        TokenKind::Newline
    }

    fn whitespace(&mut self) -> TokenKind {
        while self.offset < self.source.len() && matches!(self.current(), ' ' | '\t') {
            self.advance();
        }
        TokenKind::Whitespace
    }

    fn consume_until_newline(&mut self) {
        while self.offset < self.source.len() && !matches!(self.current(), '\r' | '\n') {
            self.advance();
        }
    }

    fn comment_start(&self) -> bool {
        self.result.tokens.last().is_none_or(|token| {
            matches!(
                token.kind,
                TokenKind::Whitespace
                    | TokenKind::Newline
                    | TokenKind::Operator(
                        Operator::Semicolon
                            | Operator::And
                            | Operator::Or
                            | Operator::Pipe
                            | Operator::Background
                            | Operator::LeftBrace
                            | Operator::LeftParen
                    )
            )
        })
    }

    fn quoted(&mut self, delimiter: char, kind: TokenKind) -> TokenKind {
        let start = self.offset;
        self.advance();
        while self.offset < self.source.len() {
            let ch = self.current();
            self.advance();
            if ch == delimiter {
                return kind;
            }
            if delimiter != '\'' && ch == '\\' && self.offset < self.source.len() {
                self.advance();
            }
        }
        self.result.diagnostics.push(Diagnostic {
            span: Span {
                start,
                end: self.offset,
            },
            message: format!("unterminated {delimiter} quote"),
            fatal: true,
        });
        kind
    }

    fn double_quoted(&mut self) -> TokenKind {
        let start = self.offset;
        self.advance();
        while self.offset < self.source.len() {
            if self.source[self.offset..].starts_with("$((") {
                self.offset += 3;
                self.consume_balanced(start, "((", "))");
            } else if self.source[self.offset..].starts_with("$(") {
                self.offset += 2;
                self.consume_balanced(start, "(", ")");
            } else if self.source[self.offset..].starts_with("${") {
                self.offset += 2;
                self.consume_balanced(start, "{", "}");
            } else if self.peek('`') {
                self.quoted('`', TokenKind::BacktickSubstitution);
            } else {
                let ch = self.current();
                self.advance();
                if ch == '"' {
                    return TokenKind::DoubleQuoted;
                }
                if ch == '\\' && self.offset < self.source.len() {
                    self.advance();
                }
            }
        }
        self.result.diagnostics.push(Diagnostic {
            span: Span {
                start,
                end: self.offset,
            },
            message: "unterminated double quote".into(),
            fatal: true,
        });
        TokenKind::DoubleQuoted
    }

    fn dollar(&mut self) -> TokenKind {
        let start = self.offset;
        self.advance();
        if self.source[self.offset..].starts_with("((") {
            self.offset += 2;
            self.consume_balanced(start, "((", "))");
            TokenKind::ArithmeticSubstitution
        } else if self.peek('(') {
            self.advance();
            self.consume_balanced(start, "(", ")");
            TokenKind::CommandSubstitution
        } else if self.peek('{') {
            self.advance();
            self.consume_balanced(start, "{", "}");
            TokenKind::Parameter
        } else {
            if self.offset < self.source.len()
                && matches!(
                    self.current(),
                    '?' | '$' | '#' | '@' | '*' | '!' | '-' | '0'..='9'
                )
            {
                self.advance();
            } else {
                while self.offset < self.source.len()
                    && (self.current() == '_' || self.current().is_alphanumeric())
                {
                    self.advance();
                }
            }
            TokenKind::Parameter
        }
    }

    fn is_process_substitution(&self) -> bool {
        self.source[self.offset..]
            .get(1..)
            .is_some_and(|remaining| remaining.starts_with('('))
    }

    fn process_substitution(&mut self) -> TokenKind {
        let start = self.offset;
        self.advance();
        self.advance();
        self.consume_balanced(start, "(", ")");
        TokenKind::ProcessSubstitution
    }

    fn is_group_brace(&self, brace: char) -> bool {
        let after = self.offset + brace.len_utf8();
        self.source[after..]
            .chars()
            .next()
            .is_none_or(|next| next.is_whitespace() || matches!(next, ';' | '&' | '|' | ')' | '}'))
    }

    fn conditional(&mut self) -> TokenKind {
        let start = self.offset;
        self.offset += 2;
        let mut quote = None;
        while self.offset < self.source.len() {
            if let Some(delimiter) = quote {
                let ch = self.current();
                self.advance();
                if ch == delimiter {
                    quote = None;
                } else if ch == '\\' && delimiter != '\'' && self.offset < self.source.len() {
                    self.advance();
                }
                continue;
            }
            if matches!(self.current(), '\'' | '"') {
                quote = Some(self.current());
                self.advance();
            } else if self.source[self.offset..].starts_with("]]") {
                self.offset += 2;
                return TokenKind::ConditionalExpression;
            } else if self.current() == '\\' {
                self.advance();
                if self.offset < self.source.len() {
                    self.advance();
                }
            } else {
                self.advance();
            }
        }
        self.result.diagnostics.push(Diagnostic {
            span: Span {
                start,
                end: self.offset,
            },
            message: "unterminated [[ conditional expression".into(),
            fatal: true,
        });
        TokenKind::ConditionalExpression
    }

    fn is_array_assignment_start(&self) -> bool {
        let bytes = self.source.as_bytes();
        let mut offset = self.offset;
        let Some(first) = bytes.get(offset) else {
            return false;
        };
        if !(*first == b'_' || first.is_ascii_alphabetic()) {
            return false;
        }
        offset += 1;
        while bytes
            .get(offset)
            .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
        {
            offset += 1;
        }
        if bytes.get(offset) == Some(&b'+') {
            offset += 1;
        }
        bytes.get(offset) == Some(&b'=') && bytes.get(offset + 1) == Some(&b'(')
    }

    fn array_assignment(&mut self) -> TokenKind {
        while self.offset < self.source.len() && self.current() != '(' {
            self.advance();
        }
        let start = self.offset;
        self.advance();
        self.consume_balanced(start, "(", ")");
        TokenKind::ArrayAssignment
    }

    fn consume_balanced(&mut self, start: usize, open: &str, close: &str) {
        let mut depth = 1_usize;
        let mut quote = None;
        while self.offset < self.source.len() {
            if let Some(delimiter) = quote {
                let ch = self.current();
                self.advance();
                if ch == delimiter {
                    quote = None;
                } else if delimiter != '\'' && ch == '\\' && self.offset < self.source.len() {
                    self.advance();
                }
                continue;
            }
            if matches!(self.current(), '\'' | '"') {
                quote = Some(self.current());
                self.advance();
                continue;
            }
            if self.current() == '\\' {
                self.advance();
                if self.offset < self.source.len() {
                    self.advance();
                }
                continue;
            }
            if self.source[self.offset..].starts_with(open) {
                depth += 1;
                self.offset += open.len();
            } else if self.source[self.offset..].starts_with(close) {
                depth = depth.saturating_sub(1);
                self.offset += close.len();
                if depth == 0 {
                    return;
                }
            } else {
                self.advance();
            }
        }
        self.result.diagnostics.push(Diagnostic {
            span: Span {
                start,
                end: self.offset,
            },
            message: format!("unterminated substitution, expected {close}"),
            fatal: true,
        });
    }

    fn redirect_after_digits(&self) -> bool {
        let mut offset = self.offset;
        while offset < self.source.len() && self.source.as_bytes()[offset].is_ascii_digit() {
            offset += 1;
        }
        matches!(self.source.as_bytes().get(offset), Some(b'<' | b'>'))
    }

    fn redirect(&mut self) -> TokenKind {
        let mut fd = None;
        if self.current().is_ascii_digit() {
            let start = self.offset;
            while self.offset < self.source.len() && self.current().is_ascii_digit() {
                self.advance();
            }
            fd = self.source[start..self.offset].parse().ok();
        }
        let operator = self.current();
        self.advance();
        let kind = if operator == '>' && self.peek('>') {
            self.advance();
            Redirect::Append
        } else if operator == '<' && self.source[self.offset..].starts_with("<<") {
            self.offset += 2;
            Redirect::HereString
        } else if operator == '<' && self.peek('<') {
            self.advance();
            if self.peek('-') {
                self.advance();
            }
            Redirect::HereDoc
        } else if self.peek('&') {
            self.advance();
            while self.offset < self.source.len() && self.current().is_ascii_digit() {
                self.advance();
            }
            Redirect::Merge
        } else if operator == '<' {
            Redirect::Input
        } else {
            Redirect::Output
        };
        TokenKind::Redirect { fd, kind }
    }

    fn word(&mut self) -> TokenKind {
        while self.offset < self.source.len() {
            let ch = self.current();
            if ch.is_whitespace()
                || matches!(
                    ch,
                    '\'' | '"' | '`' | '\\' | '$' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
                )
            {
                break;
            }
            self.advance();
        }
        TokenKind::Word
    }

    fn track_heredoc(&mut self, kind: TokenKind, start: usize, end: usize) {
        if let TokenKind::Redirect {
            kind: Redirect::HereDoc,
            ..
        } = kind
        {
            self.expected_heredoc = Some(self.source[start..end].contains("<<-"));
            return;
        }
        let Some(strip_tabs) = self.expected_heredoc else {
            return;
        };
        if matches!(
            kind,
            TokenKind::Word | TokenKind::SingleQuoted | TokenKind::DoubleQuoted
        ) {
            let delimiter = self.source[start..end].trim_matches(['\'', '"']).to_owned();
            self.pending_heredocs.push((delimiter, strip_tabs));
            self.expected_heredoc = None;
        } else if !matches!(kind, TokenKind::Whitespace) {
            self.expected_heredoc = None;
        }
    }

    fn consume_heredoc_bodies(&mut self) {
        let heredocs = std::mem::take(&mut self.pending_heredocs);
        for (delimiter, strip_tabs) in heredocs {
            let start = self.offset;
            let mut found = false;
            while self.offset < self.source.len() {
                let line_start = self.offset;
                self.consume_until_newline();
                let line_end = self.offset;
                let line = self.source[line_start..line_end].trim_end_matches('\r');
                let comparison = if strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line
                };
                if self.offset < self.source.len() {
                    self.newline();
                }
                if comparison == delimiter {
                    found = true;
                    break;
                }
            }
            if self.offset > start {
                self.result.tokens.push(Token {
                    kind: TokenKind::HereDocBody,
                    span: Span {
                        start,
                        end: self.offset,
                    },
                });
            }
            if !found {
                self.result.diagnostics.push(Diagnostic {
                    span: Span {
                        start,
                        end: self.offset,
                    },
                    message: format!("unterminated heredoc, expected {delimiter}"),
                    fatal: true,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_spans_cover_utf8_source() {
        let source = "name='wørld'; echo \"hello $name\" | grep hello\n";
        let result = tokenize(source);
        let mut cursor = 0;
        for token in &result.tokens {
            assert_eq!(token.span.start, cursor);
            assert!(source.is_char_boundary(token.span.start));
            assert!(source.is_char_boundary(token.span.end));
            cursor = token.span.end;
        }
        assert_eq!(cursor, source.len());
        assert!(result.diagnostics.is_empty());
    }

    #[test]
    fn recognizes_substitutions_and_redirects() {
        let result = tokenize("x=$(echo hi); y=$((1+2)); cat <<< \"$x\" 2>&1");
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::CommandSubstitution));
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::ArithmeticSubstitution));
        assert!(result.tokens.iter().any(|token| {
            token.kind
                == TokenKind::Redirect {
                    fd: None,
                    kind: Redirect::HereString,
                }
        }));
    }

    #[test]
    fn heredoc_bodies_are_not_tokenized_as_shell_syntax() {
        let source = "cat <<'EOF'\nif (java) { \"unterminated }\nEOF\necho done\n";
        let result = tokenize(source);

        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::HereDocBody));
        let mut cursor = 0;
        for token in &result.tokens {
            assert_eq!(token.span.start, cursor);
            cursor = token.span.end;
        }
        assert_eq!(cursor, source.len());
    }

    #[test]
    fn distinguishes_process_substitution_brace_expansion_and_arithmetic() {
        let result = tokenize("for i in {0..3}; do cat <(echo \"$i\"); ((i++)); done");

        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::ProcessSubstitution));
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::ArithmeticCommand));
        assert!(result.tokens.iter().any(|token| token
            .text("for i in {0..3}; do cat <(echo \"$i\"); ((i++)); done")
            == "{0..3}"));
    }

    #[test]
    fn process_substitution_contains_multiline_single_quoted_programs() {
        let source = r#"done < <(
  echo "${items}" | "${jq}" '
    capture("(?<path>.*)") |
    "\(.path)"
  ' | sort -u
)
"#;
        let result = tokenize(source);

        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        let substitutions = result
            .tokens
            .iter()
            .filter(|token| token.kind == TokenKind::ProcessSubstitution)
            .collect::<Vec<_>>();
        assert_eq!(substitutions.len(), 1, "{:?}", result.tokens);
        assert!(substitutions[0].text(source).contains(r#""\(.path)""#));
    }

    #[test]
    fn double_quotes_contain_nested_command_substitution_quotes() {
        let source = r#"value="$(
  printf "%s\n" "inner"
  echo 'literal'
)"
echo "$value"
"#;
        let result = tokenize(source);

        assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
        assert_eq!(
            result
                .tokens
                .iter()
                .filter(|token| token.kind == TokenKind::DoubleQuoted)
                .count(),
            2
        );
    }
}
