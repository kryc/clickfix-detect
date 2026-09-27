use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operator {
    Ampersand,
    And,
    Or,
    Pipe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Redirect {
    Output,
    Append,
    Input,
    Merge,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    Whitespace,
    Newline,
    Comment,
    Label,
    EchoControl,
    QuotedString,
    CaretEscape,
    LineContinuation,
    PercentVariable,
    DelayedVariable,
    ForVariable,
    BatchParameter,
    PercentEscape,
    Word,
    LeftParen,
    RightParen,
    Comma,
    Semicolon,
    Operator(Operator),
    Redirect(Redirect),
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
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokenization {
    pub tokens: Vec<Token>,
    pub diagnostics: Vec<Diagnostic>,
}

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn tokenize(source: &str) -> Tokenization {
    let mut result = Tokenization::default();
    let mut offset = 0;
    let mut line_start = true;
    let mut command_start = true;
    while offset < source.len() {
        let start = offset;
        let ch = next_char(source, offset);
        let kind = if line_start && source[start..].starts_with("::") {
            consume_to_newline(source, &mut offset);
            TokenKind::Comment
        } else if line_start && ch == ':' {
            consume_to_newline(source, &mut offset);
            TokenKind::Label
        } else if command_start && starts_rem_comment(source, start) {
            consume_to_newline(source, &mut offset);
            TokenKind::Comment
        } else {
            match ch {
                '\r' => {
                    offset += 1;
                    if source.as_bytes().get(offset) == Some(&b'\n') {
                        offset += 1;
                    }
                    TokenKind::Newline
                }
                '\n' => {
                    offset += 1;
                    TokenKind::Newline
                }
                ' ' | '\t' => {
                    offset += ch.len_utf8();
                    while offset < source.len() && matches!(next_char(source, offset), ' ' | '\t') {
                        offset += next_char(source, offset).len_utf8();
                    }
                    TokenKind::Whitespace
                }
                '"' => {
                    consume_quote(source, &mut offset);
                    TokenKind::QuotedString
                }
                '^' => consume_caret(source, &mut offset, start, &mut result.diagnostics),
                '%' => consume_percent(source, &mut offset),
                '!' => consume_variable(source, &mut offset, ch),
                '@' if command_start => {
                    offset += 1;
                    TokenKind::EchoControl
                }
                '(' => {
                    offset += 1;
                    TokenKind::LeftParen
                }
                ')' => {
                    offset += 1;
                    TokenKind::RightParen
                }
                ',' => {
                    offset += 1;
                    TokenKind::Comma
                }
                ';' => {
                    offset += 1;
                    TokenKind::Semicolon
                }
                '&' => {
                    offset += 1;
                    if source.as_bytes().get(offset) == Some(&b'&') {
                        offset += 1;
                        TokenKind::Operator(Operator::And)
                    } else {
                        TokenKind::Operator(Operator::Ampersand)
                    }
                }
                '|' => {
                    offset += 1;
                    if source.as_bytes().get(offset) == Some(&b'|') {
                        offset += 1;
                        TokenKind::Operator(Operator::Or)
                    } else {
                        TokenKind::Operator(Operator::Pipe)
                    }
                }
                '>' | '<' => consume_redirect(source, &mut offset, false),
                '0'..='9' if starts_redirect(source, offset) => {
                    while offset < source.len() && next_char(source, offset).is_ascii_digit() {
                        offset += 1;
                    }
                    consume_redirect(source, &mut offset, true)
                }
                _ => {
                    offset += ch.len_utf8();
                    consume_word(source, &mut offset);
                    TokenKind::Word
                }
            }
        };
        result.tokens.push(Token {
            kind,
            span: Span { start, end: offset },
        });
        match result.tokens.last().map(|token| &token.kind) {
            Some(TokenKind::Newline) => {
                line_start = true;
                command_start = true;
            }
            Some(TokenKind::Whitespace) => {}
            Some(TokenKind::EchoControl) if command_start => {
                line_start = false;
            }
            Some(TokenKind::Operator(_) | TokenKind::LeftParen) => {
                line_start = false;
                command_start = true;
            }
            _ => {
                line_start = false;
                command_start = false;
            }
        }
    }

    result
}

fn consume_to_newline(source: &str, offset: &mut usize) {
    while *offset < source.len() && !matches!(next_char(source, *offset), '\r' | '\n') {
        *offset += next_char(source, *offset).len_utf8();
    }
}

fn starts_rem_comment(source: &str, offset: usize) -> bool {
    source[offset..]
        .get(..3)
        .is_some_and(|value| value.eq_ignore_ascii_case("rem"))
        && source[offset + 3..]
            .chars()
            .next()
            .is_none_or(char::is_whitespace)
}

fn next_char(source: &str, offset: usize) -> char {
    source[offset..]
        .chars()
        .next()
        .expect("offset is in source")
}

fn consume_quote(source: &str, offset: &mut usize) {
    *offset += 1;
    while *offset < source.len() {
        let current = next_char(source, *offset);
        if matches!(current, '\r' | '\n') {
            return;
        }
        *offset += current.len_utf8();
        if current == '"' {
            return;
        }
    }
}

fn consume_caret(
    source: &str,
    offset: &mut usize,
    start: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> TokenKind {
    *offset += 1;
    if *offset == source.len() {
        diagnostics.push(Diagnostic {
            span: Span {
                start,
                end: *offset,
            },
            message: "trailing caret has no escaped character".into(),
        });
        TokenKind::CaretEscape
    } else if source[*offset..].starts_with("\r\n") {
        *offset += 2;
        TokenKind::LineContinuation
    } else if source.as_bytes().get(*offset) == Some(&b'\n') {
        *offset += 1;
        TokenKind::LineContinuation
    } else {
        *offset += next_char(source, *offset).len_utf8();
        TokenKind::CaretEscape
    }
}

fn consume_variable(source: &str, offset: &mut usize, delimiter: char) -> TokenKind {
    *offset += delimiter.len_utf8();
    if let Some(relative) = source[*offset..].find(delimiter) {
        *offset += relative + delimiter.len_utf8();
        if delimiter == '%' {
            TokenKind::PercentVariable
        } else {
            TokenKind::DelayedVariable
        }
    } else {
        consume_word(source, offset);
        TokenKind::Word
    }
}

fn consume_percent(source: &str, offset: &mut usize) -> TokenKind {
    *offset += 1;
    let Some(next) = source.get(*offset..).and_then(|value| value.chars().next()) else {
        return TokenKind::Word;
    };
    if next == '%' {
        *offset += 1;
        if source
            .get(*offset..)
            .and_then(|value| value.chars().next())
            .is_some_and(|character| character == '~' || character.is_ascii_alphanumeric())
        {
            consume_batch_reference_tail(source, offset);
            return TokenKind::ForVariable;
        }
        return TokenKind::PercentEscape;
    }
    if next == '~' || next.is_ascii_digit() || next == '*' {
        consume_batch_reference_tail(source, offset);
        return TokenKind::BatchParameter;
    }
    if let Some(relative) = source[*offset..].find('%') {
        *offset += relative + 1;
        return TokenKind::PercentVariable;
    }
    consume_word(source, offset);
    TokenKind::Word
}

fn consume_batch_reference_tail(source: &str, offset: &mut usize) {
    if source.as_bytes().get(*offset) == Some(&b'~') {
        *offset += 1;
        while *offset < source.len() {
            let character = next_char(source, *offset);
            if character.is_ascii_alphabetic() || matches!(character, '$' | ':' | '_') {
                *offset += character.len_utf8();
            } else {
                break;
            }
        }
    }
    if *offset < source.len() {
        *offset += next_char(source, *offset).len_utf8();
    }
}

fn starts_redirect(source: &str, mut offset: usize) -> bool {
    while offset < source.len() && next_char(source, offset).is_ascii_digit() {
        offset += 1;
    }
    matches!(source.as_bytes().get(offset), Some(b'>' | b'<'))
}

fn consume_redirect(source: &str, offset: &mut usize, numbered: bool) -> TokenKind {
    let operator = source.as_bytes().get(*offset).copied().unwrap_or(b'>');
    *offset += 1;
    if operator == b'>' && source.as_bytes().get(*offset) == Some(&b'>') {
        *offset += 1;
        return TokenKind::Redirect(Redirect::Append);
    }
    if operator == b'>' && source.as_bytes().get(*offset) == Some(&b'&') {
        *offset += 1;
        while *offset < source.len() && next_char(source, *offset).is_ascii_digit() {
            *offset += 1;
        }
        return TokenKind::Redirect(Redirect::Merge);
    }
    if operator == b'<' {
        TokenKind::Redirect(Redirect::Input)
    } else {
        let _ = numbered;
        TokenKind::Redirect(Redirect::Output)
    }
}

fn consume_word(source: &str, offset: &mut usize) {
    while *offset < source.len() {
        let ch = next_char(source, *offset);
        if ch.is_whitespace()
            || matches!(
                ch,
                '"' | '^' | '%' | '!' | '(' | ')' | ',' | ';' | '&' | '|' | '>' | '<'
            )
        {
            break;
        }
        if ch.is_ascii_digit() && starts_redirect(source, *offset) {
            break;
        }
        *offset += ch.len_utf8();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_complete(source: &str) -> Tokenization {
        let result = tokenize(source);
        let mut cursor = 0;
        for token in &result.tokens {
            assert_eq!(token.span.start, cursor);
            assert!(token.span.start < token.span.end);
            assert!(source.is_char_boundary(token.span.start));
            assert!(source.is_char_boundary(token.span.end));
            cursor = token.span.end;
        }
        assert_eq!(cursor, source.len());
        result
    }

    #[test]
    fn spans_cover_utf8_without_gaps() {
        assert_complete("echo héllo ^& 世界\r\n");
    }

    #[test]
    fn recognizes_quotes_carets_and_continuations() {
        let result = assert_complete("\"a b\" ^& ^\r\nnext");
        assert_eq!(result.tokens[0].kind, TokenKind::QuotedString);
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::CaretEscape));
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::LineContinuation));
    }

    #[test]
    fn recognizes_operators_variables_and_redirects() {
        let result = assert_complete("%A% && !B! || x 2>>err 1>&2 <in | y");
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::PercentVariable));
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::DelayedVariable));
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::Operator(Operator::And)));
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::Operator(Operator::Or)));
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::Redirect(Redirect::Append)));
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::Redirect(Redirect::Merge)));
    }

    #[test]
    fn recognizes_batch_parameters_and_for_variables() {
        let result = assert_complete("echo %0 %~dp0 %* %%A %%~fA %%");
        let kinds = result
            .tokens
            .iter()
            .filter(|token| !matches!(token.kind, TokenKind::Whitespace))
            .map(|token| token.kind.clone())
            .collect::<Vec<_>>();

        assert_eq!(
            kinds,
            [
                TokenKind::Word,
                TokenKind::BatchParameter,
                TokenKind::BatchParameter,
                TokenKind::BatchParameter,
                TokenKind::ForVariable,
                TokenKind::ForVariable,
                TokenKind::PercentEscape,
            ]
        );
    }

    #[test]
    fn recognizes_labels_comments_and_echo_control() {
        let result = assert_complete(" :start\r\n@rem hidden\r\n:: comment\r\necho shown");
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::Label));
        assert_eq!(
            result
                .tokens
                .iter()
                .filter(|token| token.kind == TokenKind::Comment)
                .count(),
            2
        );
        assert!(result
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::EchoControl));
    }

    #[test]
    fn unmatched_quote_stops_at_the_end_of_the_line() {
        let result = assert_complete("echo \"unfinished");
        assert!(result.diagnostics.is_empty());
        assert_eq!(result.tokens.last().unwrap().kind, TokenKind::QuotedString);
    }
}
