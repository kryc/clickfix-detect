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
    QuotedString,
    CaretEscape,
    LineContinuation,
    PercentVariable,
    DelayedVariable,
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
pub fn tokenize(source: &str) -> Tokenization {
    let mut result = Tokenization::default();
    let mut offset = 0;
    while offset < source.len() {
        let start = offset;
        let ch = next_char(source, offset);
        let kind = match ch {
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
                consume_quote(source, &mut offset, start, &mut result.diagnostics);
                TokenKind::QuotedString
            }
            '^' => consume_caret(source, &mut offset, start, &mut result.diagnostics),
            '%' | '!' => consume_variable(source, &mut offset, ch),
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
        };
        result.tokens.push(Token {
            kind,
            span: Span { start, end: offset },
        });
    }
    result
}

fn next_char(source: &str, offset: usize) -> char {
    source[offset..]
        .chars()
        .next()
        .expect("offset is in source")
}

fn consume_quote(
    source: &str,
    offset: &mut usize,
    start: usize,
    diagnostics: &mut Vec<Diagnostic>,
) {
    *offset += 1;
    while *offset < source.len() {
        let current = next_char(source, *offset);
        *offset += current.len_utf8();
        if current == '"' {
            return;
        }
    }
    diagnostics.push(Diagnostic {
        span: Span {
            start,
            end: *offset,
        },
        message: "unterminated quoted string".into(),
    });
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
    fn malformed_quote_is_diagnostic_but_still_tokenized() {
        let result = assert_complete("echo \"unfinished");
        assert_eq!(result.diagnostics.len(), 1);
    }
}
