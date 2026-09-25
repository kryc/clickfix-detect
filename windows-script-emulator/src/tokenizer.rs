use crate::ScriptLanguage;
use serde::{Deserialize, Serialize};
use std::ops::Range;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    Identifier,
    Keyword,
    Number,
    String,
    Comment,
    Whitespace,
    Newline,
    Operator,
    Delimiter,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Range<usize>,
}

impl Token {
    #[must_use]
    pub fn text<'a>(&self, source: &'a str) -> &'a str {
        &source[self.span.clone()]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub message: String,
    pub span: Range<usize>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokenization {
    pub tokens: Vec<Token>,
    pub diagnostics: Vec<Diagnostic>,
}

const KEYWORDS: &[&str] = &[
    "and",
    "as",
    "break",
    "case",
    "catch",
    "const",
    "continue",
    "dim",
    "do",
    "each",
    "else",
    "elseif",
    "end",
    "eval",
    "execute",
    "executeglobal",
    "exit",
    "false",
    "finally",
    "for",
    "function",
    "if",
    "in",
    "let",
    "loop",
    "mod",
    "new",
    "next",
    "not",
    "nothing",
    "null",
    "on",
    "or",
    "resume",
    "return",
    "select",
    "set",
    "sub",
    "then",
    "this",
    "throw",
    "true",
    "try",
    "undefined",
    "var",
    "wend",
    "while",
    "with",
    "xor",
];

/// Tokenizes JScript or VBScript while preserving every source byte in token spans.
#[must_use]
pub fn tokenize(source: &str, language: ScriptLanguage) -> Tokenization {
    let mut output = Tokenization::default();
    let mut offset = 0;
    while offset < source.len() {
        let start = offset;
        let Some(ch) = source[offset..].chars().next() else {
            break;
        };
        let kind = if matches!(ch, '\r' | '\n') {
            offset += ch.len_utf8();
            if ch == '\r' && source[offset..].starts_with('\n') {
                offset += 1;
            }
            TokenKind::Newline
        } else if ch.is_whitespace() {
            advance_while(source, &mut offset, |value| {
                value.is_whitespace() && !matches!(value, '\r' | '\n')
            });
            TokenKind::Whitespace
        } else if is_identifier_start(ch) {
            advance_while(source, &mut offset, is_identifier_continue);
            let word = &source[start..offset];
            if language == ScriptLanguage::VBScript
                && word.eq_ignore_ascii_case("rem")
                && is_vb_comment_boundary(source, offset)
            {
                advance_until_newline(source, &mut offset);
                TokenKind::Comment
            } else if KEYWORDS
                .iter()
                .any(|keyword| word.eq_ignore_ascii_case(keyword))
            {
                TokenKind::Keyword
            } else {
                TokenKind::Identifier
            }
        } else if language == ScriptLanguage::VBScript
            && ch == '&'
            && source[start..]
                .get(..2)
                .is_some_and(|value| value.eq_ignore_ascii_case("&h"))
        {
            offset += 2;
            advance_while(source, &mut offset, |value| value.is_ascii_hexdigit());
            TokenKind::Number
        } else if ch.is_ascii_digit() {
            offset += ch.len_utf8();
            if source[start..].starts_with("0x") || source[start..].starts_with("0X") {
                advance_while(source, &mut offset, |value| value.is_ascii_hexdigit());
            } else {
                let mut seen_exponent = false;
                let mut may_take_sign = false;
                while offset < source.len() {
                    let value = source[offset..].chars().next().expect("character exists");
                    if value.is_ascii_digit() || value == '.' {
                        may_take_sign = false;
                        offset += value.len_utf8();
                    } else if matches!(value, 'e' | 'E') && !seen_exponent {
                        seen_exponent = true;
                        may_take_sign = true;
                        offset += 1;
                    } else if matches!(value, '+' | '-') && may_take_sign {
                        may_take_sign = false;
                        offset += 1;
                    } else {
                        break;
                    }
                }
            }
            TokenKind::Number
        } else if matches!(ch, '\'' | '"') {
            if ch == '\'' && language == ScriptLanguage::VBScript {
                advance_until_newline(source, &mut offset);
                TokenKind::Comment
            } else {
                scan_string(source, &mut offset, ch, language, &mut output.diagnostics);
                TokenKind::String
            }
        } else if ch == '/' && source[start..].starts_with("//") {
            advance_until_newline(source, &mut offset);
            TokenKind::Comment
        } else if ch == '/' && source[start..].starts_with("/*") {
            offset += 2;
            if let Some(relative) = source[offset..].find("*/") {
                offset += relative + 2;
            } else {
                offset = source.len();
                output.diagnostics.push(Diagnostic {
                    message: "unterminated block comment".into(),
                    span: start..offset,
                });
            }
            TokenKind::Comment
        } else if "(){}[],:;.".contains(ch) {
            offset += ch.len_utf8();
            TokenKind::Delimiter
        } else if "+-*/%=&|!<>^~?".contains(ch) {
            offset += ch.len_utf8();
            while offset < source.len() {
                let next = source[offset..].chars().next().expect("character exists");
                if "=|&<>".contains(next) && offset - start < 3 {
                    offset += next.len_utf8();
                } else {
                    break;
                }
            }
            TokenKind::Operator
        } else {
            offset += ch.len_utf8();
            output.diagnostics.push(Diagnostic {
                message: format!("unrecognized character {ch:?}"),
                span: start..offset,
            });
            TokenKind::Unknown
        };
        output.tokens.push(Token {
            kind,
            span: start..offset,
        });
    }
    output
}

fn advance_while(source: &str, offset: &mut usize, predicate: impl Fn(char) -> bool) {
    while *offset < source.len() {
        let ch = source[*offset..].chars().next().expect("character exists");
        if !predicate(ch) {
            break;
        }
        *offset += ch.len_utf8();
    }
}

fn advance_until_newline(source: &str, offset: &mut usize) {
    advance_while(source, offset, |ch| !matches!(ch, '\r' | '\n'));
}

fn scan_string(
    source: &str,
    offset: &mut usize,
    quote: char,
    language: ScriptLanguage,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let start = *offset;
    *offset += quote.len_utf8();
    while *offset < source.len() {
        let ch = source[*offset..].chars().next().expect("character exists");
        *offset += ch.len_utf8();
        if ch == quote {
            if language == ScriptLanguage::VBScript
                && quote == '"'
                && source[*offset..].starts_with('"')
            {
                *offset += 1;
                continue;
            }
            return;
        }
        if language == ScriptLanguage::JScript && ch == '\\' && *offset < source.len() {
            let escaped = source[*offset..].chars().next().expect("character exists");
            *offset += escaped.len_utf8();
        }
    }
    diagnostics.push(Diagnostic {
        message: "unterminated string literal".into(),
        span: start..*offset,
    });
}

fn is_identifier_start(ch: char) -> bool {
    ch == '_' || ch == '$' || ch.is_alphabetic()
}

fn is_identifier_continue(ch: char) -> bool {
    is_identifier_start(ch) || ch.is_ascii_digit()
}

fn is_vb_comment_boundary(source: &str, offset: usize) -> bool {
    source[offset..]
        .chars()
        .next()
        .is_none_or(|ch| ch.is_whitespace() || ch == ':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invariants(source: &str, language: ScriptLanguage) {
        let result = tokenize(source, language);
        let mut cursor = 0;
        for token in result.tokens {
            assert_eq!(token.span.start, cursor);
            assert!(token.span.start < token.span.end);
            assert!(source.is_char_boundary(token.span.start));
            assert!(source.is_char_boundary(token.span.end));
            cursor = token.span.end;
        }
        assert_eq!(cursor, source.len());
    }

    #[test]
    fn spans_cover_jscript() {
        assert_invariants(
            "var π = \"a\\\\\\\"b\"; // comment\nx += 0x10;",
            ScriptLanguage::JScript,
        );
    }

    #[test]
    fn spans_cover_vbscript() {
        assert_invariants(
            "Dim x: x = \"a\"\"b\" ' comment\r\nRem another",
            ScriptLanguage::VBScript,
        );
    }

    #[test]
    fn reports_unterminated_constructs() {
        assert_eq!(
            tokenize("\"no", ScriptLanguage::JScript).diagnostics.len(),
            1
        );
        assert_eq!(
            tokenize("/* no", ScriptLanguage::JScript).diagnostics.len(),
            1
        );
    }
}
