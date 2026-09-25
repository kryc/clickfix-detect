use crate::tokenizer::{tokenize, Operator, Redirect, TokenKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainOperator {
    Always,
    OnSuccess,
    OnFailure,
    Pipe,
}

#[derive(Debug, Clone)]
pub(crate) struct ChainPart {
    pub operator: ChainOperator,
    pub command: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
    Stdin,
}

#[derive(Debug, Clone)]
pub(crate) struct Redirection {
    pub stream: Stream,
    pub target: String,
    pub append: bool,
    pub merge_to: Option<Stream>,
}

pub(crate) fn split_chain(source: &str) -> Vec<ChainPart> {
    let tokenization = tokenize(source);
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0_usize;
    let mut next_operator = ChainOperator::Always;
    for token in &tokenization.tokens {
        match token.kind {
            TokenKind::LeftParen => depth += 1,
            TokenKind::RightParen => depth = depth.saturating_sub(1),
            TokenKind::Operator(operator) if depth == 0 => {
                let command = source[start..token.span.start].trim();
                if !command.is_empty() {
                    parts.push(ChainPart {
                        operator: next_operator,
                        command: command.into(),
                    });
                }
                next_operator = match operator {
                    Operator::Ampersand => ChainOperator::Always,
                    Operator::And => ChainOperator::OnSuccess,
                    Operator::Or => ChainOperator::OnFailure,
                    Operator::Pipe => ChainOperator::Pipe,
                };
                start = token.span.end;
            }
            _ => {}
        }
    }
    let command = source[start..].trim();
    if !command.is_empty() {
        parts.push(ChainPart {
            operator: next_operator,
            command: command.into(),
        });
    }
    parts
}

pub(crate) fn parse_redirections(source: &str) -> (String, Vec<Redirection>) {
    let tokens = tokenize(source).tokens;
    let mut command = String::new();
    let mut redirections = Vec::new();
    let mut index = 0;
    let mut depth = 0_usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if token.kind == TokenKind::LeftParen {
            depth += 1;
        } else if token.kind == TokenKind::RightParen {
            depth = depth.saturating_sub(1);
        }
        let redirect = match token.kind {
            TokenKind::Redirect(kind) if depth == 0 => Some(kind),
            _ => None,
        };
        if let Some(kind) = redirect {
            let raw = token.text(source);
            if kind == Redirect::Merge {
                let from = raw
                    .chars()
                    .next()
                    .filter(char::is_ascii_digit)
                    .unwrap_or('1');
                let to = raw
                    .rsplit_once('&')
                    .and_then(|(_, value)| value.chars().next())
                    .unwrap_or('1');
                redirections.push(Redirection {
                    stream: digit_stream(from),
                    target: String::new(),
                    append: false,
                    merge_to: Some(digit_stream(to)),
                });
                index += 1;
                continue;
            }
            let stream = raw.chars().next().filter(char::is_ascii_digit).map_or_else(
                || {
                    if kind == Redirect::Input {
                        Stream::Stdin
                    } else {
                        Stream::Stdout
                    }
                },
                digit_stream,
            );
            index += 1;
            while index < tokens.len() && matches!(tokens[index].kind, TokenKind::Whitespace) {
                index += 1;
            }
            if index < tokens.len() {
                let target = unquote_and_unescape(tokens[index].text(source));
                redirections.push(Redirection {
                    stream,
                    target,
                    append: kind == Redirect::Append,
                    merge_to: None,
                });
                index += 1;
            }
            continue;
        }
        command.push_str(token.text(source));
        index += 1;
    }
    (command.trim().into(), redirections)
}

fn digit_stream(digit: char) -> Stream {
    match digit {
        '0' => Stream::Stdin,
        '2' => Stream::Stderr,
        _ => Stream::Stdout,
    }
}

pub(crate) fn split_words(source: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => quoted = !quoted,
            '^' => {
                if matches!(chars.peek(), Some('\r')) {
                    chars.next();
                    if matches!(chars.peek(), Some('\n')) {
                        chars.next();
                    }
                } else if matches!(chars.peek(), Some('\n')) {
                    chars.next();
                } else if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            ' ' | '\t' if !quoted => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

pub(crate) fn unquote_and_unescape(value: &str) -> String {
    split_words(value).into_iter().next().unwrap_or_default()
}

pub(crate) fn strip_outer_group(source: &str) -> Option<&str> {
    let trimmed = source.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return None;
    }
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, ch) in trimmed.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '^' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if quoted {
            continue;
        }
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 && offset + ch.len_utf8() != trimmed.len() {
                return None;
            }
        }
    }
    (depth == 0).then(|| &trimmed[1..trimmed.len() - 1])
}

pub(crate) fn command_and_rest(source: &str) -> (String, String) {
    let words = split_words(source);
    let Some(command) = words.first() else {
        return (String::new(), String::new());
    };
    let mut offset = 0;
    let bytes = source.as_bytes();
    while offset < bytes.len() && bytes[offset].is_ascii_whitespace() {
        offset += 1;
    }
    let start = offset;
    let mut quoted = false;
    let mut escaped = false;
    while offset < source.len() {
        let ch = source[offset..].chars().next().expect("valid offset");
        if escaped {
            escaped = false;
            offset += ch.len_utf8();
            continue;
        }
        if ch == '^' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if ch.is_whitespace() && !quoted {
            break;
        }
        offset += ch.len_utf8();
    }
    let _ = start;
    (command.clone(), source[offset..].trim_start().into())
}
