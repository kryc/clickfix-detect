use crate::parser::ParsedSource;
use crate::tokenizer::{CommentKind, Delimiter, Token, TokenKind};
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedirectStream {
    Success,
    Error,
    All,
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RedirectTarget {
    File(String),
    Merge(RedirectStream),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Redirection {
    pub(crate) stream: RedirectStream,
    pub(crate) append: bool,
    pub(crate) target: RedirectTarget,
}

pub(crate) fn parse_redirections<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, Vec<Redirection>)> {
    let window = parser.window(input)?;
    let mut nesting = TokenNesting::default();
    let mut operators = Vec::new();
    for token in window.tokens().iter().copied() {
        if nesting.is_top_level() && token.kind == TokenKind::Operator {
            if let Some(redirection) = parse_redirection_operator(token.text(window.source())) {
                operators.push((token.span, redirection));
            }
        }
        nesting.observe(token.kind);
    }
    let first = operators.first()?.0.start;
    let command = parser
        .text(crate::tokenizer::Span::new(window.span().start, first))
        .trim();
    if command.is_empty() {
        return None;
    }

    let mut redirections = Vec::new();
    for (index, (span, mut redirection)) in operators.iter().cloned().enumerate() {
        if matches!(redirection.target, RedirectTarget::File(ref path) if path.is_empty()) {
            let end = operators
                .get(index + 1)
                .map_or(window.span().end, |(next, _)| next.start);
            let target = parser
                .text(crate::tokenizer::Span::new(span.end, end))
                .trim();
            let target = split_powershell_words(parser, target)
                .first()
                .cloned()
                .unwrap_or_default();
            if target.is_empty() {
                continue;
            }
            redirection.target = RedirectTarget::File(target);
        }
        redirections.push(redirection);
    }
    (!redirections.is_empty()).then_some((command, redirections))
}

fn parse_redirection_operator(operator: &str) -> Option<Redirection> {
    if !operator.contains('>') {
        return None;
    }
    let stream = match operator.chars().next()? {
        '*' => RedirectStream::All,
        '2' => RedirectStream::Error,
        '3'..='9' => RedirectStream::Other(
            operator
                .chars()
                .next()?
                .to_digit(10)
                .and_then(|value| u8::try_from(value).ok())?,
        ),
        '1' | '>' => RedirectStream::Success,
        _ => return None,
    };
    let append = operator.contains(">>");
    let target = if let Some((_, target)) = operator.split_once(">&") {
        let stream = match target {
            "1" => RedirectStream::Success,
            "2" => RedirectStream::Error,
            "*" => RedirectStream::All,
            value => RedirectStream::Other(value.parse().ok()?),
        };
        RedirectTarget::Merge(stream)
    } else {
        RedirectTarget::File(String::new())
    };
    Some(Redirection {
        stream,
        append,
        target,
    })
}

pub(crate) fn split_assignment<'a>(
    parser: &'a ParsedSource,
    statement: &str,
) -> Option<(&'a str, &'a str)> {
    let window = parser.window(statement)?;
    let mut nesting = TokenNesting::default();
    for token in window.tokens().iter().copied() {
        if nesting.is_top_level()
            && token.kind == TokenKind::Operator
            && token.text(window.source()) == "="
        {
            let left = parser
                .text(crate::tokenizer::Span::new(
                    window.span().start,
                    token.span.start,
                ))
                .trim();
            let significant = parser
                .window(left)?
                .tokens()
                .iter()
                .copied()
                .filter(|candidate| !candidate.kind.is_trivia())
                .collect::<Vec<_>>();
            if significant.first().is_some_and(|candidate| {
                candidate.kind == TokenKind::Variable
                    || candidate.kind == TokenKind::Delimiter(Delimiter::LeftBracket)
            }) {
                return Some((
                    left,
                    parser
                        .text(crate::tokenizer::Span::new(
                            token.span.end,
                            window.span().end,
                        ))
                        .trim(),
                ));
            }
        }
        nesting.observe(token.kind);
    }
    None
}

pub(crate) fn split_compound_assignment<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str, &'a str)> {
    let window = parser.window(input)?;
    let mut nesting = TokenNesting::default();
    for token in window.tokens().iter().copied() {
        let operator = token.text(window.source());
        if nesting.is_top_level()
            && token.kind == TokenKind::Operator
            && matches!(operator, "+=" | "-=" | "*=" | "/=" | "%=")
        {
            let left = parser
                .text(crate::tokenizer::Span::new(
                    window.span().start,
                    token.span.start,
                ))
                .trim();
            let right = parser
                .text(crate::tokenizer::Span::new(
                    token.span.end,
                    window.span().end,
                ))
                .trim();
            if left.starts_with('$') {
                return Some((left, &operator[..1], right));
            }
        }
        nesting.observe(token.kind);
    }
    None
}

pub(crate) fn split_increment<'a>(parser: &ParsedSource, input: &'a str) -> Option<(&'a str, i64)> {
    let input = input.trim();
    for (operator, delta) in [("++", 1), ("--", -1)] {
        if let Some(variable) = input.strip_suffix(operator) {
            let variable = variable.trim();
            if is_variable(parser, variable) {
                return Some((variable, delta));
            }
        }
        if let Some(variable) = input.strip_prefix(operator) {
            let variable = variable.trim();
            if is_variable(parser, variable) {
                return Some((variable, delta));
            }
        }
    }
    None
}

pub(crate) fn split_key_value<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str)> {
    let window = parser.window(input)?;
    let mut nesting = TokenNesting::default();
    for token in window.tokens().iter().copied() {
        if nesting.is_top_level()
            && token.kind == TokenKind::Operator
            && token.text(window.source()) == "="
        {
            let key = parser
                .text(crate::tokenizer::Span::new(
                    window.span().start,
                    token.span.start,
                ))
                .trim();
            let value = parser
                .text(crate::tokenizer::Span::new(
                    token.span.end,
                    window.span().end,
                ))
                .trim();
            return (!key.is_empty()).then_some((key, value));
        }
        nesting.observe(token.kind);
    }
    None
}

pub(crate) fn parse_named_block<'a>(
    parser: &'a ParsedSource,
    statement: &'a str,
    keyword: &str,
) -> Option<(&'a str, &'a str)> {
    if !starts_word(statement, keyword) {
        return None;
    }
    let remainder = statement[keyword.len()..].trim_start();
    let brace = parser
        .window(remainder)?
        .tokens()
        .iter()
        .copied()
        .find(|token| token.kind == TokenKind::Delimiter(Delimiter::LeftBrace))?
        .span
        .start;
    let remainder_window = parser.window(remainder)?;
    let name = parser
        .text(crate::tokenizer::Span::new(
            remainder_window.span().start,
            brace,
        ))
        .trim();
    let block = parser.text(crate::tokenizer::Span::new(
        brace,
        remainder_window.span().end,
    ));
    let (body, _) = extract_delimited(parser, block, '{', '}')?;
    Some((name, body))
}

pub(crate) fn split_labeled_blocks<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Vec<(&'a str, &'a str)> {
    let mut blocks = Vec::new();
    let mut remainder = input;
    loop {
        let mut nesting = TokenNesting::default();
        let Some(window) = parser.window(remainder) else {
            break;
        };
        let brace = window.tokens().iter().copied().find(|token| {
            let top_level = nesting.is_top_level();
            let matched = top_level && token.kind == TokenKind::Delimiter(Delimiter::LeftBrace);
            nesting.observe(token.kind);
            matched
        });
        let Some(brace) = brace else {
            break;
        };
        let label = parser
            .text(crate::tokenizer::Span::new(
                window.span().start,
                brace.span.start,
            ))
            .trim();
        let block = parser.text(crate::tokenizer::Span::new(
            brace.span.start,
            window.span().end,
        ));
        let Some((body, after_body)) = extract_delimited(parser, block, '{', '}') else {
            break;
        };
        blocks.push((label, body));
        remainder = after_body.trim_start_matches([';', '\r', '\n', ' ']);
    }
    blocks
}

#[allow(dead_code)]
pub(crate) fn strip_comments<'a>(parser: &'a ParsedSource, input: &'a str) -> Cow<'a, str> {
    let Some(window) = parser.window(input) else {
        return Cow::Borrowed(input);
    };
    if !window.tokens().iter().any(|token| token.kind.is_comment()) {
        return Cow::Borrowed(input);
    }

    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    for token in window.tokens().iter().copied() {
        if token.kind.is_comment() {
            let start = token.span.start.saturating_sub(window.span().start);
            let end = token.span.end.saturating_sub(window.span().start);
            output.push_str(&input[cursor..start]);
            if matches!(token.kind, TokenKind::Comment(CommentKind::Block))
                && output
                    .chars()
                    .next_back()
                    .is_some_and(|character| !character.is_whitespace())
                && input[end..]
                    .chars()
                    .next()
                    .is_some_and(|character| !character.is_whitespace())
            {
                output.push(' ');
            }
            cursor = end;
        }
    }
    output.push_str(&input[cursor..]);
    Cow::Owned(output)
}

pub(crate) fn split_statements<'a>(parser: &'a ParsedSource, script: &str) -> Vec<&'a str> {
    let Some(window) = parser.window(script) else {
        return Vec::new();
    };
    let tokens = window.tokens();
    let mut parts = Vec::new();
    let mut start = window.span().start;
    let mut nesting = TokenNesting::default();
    let mut previous_significant = None;
    for (index, token) in tokens.iter().copied().enumerate() {
        let top_level = nesting.is_top_level();
        let split = if top_level && token.kind == TokenKind::Delimiter(Delimiter::Semicolon) {
            true
        } else if top_level && token.kind == TokenKind::NewLine {
            let continued_by_operator = previous_significant
                .is_some_and(|previous: Token| previous.kind == TokenKind::Operator);
            let next = tokens[index + 1..]
                .iter()
                .find(|candidate| {
                    !candidate.kind.is_trivia() && candidate.kind != TokenKind::NewLine
                })
                .copied();
            let continued_by_clause = next.is_some_and(|next| {
                let text = next.text(window.source());
                matches!(
                    text.to_ascii_lowercase().as_str(),
                    "else" | "elseif" | "catch" | "finally" | "until"
                ) || (text.eq_ignore_ascii_case("while")
                    && parser
                        .text(crate::tokenizer::Span::new(start, token.span.start))
                        .trim_start()
                        .to_ascii_lowercase()
                        .starts_with("do"))
            });
            !continued_by_operator && !continued_by_clause
        } else {
            false
        };
        if split {
            parts.push(parser.text(crate::tokenizer::Span::new(start, token.span.start)));
            start = token.span.end;
            previous_significant = None;
            continue;
        }
        if !token.kind.is_trivia() && token.kind != TokenKind::NewLine {
            previous_significant = Some(token);
        }
        nesting.observe(token.kind);
    }
    parts.push(parser.text(crate::tokenizer::Span::new(start, window.span().end)));
    parts
}

pub(crate) fn split_top_level<'a>(
    parser: &'a ParsedSource,
    input: &str,
    separator: char,
) -> Vec<&'a str> {
    split_top_level_many(parser, input, &[separator])
}

fn split_top_level_many<'a>(
    parser: &'a ParsedSource,
    input: &str,
    separators: &[char],
) -> Vec<&'a str> {
    let Some(window) = parser.window(input) else {
        return Vec::new();
    };
    let mut parts = Vec::new();
    let mut start = window.span().start;
    let mut nesting = TokenNesting::default();
    for token in window.tokens().iter().copied() {
        if nesting.is_top_level() && token_matches_separator(token, window.source(), separators) {
            parts.push(parser.text(crate::tokenizer::Span::new(start, token.span.start)));
            start = token.span.end;
            continue;
        }
        nesting.observe(token.kind);
    }
    parts.push(parser.text(crate::tokenizer::Span::new(start, window.span().end)));
    parts
}

pub(crate) fn split_powershell_words(parser: &ParsedSource, input: &str) -> Vec<String> {
    split_powershell_word_ranges(parser, input)
        .into_iter()
        .map(|range| clean_line_continuations(parser.text(range)))
        .collect()
}

pub(crate) fn split_powershell_word_ranges(
    parser: &ParsedSource,
    input: &str,
) -> Vec<crate::tokenizer::Span> {
    let Some(window) = parser.window(input) else {
        return Vec::new();
    };
    let mut words = Vec::new();
    let mut start = None;
    let mut end = window.span().start;
    let mut nesting = TokenNesting::default();
    for token in window.tokens().iter().copied() {
        let top_level_separator = nesting.is_top_level()
            && matches!(
                token.kind,
                TokenKind::Whitespace
                    | TokenKind::NewLine
                    | TokenKind::Comment(CommentKind::Block | CommentKind::Line)
            );
        if top_level_separator {
            if let Some(word_start) = start.take() {
                words.push(crate::tokenizer::Span::new(word_start, end));
            }
            if token.kind == TokenKind::Comment(CommentKind::Line) {
                break;
            }
            continue;
        }
        if start.is_none() && !token.kind.is_trivia() {
            start = Some(token.span.start);
        }
        if start.is_some() {
            end = token.span.end;
        }
        nesting.observe(token.kind);
    }
    if let Some(word_start) = start {
        words.push(crate::tokenizer::Span::new(word_start, end));
    }
    words
}

#[derive(Debug, Default, Clone, Copy)]
struct TokenNesting {
    parentheses: usize,
    brackets: usize,
    braces: usize,
}

impl TokenNesting {
    fn observe(&mut self, kind: TokenKind) {
        match kind {
            TokenKind::Delimiter(Delimiter::LeftParenthesis) => self.parentheses += 1,
            TokenKind::Delimiter(Delimiter::RightParenthesis) => {
                self.parentheses = self.parentheses.saturating_sub(1);
            }
            TokenKind::Delimiter(Delimiter::LeftBracket) => self.brackets += 1,
            TokenKind::Delimiter(Delimiter::RightBracket) => {
                self.brackets = self.brackets.saturating_sub(1);
            }
            TokenKind::Delimiter(Delimiter::LeftBrace) => self.braces += 1,
            TokenKind::Delimiter(Delimiter::RightBrace) => {
                self.braces = self.braces.saturating_sub(1);
            }
            _ => {}
        }
    }

    fn is_top_level(self) -> bool {
        self.parentheses == 0 && self.brackets == 0 && self.braces == 0
    }
}

pub(crate) fn extract_delimited<'a>(
    parser: &'a ParsedSource,
    input: &str,
    open: char,
    close: char,
) -> Option<(&'a str, &'a str)> {
    let input = input.trim_start();
    let window = parser.window_starting_at(input)?;
    let open_kind = delimiter_kind(open)?;
    let close_kind = delimiter_kind(close)?;
    let first = window
        .tokens()
        .iter()
        .find(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)?;
    if first.kind != open_kind {
        return None;
    }
    let mut depth = 0_usize;
    for token in window
        .tokens()
        .iter()
        .skip_while(|token| token.span.start < first.span.start)
    {
        if token.kind == open_kind {
            depth += 1;
        } else if token.kind == close_kind {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some((
                    parser.text(crate::tokenizer::Span::new(
                        first.span.end,
                        token.span.start,
                    )),
                    parser.text(crate::tokenizer::Span::new(
                        token.span.end,
                        window.span().end,
                    )),
                ));
            }
        }
    }
    None
}

pub(crate) fn strip_balanced_outer<'a>(
    parser: &'a ParsedSource,
    input: &str,
    open: char,
    close: char,
) -> Option<&'a str> {
    let (inner, remainder) = extract_delimited(parser, input, open, close)?;
    remainder.trim().is_empty().then_some(inner)
}

fn delimiter_kind(character: char) -> Option<TokenKind> {
    let delimiter = match character {
        '(' => Delimiter::LeftParenthesis,
        ')' => Delimiter::RightParenthesis,
        '{' => Delimiter::LeftBrace,
        '}' => Delimiter::RightBrace,
        '[' => Delimiter::LeftBracket,
        ']' => Delimiter::RightBracket,
        ',' => Delimiter::Comma,
        ';' => Delimiter::Semicolon,
        '.' => Delimiter::Dot,
        ':' => Delimiter::Colon,
        _ => return None,
    };
    Some(TokenKind::Delimiter(delimiter))
}

fn token_matches_separator(token: Token, input: &str, separators: &[char]) -> bool {
    match token.kind {
        TokenKind::NewLine => separators.contains(&'\n') || separators.contains(&'\r'),
        TokenKind::Delimiter(Delimiter::Semicolon) => separators.contains(&';'),
        TokenKind::Delimiter(Delimiter::Comma) => separators.contains(&','),
        TokenKind::Operator => token.text(input).chars().next().is_some_and(|character| {
            token.span.len() == character.len_utf8() && separators.contains(&character)
        }),
        _ => false,
    }
}

pub(crate) fn clean_line_continuations(input: &str) -> String {
    input.trim().replace("`\r\n", "").replace("`\n", "")
}

pub(crate) fn normalize_variable(input: &str) -> String {
    input
        .trim()
        .trim_start_matches('$')
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_lowercase()
}

pub(crate) fn is_variable(parser: &ParsedSource, input: &str) -> bool {
    let Some(window) = parser.window(input) else {
        return false;
    };
    let tokens = window
        .tokens()
        .iter()
        .copied()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
        .collect::<Vec<_>>();
    tokens.len() == 1 && tokens[0].kind == TokenKind::Variable
}

pub(crate) fn is_quoted(parser: &ParsedSource, input: &str) -> bool {
    let Some(window) = parser.window(input) else {
        return false;
    };
    let tokens = window
        .tokens()
        .iter()
        .copied()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
        .collect::<Vec<_>>();
    tokens.len() == 1 && matches!(tokens[0].kind, TokenKind::String(_))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum NumberLiteral {
    Integer(i64),
    Float(f64),
}

#[allow(clippy::cast_precision_loss)]
pub(crate) fn parse_number(input: &str) -> Option<NumberLiteral> {
    let normalized = input.trim().replace('_', "");
    let lowercase = normalized.to_ascii_lowercase();
    let (number, multiplier) = ["kb", "mb", "gb", "tb", "pb"]
        .iter()
        .enumerate()
        .find_map(|(index, suffix)| {
            lowercase.strip_suffix(suffix).map(|number| {
                let exponent = u32::try_from(index + 1).unwrap_or_default();
                (number, 1_024_i64.pow(exponent))
            })
        })
        .unwrap_or((lowercase.as_str(), 1));
    let number = number.trim_end_matches(['u', 'l', 'd', 'y', 's']);

    if let Some(hex) = number.strip_prefix("0x") {
        let value = i64::from_str_radix(hex, 16).ok()?;
        scale_integer(value, multiplier)
    } else if let Some(binary) = number.strip_prefix("0b") {
        let value = i64::from_str_radix(binary, 2).ok()?;
        scale_integer(value, multiplier)
    } else if number.contains(['.', 'e']) {
        number
            .parse::<f64>()
            .ok()
            .map(|value| NumberLiteral::Float(value * multiplier as f64))
    } else {
        let value = number.parse::<i64>().ok()?;
        scale_integer(value, multiplier)
    }
}

fn scale_integer(value: i64, multiplier: i64) -> Option<NumberLiteral> {
    if multiplier == 1 {
        Some(NumberLiteral::Integer(value))
    } else {
        value.checked_mul(multiplier).map(NumberLiteral::Integer)
    }
}

pub(crate) fn starts_word(input: &str, word: &str) -> bool {
    input
        .get(..word.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(word))
        && input[word.len()..]
            .chars()
            .next()
            .is_none_or(|character| character.is_whitespace() || "({".contains(character))
}

pub(crate) fn strip_prefix_case_insensitive<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    if let Some(prefix_remainder) = prefix.strip_prefix('-') {
        let first = input.chars().next()?;
        if is_powershell_dash(first) {
            let input_remainder = &input[first.len_utf8()..];
            return input_remainder
                .get(..prefix_remainder.len())
                .filter(|value| value.eq_ignore_ascii_case(prefix_remainder))
                .map(|_| &input_remainder[prefix_remainder.len()..]);
        }
    }
    input
        .get(..prefix.len())
        .filter(|value| value.eq_ignore_ascii_case(prefix))
        .map(|_| &input[prefix.len()..])
}

pub(crate) fn find_word_case_insensitive(input: &str, needle: &str) -> Option<usize> {
    input
        .to_ascii_lowercase()
        .find(&needle.to_ascii_lowercase())
}

pub(crate) fn find_top_level_binary<'a, 'b>(
    parser: &'a ParsedSource,
    input: &str,
    operators: &'b [&'b str],
) -> Option<(&'a str, &'b str, &'a str)> {
    let window = parser.window(input)?;
    let mut nesting = TokenNesting::default();
    let mut matches = Vec::new();
    let mut previous_significant = None;
    for token in window.tokens().iter().copied() {
        if nesting.is_top_level() && token.kind == TokenKind::Operator {
            let text = token.text(window.source());
            let normalized = normalize_operator(text);
            if let Some(operator) = operators
                .iter()
                .copied()
                .find(|operator| normalized.eq_ignore_ascii_case(operator))
            {
                let unary_sign = matches!(operator, "+" | "-")
                    && previous_significant.is_none_or(|previous: Token| {
                        previous.kind == TokenKind::Operator
                            || matches!(
                                previous.kind,
                                TokenKind::Delimiter(
                                    Delimiter::LeftParenthesis
                                        | Delimiter::LeftBracket
                                        | Delimiter::LeftBrace
                                        | Delimiter::Comma
                                        | Delimiter::Semicolon
                                )
                            )
                    });
                if !unary_sign {
                    matches.push((token.span.start, token.span.end, operator));
                }
            }
        }
        if !token.kind.is_trivia() && token.kind != TokenKind::NewLine {
            previous_significant = Some(token);
        }
        nesting.observe(token.kind);
    }
    let (start, end, operator) = matches.last().copied()?;
    let left = parser
        .text(crate::tokenizer::Span::new(window.span().start, start))
        .trim();
    let right = parser
        .text(crate::tokenizer::Span::new(end, window.span().end))
        .trim();
    (!left.is_empty() && !right.is_empty()).then_some((left, operator, right))
}

pub(crate) fn split_index_expression<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str)> {
    let input = input.trim();
    let window = parser.window(input)?;
    let significant = window
        .tokens()
        .iter()
        .copied()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
        .collect::<Vec<_>>();
    let last = *significant.last()?;
    if last.kind != TokenKind::Delimiter(Delimiter::RightBracket)
        || last.span.end != window.span().end
    {
        return None;
    }
    let mut depth = 0_usize;
    for token in significant.into_iter().rev() {
        if token.kind == TokenKind::Delimiter(Delimiter::RightBracket) {
            depth += 1;
        } else if token.kind == TokenKind::Delimiter(Delimiter::LeftBracket) {
            depth = depth.saturating_sub(1);
            if depth == 0 && token.span.start > window.span().start {
                return Some((
                    parser
                        .text(crate::tokenizer::Span::new(
                            window.span().start,
                            token.span.start,
                        ))
                        .trim(),
                    parser
                        .text(crate::tokenizer::Span::new(token.span.end, last.span.start))
                        .trim(),
                ));
            }
        }
    }
    None
}

pub(crate) fn parse_static_call<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str, &'a str)> {
    let input = input.trim();
    let window = parser.window(input)?;
    let significant = window
        .tokens()
        .iter()
        .copied()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
        .collect::<Vec<_>>();
    let first = *significant.first()?;
    if first.kind != TokenKind::Delimiter(Delimiter::LeftBracket) {
        return None;
    }

    let mut depth = 0_usize;
    let mut close_index = None;
    for (index, token) in significant.iter().enumerate() {
        match token.kind {
            TokenKind::Delimiter(Delimiter::LeftBracket) => depth += 1,
            TokenKind::Delimiter(Delimiter::RightBracket) => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    close_index = Some(index);
                    break;
                }
            }
            _ => {}
        }
    }
    let close_index = close_index?;
    let close = significant[close_index];
    let static_operator = significant.get(close_index + 1)?;
    if static_operator.kind != TokenKind::Operator || static_operator.text(window.source()) != "::"
    {
        return None;
    }
    let type_name = parser
        .text(crate::tokenizer::Span::new(
            first.span.end,
            close.span.start,
        ))
        .trim();
    let call = parser
        .text(crate::tokenizer::Span::new(
            static_operator.span.end,
            window.span().end,
        ))
        .trim_start();
    let open = find_call_open(parser, call)?;
    if !call.ends_with(')') {
        return None;
    }
    let call_window = parser.window(call)?;
    Some((
        type_name,
        parser
            .text(crate::tokenizer::Span::new(call_window.span().start, open))
            .trim(),
        parser.text(crate::tokenizer::Span::new(
            open + 1,
            call_window.span().end - 1,
        )),
    ))
}

pub(crate) fn parse_static_member_access(input: &str) -> Option<(&str, &str)> {
    let input = input.trim();
    if input.ends_with(')') {
        return None;
    }
    let close = input.find("]::")?;
    let type_name = input.get(1..close)?.trim();
    let member = input.get(close + 3..)?.trim();
    (!type_name.is_empty()
        && !member.is_empty()
        && member
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then_some((type_name, member))
}

pub(crate) fn parse_instance_call<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str, &'a str)> {
    if !input.ends_with(')') {
        return None;
    }
    let window = parser.window(input)?;
    let open = find_call_open(parser, input)?;
    let prefix = parser.text(crate::tokenizer::Span::new(window.span().start, open));
    let dot = find_last_top_level_dot(parser, prefix)?;
    Some((
        parser
            .text(crate::tokenizer::Span::new(window.span().start, dot))
            .trim(),
        parser
            .text(crate::tokenizer::Span::new(dot + 1, open))
            .trim(),
        parser.text(crate::tokenizer::Span::new(open + 1, window.span().end - 1)),
    ))
}

pub(crate) fn parse_member_access<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str)> {
    let window = parser.window(input)?;
    let dot = find_last_top_level_dot(parser, input)?;
    let receiver = parser
        .text(crate::tokenizer::Span::new(window.span().start, dot))
        .trim();
    let member = parser
        .text(crate::tokenizer::Span::new(dot + 1, window.span().end))
        .trim();
    (!receiver.is_empty()
        && !member.is_empty()
        && member
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then_some((receiver, member))
}

fn find_call_open(parser: &ParsedSource, input: &str) -> Option<usize> {
    let window = parser.window(input)?;
    let mut nesting = TokenNesting::default();
    for token in window.tokens().iter().copied() {
        if nesting.is_top_level() && token.kind == TokenKind::Delimiter(Delimiter::LeftParenthesis)
        {
            return Some(token.span.start);
        }
        nesting.observe(token.kind);
    }
    None
}

fn find_last_top_level_dot(parser: &ParsedSource, input: &str) -> Option<usize> {
    let window = parser.window(input)?;
    let mut nesting = TokenNesting::default();
    let mut result = None;
    for token in window.tokens().iter().copied() {
        if nesting.is_top_level() && token.kind == TokenKind::Delimiter(Delimiter::Dot) {
            result = Some(token.span.start);
        }
        nesting.observe(token.kind);
    }
    result
}

pub(crate) fn named_or_positional<'a>(
    arguments: &'a [String],
    names: &[&str],
    position: usize,
) -> Option<&'a str> {
    for (index, argument) in arguments.iter().enumerate() {
        if let Some(value) = inline_parameter_value(argument, names) {
            return Some(value);
        }
        if parameter_matches_any(argument, names) {
            return arguments.get(index + 1).map(String::as_str);
        }
    }
    if position == usize::MAX {
        None
    } else {
        positional_arguments(arguments).into_iter().nth(position)
    }
}

pub(crate) fn find_switch(arguments: &[String], name: &str) -> Option<usize> {
    arguments
        .iter()
        .position(|argument| parameter_matches_any(argument, &[name]))
}

fn parameter_matches_any(argument: &str, names: &[&str]) -> bool {
    let argument = normalize_parameter(argument);
    let argument = argument
        .split_once(':')
        .map_or(argument.as_ref(), |(name, _)| name)
        .to_ascii_lowercase();
    if !argument.starts_with('-') || argument.len() < 2 {
        return false;
    }
    let matches = names
        .iter()
        .filter(|name| name.to_ascii_lowercase().starts_with(&argument))
        .count();
    matches == 1
}

fn inline_parameter_value<'a>(argument: &'a str, names: &[&str]) -> Option<&'a str> {
    let (name, value) = argument.split_once(':')?;
    parameter_matches_any(name, names).then_some(value)
}

fn positional_arguments(arguments: &[String]) -> Vec<&str> {
    let mut positional = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument.chars().next().is_some_and(is_powershell_dash) {
            let normalized = normalize_parameter(argument);
            let name = normalized
                .split_once(':')
                .map_or(normalized.as_ref(), |(name, _)| name);
            if common_parameter_takes_value(name) && !argument.contains(':') {
                index += 2;
            } else {
                index += 1;
            }
        } else {
            positional.push(argument.as_str());
            index += 1;
        }
    }
    positional
}

fn normalize_operator(input: &str) -> Cow<'_, str> {
    let Some(first) = input.chars().next() else {
        return Cow::Borrowed(input);
    };
    if !is_powershell_dash(first) || first == '-' {
        return Cow::Borrowed(input);
    }
    Cow::Owned(format!("-{}", &input[first.len_utf8()..]))
}

fn normalize_parameter(input: &str) -> Cow<'_, str> {
    normalize_operator(input)
}

const fn is_powershell_dash(character: char) -> bool {
    matches!(character, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}')
}

fn common_parameter_takes_value(name: &str) -> bool {
    [
        "-erroraction",
        "-warningaction",
        "-informationaction",
        "-errorvariable",
        "-warningvariable",
        "-informationvariable",
        "-outvariable",
        "-outbuffer",
        "-pipelinevariable",
    ]
    .iter()
    .any(|parameter| parameter.starts_with(&name.to_ascii_lowercase()))
}

pub(crate) fn looks_like_script(input: &str) -> bool {
    let lowercase = input.to_ascii_lowercase();
    input.contains(';')
        || input.contains('\n')
        || lowercase.contains("invoke-")
        || lowercase.contains("set-content")
        || lowercase.contains("start-process")
        || lowercase.starts_with('$')
}

pub(crate) fn split_windows_command_line(input: &str) -> Vec<String> {
    let mut arguments = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut backslashes = 0;
    for character in input.chars() {
        match character {
            '\\' => backslashes += 1,
            '"' => {
                current.extend(std::iter::repeat_n('\\', backslashes / 2));
                if backslashes % 2 == 0 {
                    quoted = !quoted;
                } else {
                    current.push('"');
                }
                backslashes = 0;
            }
            character if character.is_whitespace() && !quoted => {
                current.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                if !current.is_empty() {
                    arguments.push(std::mem::take(&mut current));
                }
            }
            character => {
                current.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                current.push(character);
            }
        }
    }
    current.extend(std::iter::repeat_n('\\', backslashes));
    if !current.is_empty() {
        arguments.push(current);
    }
    arguments
}

pub(crate) fn quote_argument(input: &str) -> String {
    if input.contains(char::is_whitespace) || input.contains('"') {
        format!("\"{}\"", input.replace('"', "\\\""))
    } else {
        input.into()
    }
}

pub(crate) fn trim_url_punctuation(input: &str) -> String {
    input
        .trim_end_matches(|character: char| ".,;:)]}".contains(character))
        .into()
}
