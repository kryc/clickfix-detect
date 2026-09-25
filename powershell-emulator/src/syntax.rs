use crate::tokenizer::{tokenize, CommentKind, Delimiter, Token, TokenKind};
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

pub(crate) fn parse_redirections(input: &str) -> Option<(&str, Vec<Redirection>)> {
    let tokens = tokenize(input).tokens;
    let mut nesting = TokenNesting::default();
    let mut operators = Vec::new();
    for token in tokens {
        if nesting.is_top_level() && token.kind == TokenKind::Operator {
            if let Some(redirection) = parse_redirection_operator(token.text(input)) {
                operators.push((token.span, redirection));
            }
        }
        nesting.observe(token.kind);
    }
    let first = operators.first()?.0.start;
    let command = input[..first].trim();
    if command.is_empty() {
        return None;
    }

    let mut redirections = Vec::new();
    for (index, (span, mut redirection)) in operators.iter().cloned().enumerate() {
        if matches!(redirection.target, RedirectTarget::File(ref path) if path.is_empty()) {
            let end = operators
                .get(index + 1)
                .map_or(input.len(), |(next, _)| next.start);
            let target = input[span.end..end].trim();
            let target = split_powershell_words(target)
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

pub(crate) fn split_assignment(statement: &str) -> Option<(&str, &str)> {
    let tokenization = tokenize(statement);
    let mut nesting = TokenNesting::default();
    for token in tokenization.tokens {
        if nesting.is_top_level()
            && token.kind == TokenKind::Operator
            && token.text(statement) == "="
        {
            let left = statement[..token.span.start].trim();
            let significant = tokenize(left)
                .tokens
                .into_iter()
                .filter(|candidate| !candidate.kind.is_trivia())
                .collect::<Vec<_>>();
            if significant.first().is_some_and(|candidate| {
                candidate.kind == TokenKind::Variable
                    || candidate.kind == TokenKind::Delimiter(Delimiter::LeftBracket)
            }) {
                return Some((left, statement[token.span.end..].trim()));
            }
        }
        nesting.observe(token.kind);
    }
    None
}

pub(crate) fn split_compound_assignment(input: &str) -> Option<(&str, &str, &str)> {
    let mut nesting = TokenNesting::default();
    for token in tokenize(input).tokens {
        let operator = token.text(input);
        if nesting.is_top_level()
            && token.kind == TokenKind::Operator
            && matches!(operator, "+=" | "-=" | "*=" | "/=" | "%=")
        {
            let left = input[..token.span.start].trim();
            let right = input[token.span.end..].trim();
            if left.starts_with('$') {
                return Some((left, &operator[..1], right));
            }
        }
        nesting.observe(token.kind);
    }
    None
}

pub(crate) fn split_increment(input: &str) -> Option<(&str, i64)> {
    let input = input.trim();
    for (operator, delta) in [("++", 1), ("--", -1)] {
        if let Some(variable) = input.strip_suffix(operator) {
            let variable = variable.trim();
            if is_variable(variable) {
                return Some((variable, delta));
            }
        }
        if let Some(variable) = input.strip_prefix(operator) {
            let variable = variable.trim();
            if is_variable(variable) {
                return Some((variable, delta));
            }
        }
    }
    None
}

pub(crate) fn split_key_value(input: &str) -> Option<(&str, &str)> {
    let mut nesting = TokenNesting::default();
    for token in tokenize(input).tokens {
        if nesting.is_top_level() && token.kind == TokenKind::Operator && token.text(input) == "=" {
            let key = input[..token.span.start].trim();
            let value = input[token.span.end..].trim();
            return (!key.is_empty()).then_some((key, value));
        }
        nesting.observe(token.kind);
    }
    None
}

pub(crate) fn parse_named_block<'a>(
    statement: &'a str,
    keyword: &str,
) -> Option<(&'a str, &'a str)> {
    if !starts_word(statement, keyword) {
        return None;
    }
    let remainder = statement[keyword.len()..].trim_start();
    let brace = tokenize(remainder)
        .tokens
        .into_iter()
        .find(|token| token.kind == TokenKind::Delimiter(Delimiter::LeftBrace))?
        .span
        .start;
    let name = remainder[..brace].trim();
    let (body, _) = extract_delimited(&remainder[brace..], '{', '}')?;
    Some((name, body))
}

pub(crate) fn split_labeled_blocks(input: &str) -> Vec<(&str, &str)> {
    let mut blocks = Vec::new();
    let mut remainder = input;
    loop {
        let mut nesting = TokenNesting::default();
        let brace = tokenize(remainder).tokens.into_iter().find(|token| {
            let top_level = nesting.is_top_level();
            let matched = top_level && token.kind == TokenKind::Delimiter(Delimiter::LeftBrace);
            nesting.observe(token.kind);
            matched
        });
        let Some(brace) = brace else {
            break;
        };
        let label = remainder[..brace.span.start].trim();
        let Some((body, after_body)) = extract_delimited(&remainder[brace.span.start..], '{', '}')
        else {
            break;
        };
        blocks.push((label, body));
        remainder = after_body.trim_start_matches([';', '\r', '\n', ' ']);
    }
    blocks
}

pub(crate) fn strip_comments(input: &str) -> Cow<'_, str> {
    let tokenization = tokenize(input);
    if !tokenization
        .tokens
        .iter()
        .any(|token| token.kind.is_comment())
    {
        return Cow::Borrowed(input);
    }

    let mut output = String::with_capacity(input.len());
    let mut cursor = 0;
    for token in tokenization.tokens {
        if token.kind.is_comment() {
            output.push_str(&input[cursor..token.span.start]);
            if matches!(token.kind, TokenKind::Comment(CommentKind::Block))
                && output
                    .chars()
                    .next_back()
                    .is_some_and(|character| !character.is_whitespace())
                && input[token.span.end..]
                    .chars()
                    .next()
                    .is_some_and(|character| !character.is_whitespace())
            {
                output.push(' ');
            }
            cursor = token.span.end;
        }
    }
    output.push_str(&input[cursor..]);
    Cow::Owned(output)
}

pub(crate) fn split_statements(script: &str) -> Vec<&str> {
    let tokens = tokenize(script).tokens;
    let mut parts = Vec::new();
    let mut start = 0;
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
                let text = next.text(script);
                matches!(
                    text.to_ascii_lowercase().as_str(),
                    "else" | "elseif" | "catch" | "finally" | "until"
                ) || (text.eq_ignore_ascii_case("while")
                    && script[start..token.span.start]
                        .trim_start()
                        .to_ascii_lowercase()
                        .starts_with("do"))
            });
            !continued_by_operator && !continued_by_clause
        } else {
            false
        };
        if split {
            parts.push(&script[start..token.span.start]);
            start = token.span.end;
            previous_significant = None;
            continue;
        }
        if !token.kind.is_trivia() && token.kind != TokenKind::NewLine {
            previous_significant = Some(token);
        }
        nesting.observe(token.kind);
    }
    parts.push(&script[start..]);
    parts
}

pub(crate) fn split_top_level(input: &str, separator: char) -> Vec<&str> {
    split_top_level_many(input, &[separator])
}

fn split_top_level_many<'a>(input: &'a str, separators: &[char]) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut nesting = TokenNesting::default();
    for token in tokenize(input).tokens {
        if nesting.is_top_level() && token_matches_separator(token, input, separators) {
            parts.push(&input[start..token.span.start]);
            start = token.span.end;
            continue;
        }
        nesting.observe(token.kind);
    }
    parts.push(&input[start..]);
    parts
}

pub(crate) fn split_powershell_words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut start = None;
    let mut end = 0;
    let mut nesting = TokenNesting::default();
    for token in tokenize(input).tokens {
        let top_level_separator = nesting.is_top_level()
            && matches!(
                token.kind,
                TokenKind::Whitespace
                    | TokenKind::NewLine
                    | TokenKind::Comment(CommentKind::Block | CommentKind::Line)
            );
        if top_level_separator {
            if let Some(word_start) = start.take() {
                words.push(clean_line_continuations(&input[word_start..end]));
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
        words.push(clean_line_continuations(&input[word_start..end]));
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

pub(crate) fn extract_delimited(input: &str, open: char, close: char) -> Option<(&str, &str)> {
    let input = input.trim_start();
    let open_kind = delimiter_kind(open)?;
    let close_kind = delimiter_kind(close)?;
    let tokens = tokenize(input).tokens;
    let first = tokens
        .iter()
        .find(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)?;
    if first.kind != open_kind {
        return None;
    }
    let mut depth = 0_usize;
    for token in tokens
        .iter()
        .skip_while(|token| token.span.start < first.span.start)
    {
        if token.kind == open_kind {
            depth += 1;
        } else if token.kind == close_kind {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some((
                    &input[first.span.end..token.span.start],
                    &input[token.span.end..],
                ));
            }
        }
    }
    None
}

pub(crate) fn strip_balanced_outer(input: &str, open: char, close: char) -> Option<&str> {
    let (inner, remainder) = extract_delimited(input, open, close)?;
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

fn clean_line_continuations(input: &str) -> String {
    input.trim().replace("`\r\n", "").replace("`\n", "")
}

pub(crate) fn normalize_variable(input: &str) -> String {
    input
        .trim()
        .trim_start_matches('$')
        .trim_start_matches('{')
        .trim_end_matches('}')
        .to_ascii_lowercase()
}

pub(crate) fn is_variable(input: &str) -> bool {
    let tokens = tokenize(input)
        .tokens
        .into_iter()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
        .collect::<Vec<_>>();
    tokens.len() == 1 && tokens[0].kind == TokenKind::Variable
}

pub(crate) fn is_quoted(input: &str) -> bool {
    let tokens = tokenize(input)
        .tokens
        .into_iter()
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
    input: &'a str,
    operators: &'b [&'b str],
) -> Option<(&'a str, &'b str, &'a str)> {
    let mut nesting = TokenNesting::default();
    let mut matches = Vec::new();
    let mut previous_significant = None;
    for token in tokenize(input).tokens {
        if nesting.is_top_level() && token.kind == TokenKind::Operator {
            let text = token.text(input);
            if let Some(operator) = operators
                .iter()
                .copied()
                .find(|operator| text.eq_ignore_ascii_case(operator))
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
    let left = input[..start].trim();
    let right = input[end..].trim();
    (!left.is_empty() && !right.is_empty()).then_some((left, operator, right))
}

pub(crate) fn split_index_expression(input: &str) -> Option<(&str, &str)> {
    let input = input.trim();
    let significant = tokenize(input)
        .tokens
        .into_iter()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
        .collect::<Vec<_>>();
    let last = *significant.last()?;
    if last.kind != TokenKind::Delimiter(Delimiter::RightBracket) || last.span.end != input.len() {
        return None;
    }
    let mut depth = 0_usize;
    for token in significant.into_iter().rev() {
        if token.kind == TokenKind::Delimiter(Delimiter::RightBracket) {
            depth += 1;
        } else if token.kind == TokenKind::Delimiter(Delimiter::LeftBracket) {
            depth = depth.saturating_sub(1);
            if depth == 0 && token.span.start > 0 {
                return Some((
                    input[..token.span.start].trim(),
                    input[token.span.end..last.span.start].trim(),
                ));
            }
        }
    }
    None
}

pub(crate) fn parse_static_call(input: &str) -> Option<(String, String, String)> {
    let input = input.trim();
    let significant = tokenize(input)
        .tokens
        .into_iter()
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
    if static_operator.kind != TokenKind::Operator || static_operator.text(input) != "::" {
        return None;
    }
    let type_name = input[first.span.end..close.span.start].trim().to_string();
    let call = input[static_operator.span.end..].trim_start();
    let open = find_call_open(call)?;
    if !call.ends_with(')') {
        return None;
    }
    Some((
        type_name,
        call[..open].trim().to_string(),
        call[open + 1..call.len() - 1].to_string(),
    ))
}

pub(crate) fn parse_static_member_access(input: &str) -> Option<(String, String)> {
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
    .then(|| (type_name.into(), member.into()))
}

pub(crate) fn parse_instance_call(input: &str) -> Option<(&str, String, String)> {
    if !input.ends_with(')') {
        return None;
    }
    let open = find_call_open(input)?;
    let prefix = &input[..open];
    let dot = find_last_top_level_dot(prefix)?;
    Some((
        prefix[..dot].trim(),
        prefix[dot + 1..].trim().to_string(),
        input[open + 1..input.len() - 1].to_string(),
    ))
}

pub(crate) fn parse_member_access(input: &str) -> Option<(&str, &str)> {
    let dot = find_last_top_level_dot(input)?;
    let receiver = input[..dot].trim();
    let member = input[dot + 1..].trim();
    (!receiver.is_empty()
        && !member.is_empty()
        && member
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'))
    .then_some((receiver, member))
}

fn find_call_open(input: &str) -> Option<usize> {
    let mut nesting = TokenNesting::default();
    for token in tokenize(input).tokens {
        if nesting.is_top_level() && token.kind == TokenKind::Delimiter(Delimiter::LeftParenthesis)
        {
            return Some(token.span.start);
        }
        nesting.observe(token.kind);
    }
    None
}

fn find_last_top_level_dot(input: &str) -> Option<usize> {
    let mut nesting = TokenNesting::default();
    let mut result = None;
    for token in tokenize(input).tokens {
        if nesting.is_top_level() && token.kind == TokenKind::Delimiter(Delimiter::Dot) {
            result = Some(token.span.start);
        }
        nesting.observe(token.kind);
    }
    result
}

pub(crate) fn named_or_positional(
    arguments: &[String],
    names: &[&str],
    position: usize,
) -> Option<String> {
    for (index, argument) in arguments.iter().enumerate() {
        if let Some(value) = inline_parameter_value(argument, names) {
            return Some(value);
        }
        if parameter_matches_any(argument, names) {
            return arguments.get(index + 1).cloned();
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
    let argument = argument
        .split_once(':')
        .map_or(argument, |(name, _)| name)
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

fn inline_parameter_value(argument: &str, names: &[&str]) -> Option<String> {
    let (name, value) = argument.split_once(':')?;
    parameter_matches_any(name, names).then(|| value.into())
}

fn positional_arguments(arguments: &[String]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument.starts_with('-') {
            let name = argument
                .split_once(':')
                .map_or(argument.as_str(), |(name, _)| name);
            if common_parameter_takes_value(name) && !argument.contains(':') {
                index += 2;
            } else {
                index += 1;
            }
        } else {
            positional.push(argument.clone());
            index += 1;
        }
    }
    positional
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
