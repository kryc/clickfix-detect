use crate::ast::{
    ChainPart, Command, CommandKind, ForCommand, ForMode, ForTextOptions, IfCommand, IfCondition,
    Program, Redirection,
};
use crate::syntax::{ChainOperator, Stream};
use crate::tokenizer::{tokenize, Diagnostic, Operator, Redirect, Span, Token, TokenKind};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct ParsedDocument {
    source: Arc<str>,
    tokens: Arc<[Token]>,
    diagnostics: Arc<[Diagnostic]>,
    program: Arc<Program>,
}

impl ParsedDocument {
    pub(crate) fn parse(source: &str) -> Self {
        let tokenization = tokenize(source);
        let mut document = Self {
            source: Arc::from(source),
            tokens: Arc::from(tokenization.tokens),
            diagnostics: Arc::from(tokenization.diagnostics),
            program: Arc::new(Program { parts: Vec::new() }),
        };
        document.program = Arc::new(parse_program(&document));
        document
    }

    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    pub(crate) fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    pub(crate) fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub(crate) fn program(&self) -> &Program {
        &self.program
    }

    pub(crate) fn is_non_executable(&self) -> bool {
        self.tokens
            .iter()
            .any(|token| matches!(token.kind, TokenKind::Label | TokenKind::Comment))
    }

    pub(crate) fn label(&self) -> Option<String> {
        let token = self
            .tokens
            .iter()
            .find(|token| token.kind == TokenKind::Label)?;
        let label = token
            .text(self.source())
            .trim()
            .trim_start_matches(':')
            .split_whitespace()
            .next()
            .unwrap_or_default();
        (!label.is_empty()).then(|| label.to_ascii_lowercase())
    }

    pub(crate) fn text(&self, span: Span) -> &str {
        &self.source[span.start..span.end]
    }

    pub(crate) fn tokens_in(&self, span: Span) -> &[Token] {
        let first = self
            .tokens
            .partition_point(|token| token.span.start < span.start);
        let end = self
            .tokens
            .partition_point(|token| token.span.end <= span.end)
            .max(first);
        &self.tokens[first..end]
    }
}

fn parse_program(document: &ParsedDocument) -> Program {
    let range = Span {
        start: 0,
        end: document.source.len(),
    };
    parse_program_range(document, range)
}

fn parse_program_range(document: &ParsedDocument, range: Span) -> Program {
    let mut parts = Vec::new();
    let mut start = range.start;
    let mut depth = 0_usize;
    let mut next_operator = ChainOperator::Always;
    for token in document.tokens_in(range) {
        match token.kind {
            TokenKind::LeftParen => depth += 1,
            TokenKind::RightParen => depth = depth.saturating_sub(1),
            TokenKind::Operator(operator) if depth == 0 => {
                if let Some(command) =
                    parse_command(document, trim_range(document, start, token.span.start))
                {
                    parts.push(ChainPart {
                        operator: next_operator,
                        command,
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
    if let Some(command) = parse_command(document, trim_range(document, start, range.end)) {
        parts.push(ChainPart {
            operator: next_operator,
            command,
        });
    }
    Program { parts }
}

fn parse_command(document: &ParsedDocument, range: Span) -> Option<Command> {
    if range.start >= range.end {
        return None;
    }
    let tokens = document.tokens_in(range);
    let mut redirections = Vec::new();
    let mut excluded = Vec::<Span>::new();
    let mut index = 0;
    let mut depth = 0_usize;
    while index < tokens.len() {
        let token = &tokens[index];
        match token.kind {
            TokenKind::LeftParen => depth += 1,
            TokenKind::RightParen => depth = depth.saturating_sub(1),
            _ => {}
        }
        let TokenKind::Redirect(kind) = token.kind else {
            index += 1;
            continue;
        };
        if depth != 0 {
            index += 1;
            continue;
        }
        let raw = token.text(document.source());
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
                target: None,
                append: false,
                merge_to: Some(digit_stream(to)),
            });
            excluded.push(token.span);
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
        let mut target_index = index + 1;
        while target_index < tokens.len()
            && matches!(tokens[target_index].kind, TokenKind::Whitespace)
        {
            target_index += 1;
        }
        let target = tokens.get(target_index).map(|target| target.span);
        let excluded_end = target.map_or(token.span.end, |target| target.end);
        excluded.push(Span {
            start: token.span.start,
            end: excluded_end,
        });
        redirections.push(Redirection {
            stream,
            target,
            append: kind == Redirect::Append,
            merge_to: None,
        });
        index = target_index.saturating_add(1);
    }
    let core_ranges = complement_ranges(range, &excluded)
        .into_iter()
        .map(|range| trim_range(document, range.start, range.end))
        .filter(|range| range.start < range.end)
        .collect::<Vec<_>>();
    let group = core_ranges
        .iter()
        .find_map(|range| outer_group(document, *range))
        .map(|body| Box::new(parse_program_range(document, body)));
    let kind = if group.is_none() && core_ranges.len() == 1 {
        parse_if(document, core_ranges[0])
            .map(CommandKind::If)
            .or_else(|| parse_for(document, core_ranges[0]).map(CommandKind::For))
            .unwrap_or_else(|| parse_simple_command(document, &core_ranges))
    } else {
        parse_simple_command(document, &core_ranges)
    };
    Some(Command {
        core_ranges,
        redirections,
        group,
        kind,
    })
}

fn parse_simple_command(document: &ParsedDocument, ranges: &[Span]) -> CommandKind {
    let words = split_word_ranges(document, ranges);
    CommandKind::Simple {
        command: words.first().copied().unwrap_or(Span { start: 0, end: 0 }),
        arguments: words.get(1..).unwrap_or_default().to_vec(),
    }
}

fn split_word_ranges(document: &ParsedDocument, ranges: &[Span]) -> Vec<Span> {
    let mut words = Vec::new();
    for range in ranges {
        let mut start = None;
        let mut end = range.start;
        for token in document.tokens_in(*range) {
            if matches!(token.kind, TokenKind::Comment) {
                break;
            }
            if matches!(token.kind, TokenKind::EchoControl) && start.is_none() {
                continue;
            }
            if matches!(token.kind, TokenKind::Whitespace | TokenKind::Newline) {
                if let Some(word_start) = start.take() {
                    words.push(Span {
                        start: word_start,
                        end,
                    });
                }
                continue;
            }
            if start.is_none() {
                start = Some(token.span.start);
            }
            end = token.span.end;
        }
        if let Some(word_start) = start {
            words.push(Span {
                start: word_start,
                end,
            });
        }
    }
    words
}

fn parse_if(document: &ParsedDocument, range: Span) -> Option<IfCommand> {
    let mut rest = trim_range(document, range.start, range.end);
    if document.text(rest).starts_with('@') {
        rest.start += 1;
        rest = trim_range(document, rest.start, rest.end);
    }

    rest = strip_word(document, rest, "if")?;
    let mut ignore_case = false;
    if let Some(after) = strip_word(document, rest, "/i") {
        ignore_case = true;
        rest = after;
    }
    let mut negate = false;
    if let Some(after) = strip_word(document, rest, "not") {
        negate = true;
        rest = after;
    }
    let (condition, command) = parse_if_condition(document, rest)?;
    let (then_range, else_range) = split_else(document, command);
    Some(IfCommand {
        ignore_case,
        negate,
        condition,
        then_program: Box::new(parse_program_range(document, then_range)),
        else_program: else_range.map(|range| Box::new(parse_program_range(document, range))),
    })
}

fn parse_for(document: &ParsedDocument, range: Span) -> Option<ForCommand> {
    let mut rest = trim_range(document, range.start, range.end);
    if document.text(rest).starts_with('@') {
        rest.start += 1;
        rest = trim_range(document, rest.start, rest.end);
    }
    rest = strip_word(document, rest, "for")?;
    let mut mode_name = "";
    if document.text(rest).starts_with('/') {
        let (mode, after) = take_word(document, rest)?;
        mode_name = document.text(mode);
        rest = after;
    }
    let mut options = String::new();
    let mut parsed_variable = None;
    if mode_name.eq_ignore_ascii_case("/f") && document.text(rest).starts_with('"') {
        let (value, after) = take_word(document, rest)?;
        options = document.text(value).trim_matches('"').into();
        rest = after;
    } else if mode_name.eq_ignore_ascii_case("/f") {
        loop {
            let (value, after) = take_word(document, rest)?;
            let text = document.text(value);
            if text.starts_with('%') {
                parsed_variable = Some((value, after));
                break;
            }
            if !is_for_text_option(text) {
                break;
            }
            if !options.is_empty() {
                options.push(' ');
            }
            options.push_str(text);
            rest = after;
        }
    }
    let (mut variable, mut after) = parsed_variable.unwrap_or(take_word(document, rest)?);
    let mut root = None;
    if mode_name.eq_ignore_ascii_case("/r") && !document.text(variable).starts_with('%') {
        root = Some(variable);
        (variable, after) = take_word(document, after)?;
    }
    let variable = document
        .text(variable)
        .trim_start_matches('%')
        .chars()
        .next()?
        .to_ascii_uppercase();
    rest = strip_word(document, after, "in")?;
    let (set, after_set) = take_parenthesized(document, rest)?;
    rest = strip_word(document, after_set, "do")?;
    let mode = if mode_name.eq_ignore_ascii_case("/l") {
        ForMode::Linear
    } else if mode_name.eq_ignore_ascii_case("/r") {
        ForMode::Recursive { root }
    } else if mode_name.eq_ignore_ascii_case("/f") {
        ForMode::Text {
            options: parse_for_text_options(&options),
        }
    } else {
        ForMode::Simple
    };
    Some(ForCommand {
        mode,
        variable,
        set,
        body: Box::new(parse_program_range(document, rest)),
    })
}

fn is_for_text_option(value: &str) -> bool {
    ["tokens=", "delims=", "skip=", "eol="]
        .iter()
        .any(|option| value.to_ascii_lowercase().starts_with(option))
}

fn parse_for_text_options(source: &str) -> ForTextOptions {
    let mut options = ForTextOptions {
        tokens: vec![1],
        remainder: false,
        delimiters: " \t".into(),
        skip: 0,
        eol: Some(';'),
    };
    for option in crate::syntax::split_words(source) {
        let lower = option.to_ascii_lowercase();
        if lower.starts_with("tokens=") {
            let value = &option["tokens=".len()..];
            options.tokens.clear();
            for token in value.split(',') {
                if token == "*" {
                    options.remainder = true;
                } else if let Ok(index) = token.parse() {
                    options.tokens.push(index);
                }
            }
        } else if lower.starts_with("delims=") {
            options.delimiters = option["delims=".len()..].into();
        } else if lower.starts_with("skip=") {
            options.skip = option["skip=".len()..].parse().unwrap_or(0);
        } else if lower.starts_with("eol=") {
            options.eol = option["eol=".len()..].chars().next();
        }
    }
    options
}

fn take_parenthesized(document: &ParsedDocument, range: Span) -> Option<(Span, Span)> {
    let range = trim_range(document, range.start, range.end);
    let source = document.text(range);
    let after_open = source.strip_prefix('(')?;
    let content_start = range.start + 1;
    let mut depth = 1_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, character) in after_open.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '^' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == '(' {
            depth += 1;
        } else if !quoted && character == ')' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                let close = content_start + offset;
                return Some((
                    Span {
                        start: content_start,
                        end: close,
                    },
                    trim_range(document, close + 1, range.end),
                ));
            }
        }
    }
    None
}

fn parse_if_condition(document: &ParsedDocument, range: Span) -> Option<(IfCondition, Span)> {
    if let Some(rest) = strip_word(document, range, "errorlevel") {
        let (value, command) = take_word(document, rest)?;
        return Some((IfCondition::ErrorLevel(value), command));
    }
    if let Some(rest) = strip_word(document, range, "exist") {
        let (path, command) = take_word(document, rest)?;
        return Some((IfCondition::Exist(path), command));
    }
    if let Some(rest) = strip_word(document, range, "defined") {
        let (name, command) = take_word(document, rest)?;
        return Some((IfCondition::Defined(name), command));
    }
    if let Some(equal) = find_unquoted(document, range, "==") {
        let left = trim_range(document, range.start, equal);
        let (right, command) = take_word(
            document,
            Span {
                start: equal + 2,
                end: range.end,
            },
        )?;
        return Some((IfCondition::Equal { left, right }, command));
    }
    let (left, rest) = take_word(document, range)?;
    let (operator, rest) = take_word(document, rest)?;
    let (right, command) = take_word(document, rest)?;
    Some((
        IfCondition::Compare {
            left,
            operator,
            right,
        },
        command,
    ))
}

fn strip_word(document: &ParsedDocument, range: Span, word: &str) -> Option<Span> {
    let range = trim_range(document, range.start, range.end);
    let source = document.text(range);
    let prefix = source.get(..word.len())?;
    if !prefix.eq_ignore_ascii_case(word)
        || source[word.len()..]
            .chars()
            .next()
            .is_some_and(|character| !character.is_whitespace())
    {
        return None;
    }
    Some(trim_range(document, range.start + word.len(), range.end))
}

fn take_word(document: &ParsedDocument, range: Span) -> Option<(Span, Span)> {
    let range = trim_range(document, range.start, range.end);
    if range.start >= range.end {
        return None;
    }
    let source = document.text(range);
    let mut quoted = false;
    let mut escaped = false;
    for (offset, character) in source.char_indices() {
        if escaped {
            escaped = false;
        } else if character == '^' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if character.is_whitespace() && !quoted {
            let end = range.start + offset;
            return Some((
                Span {
                    start: range.start,
                    end,
                },
                trim_range(document, end, range.end),
            ));
        }
    }
    Some((
        range,
        Span {
            start: range.end,
            end: range.end,
        },
    ))
}

fn find_unquoted(document: &ParsedDocument, range: Span, needle: &str) -> Option<usize> {
    let source = document.text(range);
    let mut quoted = false;
    let mut escaped = false;
    let mut offset = 0;
    while offset < source.len() {
        if !quoted && source[offset..].starts_with(needle) {
            return Some(range.start + offset);
        }
        let character = source[offset..].chars().next()?;
        if escaped {
            escaped = false;
        } else if character == '^' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        }
        offset += character.len_utf8();
    }
    None
}

fn split_else(document: &ParsedDocument, range: Span) -> (Span, Option<Span>) {
    let source = document.text(range);
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for (offset, character) in source.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if character == '^' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == '(' {
            depth += 1;
        } else if !quoted && character == ')' {
            depth = depth.saturating_sub(1);
        } else if !quoted
            && depth == 0
            && source[offset..]
                .get(..4)
                .is_some_and(|word| word.eq_ignore_ascii_case("else"))
            && source[..offset]
                .chars()
                .next_back()
                .is_none_or(char::is_whitespace)
            && source[offset + 4..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace)
        {
            return (
                trim_range(document, range.start, range.start + offset),
                Some(trim_range(document, range.start + offset + 4, range.end)),
            );
        }
    }
    (range, None)
}

fn complement_ranges(range: Span, excluded: &[Span]) -> Vec<Span> {
    let mut output = Vec::new();
    let mut cursor = range.start;
    for excluded in excluded {
        if cursor < excluded.start {
            output.push(Span {
                start: cursor,
                end: excluded.start,
            });
        }
        cursor = cursor.max(excluded.end);
    }
    if cursor < range.end {
        output.push(Span {
            start: cursor,
            end: range.end,
        });
    }
    output
}

fn outer_group(document: &ParsedDocument, range: Span) -> Option<Span> {
    let tokens = document.tokens_in(range);
    let first = tokens
        .iter()
        .find(|token| !matches!(token.kind, TokenKind::Whitespace))?;
    let last = tokens
        .iter()
        .rev()
        .find(|token| !matches!(token.kind, TokenKind::Whitespace))?;
    if first.kind != TokenKind::LeftParen || last.kind != TokenKind::RightParen {
        return None;
    }
    let mut depth = 0_usize;
    for token in tokens {
        match token.kind {
            TokenKind::LeftParen => depth += 1,
            TokenKind::RightParen => {
                depth = depth.saturating_sub(1);
                if depth == 0 && token.span != last.span {
                    return None;
                }
            }
            _ => {}
        }
    }
    (depth == 0).then_some(Span {
        start: first.span.end,
        end: last.span.start,
    })
}

fn trim_range(document: &ParsedDocument, mut start: usize, mut end: usize) -> Span {
    while start < end
        && document.source[start..end]
            .chars()
            .next()
            .is_some_and(char::is_whitespace)
    {
        start += document.source[start..end]
            .chars()
            .next()
            .map_or(0, char::len_utf8);
    }
    while start < end
        && document.source[start..end]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace)
    {
        end -= document.source[start..end]
            .chars()
            .next_back()
            .map_or(0, char::len_utf8);
    }
    Span { start, end }
}

fn digit_stream(digit: char) -> Stream {
    match digit {
        '0' => Stream::Stdin,
        '2' => Stream::Stderr,
        _ => Stream::Stdout,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_group_with_outer_redirection() {
        let document = ParsedDocument::parse("(echo visible & type absent) > combined.txt 2>&1");
        let command = &document.program().parts[0].command;

        assert!(command.group.is_some());
        assert_eq!(command.redirections.len(), 2);
    }

    #[test]
    fn parses_if_and_for_commands_once() {
        let if_document = ParsedDocument::parse("if /i \"A\"==\"a\" (echo yes) else echo no");
        assert!(matches!(
            if_document.program().parts[0].command.kind,
            CommandKind::If(_)
        ));

        let for_document = ParsedDocument::parse("for /l %%A in (1,1,3) do echo %%A");
        let CommandKind::For(command) = &for_document.program().parts[0].command.kind else {
            panic!("expected FOR command");
        };
        assert_eq!(command.variable, 'A');
        assert!(matches!(command.mode, ForMode::Linear));
        assert_eq!(for_document.text(command.set), "1,1,3");
    }
}
