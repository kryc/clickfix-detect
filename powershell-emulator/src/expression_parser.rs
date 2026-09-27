use crate::ast::{Expression, ExpressionKind, HashtableEntry};
use crate::parser::ParsedSource;
use crate::syntax::{
    extract_delimited, find_top_level_binary, is_quoted, is_variable, parse_instance_call,
    parse_member_access, parse_number, parse_static_call, parse_static_member_access,
    split_index_expression, split_key_value, split_powershell_word_ranges, split_statements,
    split_top_level, starts_word, strip_balanced_outer, strip_prefix_case_insensitive,
};
use crate::tokenizer::{Delimiter, Span, TokenKind};

pub(crate) fn parse_expression(parser: &ParsedSource, expression: &str) -> Option<Expression> {
    let expression = expression.trim();
    let range = parser.range(expression)?;
    let kind = parse_expression_kind(parser, expression)?;
    Some(Expression { range, kind })
}

#[allow(clippy::too_many_lines)]
fn parse_expression_kind(parser: &ParsedSource, expression: &str) -> Option<ExpressionKind> {
    if expression.is_empty() {
        return Some(ExpressionKind::Empty);
    }
    if let Some(inner) = strip_balanced_outer(parser, expression, '(', ')') {
        return Some(ExpressionKind::Parenthesized(Box::new(parse_expression(
            parser, inner,
        )?)));
    }
    if let Some(inner) = expression
        .strip_prefix("$(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return Some(ExpressionKind::Subexpression(parser.range(inner)?));
    }
    if expression.eq_ignore_ascii_case("$true") {
        return Some(ExpressionKind::Boolean(true));
    }
    if expression.eq_ignore_ascii_case("$false") {
        return Some(ExpressionKind::Boolean(false));
    }
    if expression.eq_ignore_ascii_case("$null") {
        return Some(ExpressionKind::Null);
    }
    if is_variable(parser, expression) {
        return Some(ExpressionKind::Variable);
    }
    if is_quoted(parser, expression) {
        let kind = parser
            .window(expression)?
            .tokens()
            .iter()
            .find_map(|token| match token.kind {
                TokenKind::String(kind) => Some(kind),
                _ => None,
            })?;
        return Some(ExpressionKind::String(kind));
    }
    let significant = parser
        .window(expression)?
        .tokens()
        .iter()
        .copied()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
        .collect::<Vec<_>>();
    if let [token] = significant.as_slice() {
        if let TokenKind::HereString(kind) = token.kind {
            return Some(ExpressionKind::HereString(kind));
        }
    }
    if parse_number(expression).is_some() {
        return Some(ExpressionKind::Number);
    }
    if let Some(inner) = expression
        .strip_prefix("@(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return Some(ExpressionKind::Array(parse_expression_list(parser, inner)));
    }
    if let Some((body, remainder)) = extract_delimited(parser, expression, '{', '}') {
        if remainder.trim().is_empty() {
            return Some(ExpressionKind::ScriptBlock(parser.range(body)?));
        }
    }
    if expression.starts_with("@{") && expression.ends_with('}') {
        return Some(ExpressionKind::Hashtable(parse_hashtable(
            parser,
            &expression[2..expression.len() - 1],
        )));
    }

    for type_name in [
        "char",
        "char[]",
        "byte[]",
        "int",
        "int32",
        "int64",
        "long",
        "string",
        "pscustomobject",
        "xml",
        "regex",
        "type",
    ] {
        let prefix = format!("[{type_name}]");
        if let Some(rest) = strip_prefix_case_insensitive(expression, &prefix) {
            let rest = rest.trim_start();
            if !rest.is_empty() && !rest.starts_with('.') && !rest.starts_with("::") {
                return Some(ExpressionKind::Cast {
                    type_name: type_name.into(),
                    value: Box::new(parse_expression(parser, rest)?),
                });
            }
        }
    }
    if expression.starts_with('[') && expression.ends_with(']') {
        return Some(ExpressionKind::TypeLiteral(
            expression[1..expression.len() - 1].trim().into(),
        ));
    }
    if let Some(rest) = strip_prefix_case_insensitive(expression, "-join") {
        if !rest.trim().is_empty() {
            return Some(ExpressionKind::Unary {
                operator: "-join".into(),
                value: Box::new(parse_expression(parser, rest)?),
            });
        }
    }

    for operators in binary_precedence() {
        if let Some((left, operator, right)) = find_top_level_binary(parser, expression, operators)
        {
            return Some(ExpressionKind::Binary {
                left: Box::new(parse_expression(parser, left)?),
                operator: operator.into(),
                right: Box::new(parse_expression(parser, right)?),
            });
        }
    }
    for unary in ["-not", "!", "-bnot", "-", "+"] {
        if let Some(rest) = strip_prefix_case_insensitive(expression, unary) {
            if !rest.trim().is_empty() {
                return Some(ExpressionKind::Unary {
                    operator: unary.into(),
                    value: Box::new(parse_expression(parser, rest)?),
                });
            }
        }
    }
    if let Some((value, index)) = split_null_conditional_index(parser, expression) {
        return Some(ExpressionKind::Index {
            value: Box::new(parse_expression(parser, value)?),
            index: Box::new(parse_expression(parser, index)?),
            null_conditional: true,
        });
    }
    if let Some((value, index)) = split_index_expression(parser, expression) {
        return Some(ExpressionKind::Index {
            value: Box::new(parse_expression(parser, value)?),
            index: Box::new(parse_expression(parser, index)?),
            null_conditional: false,
        });
    }
    if let Some((type_name, method, arguments)) = parse_static_call(parser, expression) {
        return Some(ExpressionKind::StaticCall {
            type_name: parser.range(type_name)?,
            method: parser.range(method)?,
            arguments: parse_expression_list(parser, arguments),
        });
    }
    if let Some((type_name, member)) = parse_static_member_access(expression) {
        return Some(ExpressionKind::StaticMember {
            type_name: parser.range(type_name)?,
            member: parser.range(member)?,
        });
    }
    if let Some((receiver, method, arguments, null_conditional)) =
        parse_instance_call_expression(parser, expression)
    {
        return Some(ExpressionKind::InstanceCall {
            receiver: Box::new(parse_expression(parser, receiver)?),
            method: parser.range(method)?,
            arguments: parse_expression_list(parser, arguments),
            null_conditional,
        });
    }
    if let Some((receiver, member, null_conditional)) = parse_member_expression(parser, expression)
    {
        return Some(ExpressionKind::Member {
            receiver: Box::new(parse_expression(parser, receiver)?),
            member: parser.range(member)?,
            null_conditional,
        });
    }
    if starts_word(expression, "new-object") {
        let words = split_powershell_word_ranges(parser, expression);
        return Some(ExpressionKind::NewObject {
            arguments: words.get(1..).unwrap_or_default().to_vec(),
        });
    }
    let comma_values = split_top_level(parser, expression, ',');
    if comma_values.len() > 1 {
        return Some(ExpressionKind::Array(
            comma_values
                .into_iter()
                .filter_map(|value| parse_expression(parser, value))
                .collect(),
        ));
    }
    Some(ExpressionKind::Bare)
}

fn parse_expression_list(parser: &ParsedSource, expressions: &str) -> Vec<Expression> {
    split_top_level(parser, expressions, ',')
        .into_iter()
        .filter(|expression| !expression.trim().is_empty())
        .filter_map(|expression| parse_expression(parser, expression))
        .collect()
}

fn parse_hashtable(parser: &ParsedSource, body: &str) -> Vec<HashtableEntry> {
    let mut entries = Vec::new();
    for statement in split_statements(parser, body) {
        for entry in split_top_level(parser, statement, ',') {
            let Some((key, value)) = split_key_value(parser, entry) else {
                continue;
            };
            let Some(value) = parse_expression(parser, value) else {
                continue;
            };
            entries.push(HashtableEntry {
                key: key.trim().trim_matches(['\'', '"']).into(),
                value,
            });
        }
    }
    entries
}

fn split_null_conditional_index<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str)> {
    let input = input.trim();
    let window = parser.window(input)?;
    let tokens = window
        .tokens()
        .iter()
        .copied()
        .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
        .collect::<Vec<_>>();
    let last = *tokens.last()?;
    if last.kind != TokenKind::Delimiter(Delimiter::RightBracket)
        || last.span.end != window.span().end
    {
        return None;
    }
    let mut depth = 0_usize;
    for token in tokens.into_iter().rev() {
        if token.kind == TokenKind::Delimiter(Delimiter::RightBracket) {
            depth += 1;
        } else if token.kind == TokenKind::Operator && token.text(parser.source()) == "?[" {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some((
                    parser
                        .text(Span::new(window.span().start, token.span.start))
                        .trim(),
                    parser
                        .text(Span::new(token.span.end, last.span.start))
                        .trim(),
                ));
            }
        } else if token.kind == TokenKind::Delimiter(Delimiter::LeftBracket) {
            depth = depth.saturating_sub(1);
        }
    }
    None
}

fn parse_instance_call_expression<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str, &'a str, bool)> {
    if let Some((receiver, method, arguments)) = parse_instance_call(parser, input) {
        return Some((receiver, method, arguments, false));
    }
    let input = input.trim();
    if !input.ends_with(')') {
        return None;
    }
    let window = parser.window(input)?;
    let tokens = window.tokens();
    let mut parentheses = 0_usize;
    let mut call_open = None;
    let mut operator = None;
    for token in tokens.iter().copied() {
        match token.kind {
            TokenKind::Delimiter(Delimiter::LeftParenthesis) => {
                if parentheses == 0 {
                    call_open = Some(token);
                }
                parentheses += 1;
            }
            TokenKind::Delimiter(Delimiter::RightParenthesis) => {
                parentheses = parentheses.saturating_sub(1);
            }
            TokenKind::Operator if parentheses == 0 && token.text(parser.source()) == "?." => {
                operator = Some(token);
            }
            _ => {}
        }
    }
    let operator = operator?;
    let call_open = call_open?;
    (operator.span.start < call_open.span.start).then(|| {
        (
            parser
                .text(Span::new(window.span().start, operator.span.start))
                .trim(),
            parser
                .text(Span::new(operator.span.end, call_open.span.start))
                .trim(),
            parser
                .text(Span::new(call_open.span.end, window.span().end - 1))
                .trim(),
            true,
        )
    })
}

fn parse_member_expression<'a>(
    parser: &'a ParsedSource,
    input: &str,
) -> Option<(&'a str, &'a str, bool)> {
    if let Some((receiver, member)) = parse_member_access(parser, input) {
        return Some((receiver, member, false));
    }
    let window = parser.window(input)?;
    let mut nesting = (0_usize, 0_usize, 0_usize);
    let mut operator = None;
    for token in window.tokens().iter().copied() {
        if nesting == (0, 0, 0)
            && token.kind == TokenKind::Operator
            && token.text(parser.source()) == "?."
        {
            operator = Some(token);
        }
        match token.kind {
            TokenKind::Delimiter(Delimiter::LeftParenthesis) => nesting.0 += 1,
            TokenKind::Delimiter(Delimiter::RightParenthesis) => {
                nesting.0 = nesting.0.saturating_sub(1);
            }
            TokenKind::Delimiter(Delimiter::LeftBracket) => nesting.1 += 1,
            TokenKind::Delimiter(Delimiter::RightBracket) => {
                nesting.1 = nesting.1.saturating_sub(1);
            }
            TokenKind::Delimiter(Delimiter::LeftBrace) => nesting.2 += 1,
            TokenKind::Delimiter(Delimiter::RightBrace) => {
                nesting.2 = nesting.2.saturating_sub(1);
            }
            _ => {}
        }
    }
    let operator = operator?;
    let receiver = parser
        .text(Span::new(window.span().start, operator.span.start))
        .trim();
    let member = parser
        .text(Span::new(operator.span.end, window.span().end))
        .trim();
    (!receiver.is_empty() && !member.is_empty()).then_some((receiver, member, true))
}

fn binary_precedence() -> [&'static [&'static str]; 12] {
    [
        &["-or"],
        &["-xor"],
        &["-and"],
        &[
            "-eq",
            "-ieq",
            "-ceq",
            "-ne",
            "-ine",
            "-cne",
            "-lt",
            "-le",
            "-gt",
            "-ge",
            "-ilt",
            "-ile",
            "-igt",
            "-ige",
            "-clt",
            "-cle",
            "-cgt",
            "-cge",
            "-like",
            "-ilike",
            "-clike",
            "-notlike",
            "-inotlike",
            "-cnotlike",
            "-match",
            "-imatch",
            "-cmatch",
            "-notmatch",
            "-inotmatch",
            "-cnotmatch",
            "-contains",
            "-icontains",
            "-ccontains",
            "-notcontains",
            "-inotcontains",
            "-cnotcontains",
            "-in",
            "-notin",
            "-is",
            "-isnot",
        ],
        &["-bor"],
        &["-bxor"],
        &["-band"],
        &["-shl", "-shr"],
        &[
            "-replace",
            "-ireplace",
            "-creplace",
            "-split",
            "-isplit",
            "-csplit",
            "-join",
            "-f",
        ],
        &["+", "-"],
        &["*", "/", "%"],
        &[".."],
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_binary_member_expression_with_source_ranges() {
        let source = "$value.Count + 1";
        let parser = ParsedSource::parse(source).expect("valid source");
        let expression = parse_expression(&parser, parser.source()).expect("expression");

        let ExpressionKind::Binary {
            left,
            operator,
            right,
        } = expression.kind
        else {
            panic!("expected binary expression");
        };
        assert_eq!(operator, "+");
        assert_eq!(parser.text(left.range), "$value.Count");
        assert_eq!(parser.text(right.range), "1");
        assert!(matches!(left.kind, ExpressionKind::Member { .. }));
        assert!(matches!(right.kind, ExpressionKind::Number));
    }

    #[test]
    fn parses_null_conditional_access_as_typed_nodes() {
        let source = "${value}?.Items?[0]";
        let parser = ParsedSource::parse(source).expect("valid source");
        let expression = parse_expression(&parser, parser.source()).expect("expression");

        let ExpressionKind::Index {
            value,
            null_conditional,
            ..
        } = expression.kind
        else {
            panic!("expected index expression");
        };
        assert!(null_conditional);
        assert!(matches!(
            value.kind,
            ExpressionKind::Member {
                null_conditional: true,
                ..
            }
        ));
    }
}
