use crate::ast::{
    DoStatement, ForStatement, ForeachStatement, IfBranch, IfStatement, ParameterDeclaration,
    Program, Statement, StatementKind, SwitchCase, SwitchInput, SwitchMatching, SwitchStatement,
    TryStatement, WhileStatement,
};
use crate::expression_parser::parse_expression;
use crate::parser::ParsedSource;
use crate::syntax::{
    extract_delimited, find_word_case_insensitive, parse_instance_call, parse_named_block,
    parse_redirections, parse_static_call, split_assignment, split_compound_assignment,
    split_increment, split_key_value, split_labeled_blocks, split_powershell_word_ranges,
    split_powershell_words, split_statements, split_top_level, starts_word,
};
use crate::tokenizer::Span;

pub(crate) fn parse_program(parser: &ParsedSource) -> Program {
    let source = parser.source();
    Program {
        range: Span::new(0, source.len()),
        statements: split_statements(parser, source)
            .into_iter()
            .filter_map(|statement| parse_statement(parser, statement))
            .collect(),
    }
}

pub(crate) fn parse_statement(parser: &ParsedSource, statement: &str) -> Option<Statement> {
    let statement = statement.trim();
    let range = parser.range(statement)?;
    let kind = parse_statement_kind(parser, statement)?;
    Some(Statement { range, kind })
}

#[allow(clippy::too_many_lines)]
fn parse_statement_kind(parser: &ParsedSource, statement: &str) -> Option<StatementKind> {
    if statement.is_empty() {
        return Some(StatementKind::Empty);
    }
    if let Some((command, redirections)) = parse_redirections(parser, statement) {
        return Some(StatementKind::Redirected {
            command: Box::new(parse_statement(parser, command)?),
            redirections,
        });
    }
    for (keyword, filter) in [("function", false), ("filter", true)] {
        if let Some((name, body)) = parse_named_block(parser, statement, keyword) {
            let (name, parameters, body) = parse_function_parts(parser, name, body)?;
            return Some(StatementKind::Function {
                name,
                parameters,
                body,
                filter,
            });
        }
    }
    if ["class", "enum", "data"]
        .iter()
        .any(|keyword| starts_word(statement, keyword))
    {
        return Some(StatementKind::OpaqueDeclaration);
    }
    if starts_word(statement, "param") {
        return Some(StatementKind::Param(parse_parameters(parser, statement)?));
    }
    if starts_word(statement, "if") {
        return Some(StatementKind::If(parse_if(parser, statement, "if")?));
    }
    if starts_word(statement, "foreach") {
        return Some(StatementKind::Foreach(parse_foreach(parser, statement)?));
    }
    if starts_word(statement, "while") {
        return Some(StatementKind::While(parse_while(parser, statement)?));
    }
    if starts_word(statement, "for") {
        return Some(StatementKind::For(parse_for(parser, statement)?));
    }
    if starts_word(statement, "do") {
        return Some(StatementKind::Do(parse_do(parser, statement)?));
    }
    if starts_word(statement, "switch") {
        return Some(StatementKind::Switch(parse_switch(parser, statement)?));
    }
    if starts_word(statement, "try") {
        return Some(StatementKind::Try(parse_try(parser, statement)?));
    }
    if statement.eq_ignore_ascii_case("break") {
        return Some(StatementKind::Break);
    }
    if statement.eq_ignore_ascii_case("continue") {
        return Some(StatementKind::Continue);
    }
    for keyword in ["return", "exit", "throw"] {
        if starts_word(statement, keyword) {
            let remainder = statement[keyword.len()..].trim();
            let expression = (!remainder.is_empty())
                .then(|| parse_expression(parser, remainder))
                .flatten();
            return Some(match keyword {
                "return" => StatementKind::Return(expression),
                "exit" => StatementKind::Exit(expression),
                "throw" => StatementKind::Throw(expression?),
                _ => unreachable!(),
            });
        }
    }
    if let Some((variable, delta)) = split_increment(parser, statement) {
        return Some(StatementKind::Increment {
            variable: parser.range(variable)?,
            delta,
        });
    }
    if let Some((target, operator, value)) = split_compound_assignment(parser, statement) {
        return Some(StatementKind::CompoundAssignment {
            target: parser.range(target)?,
            operator: operator.into(),
            value: parse_expression(parser, value)?,
        });
    }
    if let Some((target, value)) = split_assignment(parser, statement) {
        return Some(StatementKind::Assignment {
            target: parser.range(target)?,
            value: parse_expression(parser, value)?,
        });
    }
    let pipeline = split_top_level(parser, statement, '|');
    if pipeline.len() > 1 {
        return Some(StatementKind::Pipeline(
            pipeline
                .into_iter()
                .filter_map(|segment| parse_statement(parser, segment))
                .collect(),
        ));
    }
    if statement.starts_with('&') || statement.starts_with(". ") {
        let dot_source = statement.starts_with(". ");
        let invocation = statement[1..].trim();
        let ranges = split_powershell_word_ranges(parser, invocation);
        return Some(StatementKind::Invocation {
            target: parse_expression(parser, parser.text(*ranges.first()?))?,
            arguments: ranges[1..]
                .iter()
                .filter_map(|range| parse_expression(parser, parser.text(*range)))
                .collect(),
            dot_source,
        });
    }

    let words = split_powershell_words(parser, statement);
    if words.len() > 1 {
        let first = parser
            .window(statement)?
            .tokens()
            .iter()
            .find(|token| {
                !token.kind.is_trivia() && token.kind != crate::tokenizer::TokenKind::NewLine
            })
            .copied();
        if first.is_some_and(|token| {
            matches!(
                token.kind,
                crate::tokenizer::TokenKind::Identifier | crate::tokenizer::TokenKind::Keyword
            )
        }) {
            let ranges = split_powershell_word_ranges(parser, statement);
            return Some(StatementKind::Command {
                command: *ranges.first()?,
                arguments: ranges[1..].to_vec(),
            });
        }
    }
    if words.len() == 1
        && (parse_static_call(parser, statement).is_some()
            || parse_instance_call(parser, statement).is_some())
    {
        return Some(StatementKind::Expression(parse_expression(
            parser, statement,
        )?));
    }
    if let Some(expression) = parse_expression(parser, statement) {
        if !matches!(expression.kind, crate::ast::ExpressionKind::Bare) {
            return Some(StatementKind::Expression(expression));
        }
    }
    let ranges = split_powershell_word_ranges(parser, statement);
    Some(StatementKind::Command {
        command: *ranges.first()?,
        arguments: ranges[1..].to_vec(),
    })
}

fn parse_parameters(parser: &ParsedSource, statement: &str) -> Option<Vec<ParameterDeclaration>> {
    let after_keyword = statement["param".len()..].trim_start();
    let (parameters, _) = extract_delimited(parser, after_keyword, '(', ')')?;
    Some(
        split_top_level(parser, parameters, ',')
            .into_iter()
            .filter_map(|parameter| {
                let (declaration, default) = split_key_value(parser, parameter)
                    .map_or((parameter, None), |(declaration, default)| {
                        (declaration, Some(default))
                    });
                let variable = parser
                    .window(declaration)?
                    .tokens()
                    .iter()
                    .find(|token| token.kind == crate::tokenizer::TokenKind::Variable)
                    .copied()?;
                Some(ParameterDeclaration {
                    name: variable.span,
                    default: default.and_then(|value| parse_expression(parser, value)),
                })
            })
            .collect(),
    )
}

fn parse_function_parts(
    parser: &ParsedSource,
    name: &str,
    body: &str,
) -> Option<(Span, Vec<ParameterDeclaration>, Span)> {
    if let Some(open) = name.find('(') {
        let function_name = name[..open].trim();
        let (parameters, _) = extract_delimited(parser, &name[open..], '(', ')')?;
        return Some((
            parser.range(function_name)?,
            parse_parameter_list(parser, parameters),
            parser.range(body.trim())?,
        ));
    }
    let body = body.trim();
    if starts_word(body, "param") {
        let after_keyword = body["param".len()..].trim_start();
        let (parameters, remainder) = extract_delimited(parser, after_keyword, '(', ')')?;
        return Some((
            parser.range(name.trim())?,
            parse_parameter_list(parser, parameters),
            parser.range(remainder.trim_start_matches([';', '\r', '\n']).trim())?,
        ));
    }
    Some((parser.range(name.trim())?, Vec::new(), parser.range(body)?))
}

fn parse_parameter_list(parser: &ParsedSource, parameters: &str) -> Vec<ParameterDeclaration> {
    split_top_level(parser, parameters, ',')
        .into_iter()
        .filter_map(|parameter| {
            let (declaration, default) = split_key_value(parser, parameter)
                .map_or((parameter, None), |(declaration, default)| {
                    (declaration, Some(default))
                });
            let variable = parser
                .window(declaration)?
                .tokens()
                .iter()
                .find(|token| token.kind == crate::tokenizer::TokenKind::Variable)
                .copied()?;
            Some(ParameterDeclaration {
                name: variable.span,
                default: default.and_then(|value| parse_expression(parser, value)),
            })
        })
        .collect()
}

fn parse_if(parser: &ParsedSource, statement: &str, keyword: &str) -> Option<IfStatement> {
    let after_keyword = statement[keyword.len()..].trim_start();
    let (condition, after_condition) = extract_delimited(parser, after_keyword, '(', ')')?;
    let (then_body, remainder) = extract_delimited(parser, after_condition.trim_start(), '{', '}')?;
    let remainder = remainder.trim_start();
    let else_branch = if starts_word(remainder, "elseif") {
        Some(IfBranch::ElseIf(Box::new(parse_if(
            parser, remainder, "elseif",
        )?)))
    } else if starts_word(remainder, "else") {
        let (body, _) =
            extract_delimited(parser, remainder["else".len()..].trim_start(), '{', '}')?;
        Some(IfBranch::Else(parser.range(body)?))
    } else {
        None
    };
    Some(IfStatement {
        condition: parse_expression(parser, condition)?,
        then_body: parser.range(then_body)?,
        else_branch,
    })
}

fn parse_foreach(parser: &ParsedSource, statement: &str) -> Option<ForeachStatement> {
    let after_keyword = statement["foreach".len()..].trim_start();
    let (header, after_header) = extract_delimited(parser, after_keyword, '(', ')')?;
    let (body, _) = extract_delimited(parser, after_header.trim_start(), '{', '}')?;
    let separator = find_word_case_insensitive(header, " in ")?;
    let variable = header[..separator].trim();
    let values = header[separator + 4..].trim();
    Some(ForeachStatement {
        variable: parser.range(variable)?,
        values: parse_expression(parser, values)?,
        body: parser.range(body)?,
    })
}

fn parse_while(parser: &ParsedSource, statement: &str) -> Option<WhileStatement> {
    let after_keyword = statement["while".len()..].trim_start();
    let (condition, after_condition) = extract_delimited(parser, after_keyword, '(', ')')?;
    let (body, _) = extract_delimited(parser, after_condition.trim_start(), '{', '}')?;
    Some(WhileStatement {
        condition: parse_expression(parser, condition)?,
        body: parser.range(body)?,
    })
}

fn parse_for(parser: &ParsedSource, statement: &str) -> Option<ForStatement> {
    let after_keyword = statement["for".len()..].trim_start();
    let (header, after_header) = extract_delimited(parser, after_keyword, '(', ')')?;
    let (body, _) = extract_delimited(parser, after_header.trim_start(), '{', '}')?;
    let parts = split_top_level(parser, header, ';');
    if parts.len() != 3 {
        return None;
    }
    Some(ForStatement {
        initialization: Box::new(parse_statement(parser, parts[0])?),
        condition: parse_expression(parser, parts[1])?,
        iteration: Box::new(parse_statement(parser, parts[2])?),
        body: parser.range(body)?,
    })
}

fn parse_do(parser: &ParsedSource, statement: &str) -> Option<DoStatement> {
    let after_keyword = statement["do".len()..].trim_start();
    let (body, remainder) = extract_delimited(parser, after_keyword, '{', '}')?;
    let remainder = remainder.trim_start();
    let (until, condition_text) = if starts_word(remainder, "until") {
        (true, remainder["until".len()..].trim_start())
    } else if starts_word(remainder, "while") {
        (false, remainder["while".len()..].trim_start())
    } else {
        return None;
    };
    let (condition, _) = extract_delimited(parser, condition_text, '(', ')')?;
    Some(DoStatement {
        body: parser.range(body)?,
        condition: parse_expression(parser, condition)?,
        until,
    })
}

fn parse_switch(parser: &ParsedSource, statement: &str) -> Option<SwitchStatement> {
    let after_keyword = statement["switch".len()..].trim_start();
    let condition_start = after_keyword.find('(')?;
    let options = after_keyword[..condition_start].to_ascii_lowercase();
    let (condition, after_condition) =
        extract_delimited(parser, &after_keyword[condition_start..], '(', ')')?;
    let (body, _) = extract_delimited(parser, after_condition.trim_start(), '{', '}')?;
    let cases = split_labeled_blocks(parser, body)
        .into_iter()
        .filter_map(|(label, body)| {
            Some(SwitchCase {
                label: (!label.eq_ignore_ascii_case("default"))
                    .then(|| parse_expression(parser, label))
                    .flatten(),
                body: parser.range(body)?,
            })
        })
        .collect();
    Some(SwitchStatement {
        condition: parse_expression(parser, condition)?,
        cases,
        input: if options.contains("-file") {
            SwitchInput::File
        } else {
            SwitchInput::Values
        },
        case_sensitive: options.contains("-casesensitive"),
        matching: if options.contains("-regex") {
            SwitchMatching::Regex
        } else if options.contains("-wildcard") {
            SwitchMatching::Wildcard
        } else {
            SwitchMatching::Exact
        },
    })
}

fn parse_try(parser: &ParsedSource, statement: &str) -> Option<TryStatement> {
    let after_try = statement["try".len()..].trim_start();
    let (body, remainder) = extract_delimited(parser, after_try, '{', '}')?;
    let mut remainder = remainder.trim_start();
    let mut catch_body = None;
    if starts_word(remainder, "catch") {
        let after_catch = remainder["catch".len()..].trim_start();
        let (body, after_body) = extract_delimited(parser, after_catch, '{', '}')?;
        catch_body = Some(parser.range(body)?);
        remainder = after_body.trim_start();
    }
    let finally_body = if starts_word(remainder, "finally") {
        let (body, _) =
            extract_delimited(parser, remainder["finally".len()..].trim_start(), '{', '}')?;
        Some(parser.range(body)?)
    } else {
        None
    };
    Some(TryStatement {
        body: parser.range(body)?,
        catch_body,
        finally_body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Expression;

    #[test]
    fn distinguishes_command_mode_from_expression_mode() {
        let source = "Write-Output 1+3\n1 + 3";
        let parser = ParsedSource::parse(source).expect("valid source");
        let program = parse_program(&parser);

        assert!(matches!(
            program.statements[0].kind,
            StatementKind::Command { .. }
        ));
        assert!(matches!(
            program.statements[1].kind,
            StatementKind::Expression(Expression {
                kind: crate::ast::ExpressionKind::Binary { .. },
                ..
            })
        ));
    }

    #[test]
    fn parses_control_flow_and_function_bodies_as_ranges() {
        let source = "function Test { if ($true) { 'yes' } }\nTest";
        let parser = ParsedSource::parse(source).expect("valid source");
        let program = parse_program(&parser);

        let StatementKind::Function { body, .. } = program.statements[0].kind else {
            panic!("expected function");
        };
        assert_eq!(parser.text(body).trim(), "if ($true) { 'yes' }");
        assert!(matches!(
            program.statements[1].kind,
            StatementKind::Command { .. }
        ));
    }
}
