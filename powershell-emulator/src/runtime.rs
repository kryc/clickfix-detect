use crate::parser::ParsedSource;
use crate::syntax::{
    extract_delimited, normalize_variable, split_key_value, split_top_level, starts_word,
};
use crate::tokenizer::TokenKind;
use crate::Value;

#[derive(Debug, Clone)]
pub(crate) struct FunctionDefinition {
    pub(crate) parser: ParsedSource,
    pub(crate) parameters: Vec<FunctionParameter>,
    pub(crate) body: String,
}

#[derive(Debug, Clone)]
pub(crate) struct FunctionParameter {
    pub(crate) name: String,
    pub(crate) default: Option<String>,
}

impl FunctionDefinition {
    pub(crate) fn parse(parser: &ParsedSource, body: &str) -> Self {
        let body = body.trim();
        if starts_word(body, "param") {
            let after_keyword = body["param".len()..].trim_start();
            if let Some((parameters, remainder)) =
                extract_delimited(parser, after_keyword, '(', ')')
            {
                return Self {
                    parser: parser.clone(),
                    parameters: split_top_level(parser, parameters, ',')
                        .into_iter()
                        .map(|parameter| {
                            let (declaration, default) = split_key_value(parser, parameter)
                                .map_or((parameter, None), |(declaration, default)| {
                                    (declaration, Some(default.into()))
                                });
                            FunctionParameter {
                                name: parameter_name(parser, declaration),
                                default,
                            }
                        })
                        .filter(|parameter| !parameter.name.is_empty())
                        .collect(),
                    body: remainder
                        .trim_start_matches([';', '\r', '\n'])
                        .trim()
                        .into(),
                };
            }
        }
        Self {
            parser: parser.clone(),
            parameters: Vec::new(),
            body: body.into(),
        }
    }
}

fn parameter_name(parser: &ParsedSource, input: &str) -> String {
    parser
        .window(input)
        .into_iter()
        .flat_map(|window| window.tokens().iter().copied())
        .find(|token| token.kind == TokenKind::Variable)
        .map_or_else(String::new, |token| {
            normalize_variable(token.text(parser.source()))
        })
}

#[derive(Debug, Clone, Default)]
pub(crate) enum FlowControl {
    #[default]
    None,
    Break,
    Continue,
    Return(Option<Value>),
    Exit(Option<Value>),
}

impl FlowControl {
    pub(crate) const fn is_active(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub(crate) fn take(&mut self) -> Self {
        std::mem::take(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_function_parameters() {
        let source = "param($Value, [string]$Name)\nWrite-Output \"$Name=$Value\"";
        let parser = ParsedSource::parse(source).expect("valid source");
        let function = FunctionDefinition::parse(&parser, source);

        assert_eq!(
            function
                .parameters
                .iter()
                .map(|parameter| parameter.name.as_str())
                .collect::<Vec<_>>(),
            ["value", "name"]
        );
        assert_eq!(function.body, "Write-Output \"$Name=$Value\"");
    }
}
