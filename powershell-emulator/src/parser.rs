use crate::ast::{Expression, Program};
use crate::expression_parser::parse_expression;
use crate::statement_parser::{parse_program, parse_statement};
use crate::syntax::split_statements;
use crate::tokenizer::{tokenize, Diagnostic, NestedTokenization, Span, Token, Tokenization};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

type SourceRangeKey = (usize, usize);
type ExpressionCache = Arc<Mutex<BTreeMap<SourceRangeKey, Arc<Expression>>>>;
type StatementCache = Arc<Mutex<BTreeMap<SourceRangeKey, Arc<[crate::ast::Statement]>>>>;
type ExternalRanges = Arc<Mutex<BTreeMap<(usize, usize), Span>>>;

#[derive(Debug, Clone)]
pub(crate) struct ParsedSource {
    source: Arc<str>,
    tokens: Arc<[Token]>,
    diagnostics: Arc<[Diagnostic]>,
    nested: Arc<[NestedTokenization]>,
    expressions: ExpressionCache,
    statement_blocks: StatementCache,
    program: Arc<Program>,
    external_ranges: ExternalRanges,
}

impl ParsedSource {
    pub(crate) fn parse(source: &str) -> Result<Self, Diagnostic> {
        let Tokenization {
            tokens,
            diagnostics,
            nested,
        } = tokenize(source);
        if let Some(diagnostic) = diagnostics.iter().find(|diagnostic| diagnostic.is_fatal()) {
            return Err(diagnostic.clone());
        }
        let mut parsed = Self {
            source: Arc::from(source),
            tokens: Arc::from(tokens),
            diagnostics: Arc::from(diagnostics),
            nested: Arc::from(nested),
            expressions: Arc::new(Mutex::new(BTreeMap::new())),
            statement_blocks: Arc::new(Mutex::new(BTreeMap::new())),
            program: Arc::new(Program {
                range: Span::new(0, 0),
                statements: Vec::new(),
            }),
            external_ranges: Arc::new(Mutex::new(BTreeMap::new())),
        };
        parsed.program = Arc::new(parse_program(&parsed));
        Ok(parsed)
    }

    pub(crate) fn source(&self) -> &str {
        &self.source
    }

    pub(crate) fn token_count(&self) -> usize {
        self.tokens.len()
    }

    pub(crate) fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub(crate) fn program(&self) -> &Program {
        &self.program
    }

    pub(crate) fn expression(&self, input: &str) -> Option<Arc<Expression>> {
        let range = self.range(input)?;
        let key = (range.start, range.end);
        if let Some(expression) = self
            .expressions
            .lock()
            .expect("PowerShell expression cache poisoned")
            .get(&key)
            .cloned()
        {
            return Some(expression);
        }
        let expression = Arc::new(parse_expression(self, input)?);
        self.expressions
            .lock()
            .expect("PowerShell expression cache poisoned")
            .insert(key, expression.clone());
        Some(expression)
    }

    pub(crate) fn statements(&self, input: &str) -> Option<Arc<[crate::ast::Statement]>> {
        let range = self.range(input)?;
        if range == self.program.range {
            return Some(Arc::from(self.program.statements.clone()));
        }
        let key = (range.start, range.end);
        if let Some(statements) = self
            .statement_blocks
            .lock()
            .expect("PowerShell statement cache poisoned")
            .get(&key)
            .cloned()
        {
            return Some(statements);
        }
        let statements: Arc<[crate::ast::Statement]> = split_statements(self, input)
            .into_iter()
            .filter_map(|statement| parse_statement(self, statement))
            .collect::<Vec<_>>()
            .into();
        self.statement_blocks
            .lock()
            .expect("PowerShell statement cache poisoned")
            .insert(key, statements.clone());
        Some(statements)
    }

    pub(crate) fn window<'a>(&'a self, input: &str) -> Option<TokenWindow<'a>> {
        let span = self.span(input)?;
        let tokens = self
            .nested
            .iter()
            .filter(|nested| nested.span.start <= span.start && nested.span.end >= span.end)
            .min_by_key(|nested| nested.span.len())
            .map_or(self.tokens.as_ref(), |nested| nested.tokens.as_slice());
        let first = tokens.partition_point(|token| token.span.start < span.start);
        let end = tokens.partition_point(|token| token.span.end <= span.end);
        let end = end.max(first);
        Some(TokenWindow {
            source: &self.source,
            span,
            tokens: &tokens[first..end],
        })
    }

    pub(crate) fn window_starting_at<'a>(&'a self, input: &str) -> Option<TokenWindow<'a>> {
        let span = self.span(input)?;
        let tokens = self
            .nested
            .iter()
            .filter(|nested| nested.span.start <= span.start && nested.span.end > span.start)
            .min_by_key(|nested| nested.span.len())
            .map_or(self.tokens.as_ref(), |nested| nested.tokens.as_slice());
        let first = tokens.partition_point(|token| token.span.start < span.start);
        let end = tokens.partition_point(|token| token.span.end <= span.end);
        let end = end.max(first);
        Some(TokenWindow {
            source: &self.source,
            span,
            tokens: &tokens[first..end],
        })
    }

    pub(crate) fn text(&self, span: Span) -> &str {
        &self.source[span.start..span.end]
    }

    pub(crate) fn range(&self, input: &str) -> Option<Span> {
        self.span(input)
    }

    pub(crate) fn bind_external<'a>(&'a self, input: &str, range: Span) -> ExternalRangeGuard<'a> {
        let key = (input.as_ptr() as usize, input.len());
        self.external_ranges
            .lock()
            .expect("PowerShell external range cache poisoned")
            .insert(key, range);
        ExternalRangeGuard { parser: self, key }
    }

    fn span(&self, input: &str) -> Option<Span> {
        let source_start = self.source.as_ptr() as usize;
        let source_end = source_start.checked_add(self.source.len())?;
        let input_start = input.as_ptr() as usize;
        let input_end = input_start.checked_add(input.len())?;
        if input_start >= source_start && input_end <= source_end {
            return Some(Span::new(
                input_start.saturating_sub(source_start),
                input_end.saturating_sub(source_start),
            ));
        }

        self.external_ranges
            .lock()
            .expect("PowerShell external range cache poisoned")
            .get(&(input_start, input.len()))
            .copied()
    }
}

pub(crate) struct ExternalRangeGuard<'a> {
    parser: &'a ParsedSource,
    key: (usize, usize),
}

impl Drop for ExternalRangeGuard<'_> {
    fn drop(&mut self) {
        self.parser
            .external_ranges
            .lock()
            .expect("PowerShell external range cache poisoned")
            .remove(&self.key);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct TokenWindow<'a> {
    source: &'a str,
    span: Span,
    tokens: &'a [Token],
}

impl<'a> TokenWindow<'a> {
    pub(crate) fn source(self) -> &'a str {
        self.source
    }

    pub(crate) fn span(self) -> Span {
        self.span
    }

    pub(crate) fn tokens(self) -> &'a [Token] {
        self.tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caches_expression_ast_by_source_range() {
        let parser = ParsedSource::parse("$value + 1").expect("valid source");
        let first = parser.expression(parser.source()).expect("expression");
        let second = parser.expression(parser.source()).expect("expression");

        assert!(Arc::ptr_eq(&first, &second));
    }
}
