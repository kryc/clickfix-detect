use crate::ast::{
    CaseArm, Command, ListItem, ListOperator, Pipeline, Program, RedirectKind, Redirection,
    SimpleCommand, Word,
};
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
        let mut parser = Parser::new(source, &tokenization.tokens);
        let program = parser.parse_program_until(&[]);
        let mut diagnostics = tokenization.diagnostics;
        diagnostics.extend(parser.diagnostics);
        Self {
            source: Arc::from(source),
            tokens: Arc::from(tokenization.tokens),
            diagnostics: Arc::from(diagnostics),
            program: Arc::new(program),
        }
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
}

struct Parser<'a> {
    source: &'a str,
    tokens: &'a [Token],
    index: usize,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str, tokens: &'a [Token]) -> Self {
        Self {
            source,
            tokens,
            index: 0,
            diagnostics: Vec::new(),
        }
    }

    fn parse_program_until(&mut self, stop_words: &[&str]) -> Program {
        let mut program = Program::default();
        let mut next_operator = ListOperator::Always;
        loop {
            self.skip_case_separators();
            if self.index >= self.tokens.len() || self.at_stop_word(stop_words) {
                break;
            }
            let start_index = self.index;
            let pipeline = self.parse_pipeline(stop_words);
            if pipeline.commands.is_empty() || self.index == start_index {
                self.diagnostic_here("expected shell command");
                self.index = self.index.saturating_add(1);
                continue;
            }
            program.items.push(ListItem {
                operator: next_operator,
                pipeline,
            });
            self.skip_whitespace();
            next_operator = match self.peek_operator() {
                Some(Operator::And) => {
                    self.index += 1;
                    ListOperator::OnSuccess
                }
                Some(Operator::Or) => {
                    self.index += 1;
                    ListOperator::OnFailure
                }
                Some(Operator::Background) => {
                    self.index += 1;
                    ListOperator::Background
                }
                Some(Operator::Semicolon) => {
                    self.index += 1;
                    ListOperator::Always
                }
                _ if self.peek_kind(TokenKind::Newline) => {
                    self.index += 1;
                    ListOperator::Always
                }
                _ => ListOperator::Always,
            };
        }
        program
    }

    fn parse_pipeline(&mut self, stop_words: &[&str]) -> Pipeline {
        self.skip_whitespace();
        let mut pipeline = Pipeline::default();
        if self.peek_word("!") {
            self.consume_word();
            pipeline.negated = true;
        }
        loop {
            if self.at_stop_word(stop_words) {
                break;
            }
            let Some(command) = self.parse_command(stop_words) else {
                break;
            };
            pipeline.commands.push(command);
            self.skip_whitespace();
            if self.peek_operator() == Some(Operator::Pipe) {
                self.index += 1;
                self.skip_whitespace();
            } else {
                break;
            }
        }
        pipeline
    }

    fn parse_command(&mut self, stop_words: &[&str]) -> Option<Command> {
        self.skip_whitespace();
        if self.at_stop_word(stop_words) {
            return None;
        }
        if matches!(
            self.peek_operator(),
            Some(Operator::RightBrace | Operator::RightParen)
        ) {
            return None;
        }
        if self.peek_word("if") {
            let command = self.parse_if();
            return Some(self.with_trailing_redirections(command));
        }
        if self.peek_word("case") {
            let command = self.parse_case();
            return Some(self.with_trailing_redirections(command));
        }
        if self.peek_word("for") {
            let command = self.parse_for();
            return Some(self.with_trailing_redirections(command));
        }
        if self.peek_word("while") || self.peek_word("until") {
            let command = self.parse_while();
            return Some(self.with_trailing_redirections(command));
        }
        if self.peek_word("function") {
            let command = self.parse_function_keyword();
            return Some(self.with_trailing_redirections(command));
        }
        if self.peek_kind(TokenKind::ArithmeticCommand) {
            let token = self.tokens[self.index].clone();
            self.index += 1;
            let expression = token
                .text(self.source)
                .strip_prefix("((")
                .and_then(|value| value.strip_suffix("))"))
                .unwrap_or_default()
                .trim()
                .into();
            return Some(Command::Arithmetic { expression });
        }
        if self.peek_kind(TokenKind::ConditionalExpression) {
            let token = self.tokens[self.index].clone();
            self.index += 1;
            let expression = token
                .text(self.source)
                .strip_prefix("[[")
                .and_then(|value| value.strip_suffix("]]"))
                .unwrap_or_default()
                .trim()
                .into();
            return Some(Command::Conditional { expression });
        }
        if self.peek_operator() == Some(Operator::LeftBrace) {
            self.index += 1;
            let body = self.parse_program_until_operator(Operator::RightBrace);
            self.consume_operator(Operator::RightBrace);
            let command = Command::Group {
                body,
                subshell: false,
            };
            return Some(self.with_trailing_redirections(command));
        }
        if self.peek_operator() == Some(Operator::LeftParen) {
            self.index += 1;
            let body = self.parse_program_until_operator(Operator::RightParen);
            self.consume_operator(Operator::RightParen);
            let command = Command::Group {
                body,
                subshell: true,
            };
            return Some(self.with_trailing_redirections(command));
        }
        if let Some(function) = self.try_parse_function() {
            return Some(function);
        }
        Some(Command::Simple(self.parse_simple()))
    }

    fn with_trailing_redirections(&mut self, command: Command) -> Command {
        let redirections = self.parse_redirections();
        if redirections.is_empty() {
            command
        } else {
            Command::Redirected {
                command: Box::new(command),
                redirections,
            }
        }
    }

    fn parse_redirections(&mut self) -> Vec<Redirection> {
        let mut redirections = Vec::new();
        loop {
            self.skip_whitespace();
            let Some(Token {
                kind: TokenKind::Redirect { fd, kind },
                ..
            }) = self.tokens.get(self.index)
            else {
                break;
            };
            let fd = *fd;
            let kind = *kind;
            let raw = self.tokens[self.index].text(self.source);
            self.index += 1;
            let default_fd = u8::from(!matches!(
                kind,
                Redirect::Input | Redirect::HereDoc | Redirect::HereString
            ));
            let merge_fd = if kind == Redirect::Merge {
                raw.rsplit_once('&')
                    .and_then(|(_, value)| value.parse::<u8>().ok())
            } else {
                None
            };
            self.skip_whitespace();
            let target = if kind == Redirect::Merge {
                None
            } else {
                self.parse_word()
            };
            redirections.push(Redirection {
                fd: fd.unwrap_or(default_fd),
                kind: match kind {
                    Redirect::Input => RedirectKind::Input,
                    Redirect::Output => RedirectKind::Output,
                    Redirect::Append => RedirectKind::Append,
                    Redirect::HereDoc => RedirectKind::HereDoc,
                    Redirect::HereString => RedirectKind::HereString,
                    Redirect::Merge => RedirectKind::Merge,
                },
                target,
                merge_fd,
            });
        }
        redirections
    }

    fn parse_if(&mut self) -> Command {
        self.consume_keyword("if");
        let mut branches = Vec::new();
        loop {
            let condition = self.parse_program_until(&["then"]);
            self.consume_keyword("then");
            let body = self.parse_program_until(&["elif", "else", "fi"]);
            branches.push((condition, body));
            if self.peek_word("elif") {
                self.consume_keyword("elif");
                continue;
            }
            break;
        }
        let else_body = if self.peek_word("else") {
            self.consume_keyword("else");
            Some(self.parse_program_until(&["fi"]))
        } else {
            None
        };
        self.consume_keyword("fi");
        Command::If {
            branches,
            else_body,
        }
    }

    fn parse_case(&mut self) -> Command {
        self.consume_keyword("case");
        let word = self.consume_word().unwrap_or(Word {
            fragments: Vec::new(),
        });
        self.consume_keyword("in");
        let mut arms = Vec::new();
        loop {
            self.skip_separators();
            if self.peek_word("esac") || self.index >= self.tokens.len() {
                break;
            }
            if self.peek_operator() == Some(Operator::LeftParen) {
                self.index += 1;
            }
            let mut patterns = Vec::new();
            loop {
                self.skip_whitespace();
                if let Some(pattern) = self.parse_word() {
                    patterns.push(pattern);
                }
                self.skip_whitespace();
                if self.peek_operator() == Some(Operator::Pipe) {
                    self.index += 1;
                    continue;
                }
                break;
            }
            self.consume_operator(Operator::RightParen);
            let body = self.parse_program_until_case_terminator();
            self.consume_case_terminator();
            arms.push(CaseArm { patterns, body });
        }
        self.consume_keyword("esac");
        Command::Case { word, arms }
    }

    fn parse_for(&mut self) -> Command {
        self.consume_keyword("for");
        self.skip_whitespace();
        if self.peek_kind(TokenKind::ArithmeticCommand) {
            let token = self.tokens[self.index].clone();
            self.index += 1;
            let expression = token
                .text(self.source)
                .strip_prefix("((")
                .and_then(|value| value.strip_suffix("))"))
                .unwrap_or_default();
            let mut parts = expression.splitn(3, ';');
            let initializer = parts.next().unwrap_or_default().trim().into();
            let condition = parts.next().unwrap_or_default().trim().into();
            let update = parts.next().unwrap_or_default().trim().into();
            self.skip_separators();
            self.consume_keyword("do");
            let body = self.parse_program_until(&["done"]);
            self.consume_keyword("done");
            return Command::ForArithmetic {
                initializer,
                condition,
                update,
                body,
            };
        }
        let name = self
            .consume_word()
            .map(|word| self.render_word(&word))
            .unwrap_or_default();
        self.skip_whitespace();
        let mut words = Vec::new();
        if self.peek_word("in") {
            self.consume_keyword("in");
            loop {
                self.skip_whitespace();
                if self.at_separator() {
                    break;
                }
                let Some(word) = self.parse_word() else {
                    break;
                };
                words.push(word);
            }
        }
        self.skip_separators();
        self.consume_keyword("do");
        let body = self.parse_program_until(&["done"]);
        self.consume_keyword("done");
        Command::For { name, words, body }
    }

    fn parse_while(&mut self) -> Command {
        let until = self.peek_word("until");
        if until {
            self.consume_keyword("until");
        } else {
            self.consume_keyword("while");
        }
        let condition = self.parse_program_until(&["do"]);
        self.consume_keyword("do");
        let body = self.parse_program_until(&["done"]);
        self.consume_keyword("done");
        Command::While {
            condition,
            body,
            until,
        }
    }

    fn parse_function_keyword(&mut self) -> Command {
        self.consume_keyword("function");
        self.skip_whitespace();
        let name = self
            .consume_word()
            .map(|word| self.render_word(&word))
            .unwrap_or_default();
        self.skip_whitespace();
        if self.peek_operator() == Some(Operator::LeftParen) {
            self.index += 1;
            self.skip_whitespace();
            self.consume_operator(Operator::RightParen);
        }
        self.skip_separators();
        let body = self.parse_command(&[]).unwrap_or_else(|| {
            self.diagnostic_here("function body is missing");
            Command::Simple(SimpleCommand::default())
        });
        Command::Function {
            name,
            body: Box::new(body),
        }
    }

    fn try_parse_function(&mut self) -> Option<Command> {
        let saved = self.index;
        let name = self.consume_word()?;
        self.skip_whitespace();
        if self.peek_operator() != Some(Operator::LeftParen) {
            self.index = saved;
            return None;
        }
        self.index += 1;
        self.skip_whitespace();
        if self.peek_operator() != Some(Operator::RightParen) {
            self.index = saved;
            return None;
        }
        self.index += 1;
        self.skip_separators();
        let body = self.parse_command(&[])?;
        Some(Command::Function {
            name: self.render_word(&name),
            body: Box::new(body),
        })
    }

    fn parse_simple(&mut self) -> SimpleCommand {
        let mut command = SimpleCommand::default();
        loop {
            self.skip_whitespace();
            if self.index >= self.tokens.len() || self.at_separator() {
                break;
            }
            if let TokenKind::Redirect { fd, kind } = self.tokens[self.index].kind {
                let _ = (fd, kind);
                command.redirections.extend(self.parse_redirections());
                continue;
            }
            let Some(word) = self.parse_word() else {
                break;
            };
            command.words.push(word);
        }
        command
    }

    fn parse_word(&mut self) -> Option<Word> {
        let mut fragments = Vec::new();
        while let Some(token) = self.tokens.get(self.index) {
            if !matches!(
                token.kind,
                TokenKind::Word
                    | TokenKind::SingleQuoted
                    | TokenKind::DoubleQuoted
                    | TokenKind::Parameter
                    | TokenKind::CommandSubstitution
                    | TokenKind::ArithmeticSubstitution
                    | TokenKind::ArithmeticCommand
                    | TokenKind::ProcessSubstitution
                    | TokenKind::ArrayAssignment
                    | TokenKind::BacktickSubstitution
                    | TokenKind::Escape
            ) {
                break;
            }
            fragments.push(token.span);
            self.index += 1;
        }
        (!fragments.is_empty()).then_some(Word { fragments })
    }

    fn consume_word(&mut self) -> Option<Word> {
        self.skip_whitespace();
        self.parse_word()
    }

    fn parse_program_until_operator(&mut self, operator: Operator) -> Program {
        let mut program = Program::default();
        let mut next_operator = ListOperator::Always;
        loop {
            self.skip_separators();
            if self.index >= self.tokens.len() || self.peek_operator() == Some(operator) {
                break;
            }

            let start_index = self.index;
            let pipeline = self.parse_pipeline(&[]);
            if pipeline.commands.is_empty() || self.index == start_index {
                self.diagnostic_here("expected shell command");
                self.index = self.index.saturating_add(1);
                continue;
            }
            program.items.push(ListItem {
                operator: next_operator,
                pipeline,
            });
            self.skip_whitespace();
            next_operator = match self.peek_operator() {
                Some(Operator::And) => {
                    self.index += 1;
                    ListOperator::OnSuccess
                }
                Some(Operator::Or) => {
                    self.index += 1;
                    ListOperator::OnFailure
                }
                Some(Operator::Background) => {
                    self.index += 1;
                    ListOperator::Background
                }
                Some(Operator::Semicolon) => {
                    self.index += 1;
                    ListOperator::Always
                }
                _ => ListOperator::Always,
            };
        }
        program
    }

    fn parse_program_until_case_terminator(&mut self) -> Program {
        let mut program = Program::default();
        let mut next_operator = ListOperator::Always;
        loop {
            self.skip_case_separators();
            if self.index >= self.tokens.len()
                || self.peek_word("esac")
                || self.at_case_terminator()
            {
                break;
            }
            let start_index = self.index;
            let pipeline = self.parse_pipeline(&[]);
            if pipeline.commands.is_empty() || self.index == start_index {
                self.diagnostic_here("expected shell command");
                self.index = self.index.saturating_add(1);
                continue;
            }
            program.items.push(ListItem {
                operator: next_operator,
                pipeline,
            });
            self.skip_whitespace();
            if self.at_case_terminator() {
                break;
            }
            next_operator = match self.peek_operator() {
                Some(Operator::And) => {
                    self.index += 1;
                    ListOperator::OnSuccess
                }
                Some(Operator::Or) => {
                    self.index += 1;
                    ListOperator::OnFailure
                }
                Some(Operator::Background) => {
                    self.index += 1;
                    ListOperator::Background
                }
                Some(Operator::Semicolon) => {
                    self.index += 1;
                    ListOperator::Always
                }
                _ if self.peek_kind(TokenKind::Newline) => {
                    self.index += 1;
                    ListOperator::Always
                }
                _ => ListOperator::Always,
            };
        }
        program
    }

    fn skip_case_separators(&mut self) {
        loop {
            self.skip_whitespace();
            if self.at_case_terminator() {
                break;
            }
            if matches!(
                self.tokens.get(self.index).map(|token| &token.kind),
                Some(TokenKind::Newline | TokenKind::Operator(Operator::Semicolon))
            ) {
                self.index += 1;
            } else {
                break;
            }
        }
    }

    fn at_case_terminator(&self) -> bool {
        if self.peek_operator() != Some(Operator::Semicolon) {
            return false;
        }
        matches!(
            self.tokens
                .get(self.index + 1)
                .and_then(|token| match token.kind {
                    TokenKind::Operator(operator) => Some(operator),
                    _ => None,
                }),
            Some(Operator::Semicolon | Operator::Background)
        )
    }

    fn consume_case_terminator(&mut self) {
        if !self.at_case_terminator() {
            return;
        }
        self.index += 2;
        if self.peek_operator() == Some(Operator::Background) {
            self.index += 1;
        }
    }

    fn at_stop_word(&mut self, stop_words: &[&str]) -> bool {
        self.skip_whitespace();
        stop_words.iter().any(|word| self.peek_word(word))
    }

    fn at_separator(&self) -> bool {
        matches!(
            self.tokens.get(self.index).map(|token| &token.kind),
            None | Some(
                TokenKind::Newline
                    | TokenKind::Operator(
                        Operator::Semicolon
                            | Operator::And
                            | Operator::Or
                            | Operator::Pipe
                            | Operator::Background
                            | Operator::RightBrace
                            | Operator::RightParen
                    )
            )
        )
    }

    fn skip_whitespace(&mut self) {
        while matches!(
            self.tokens.get(self.index).map(|token| &token.kind),
            Some(TokenKind::Whitespace | TokenKind::Comment | TokenKind::HereDocBody)
        ) {
            self.index += 1;
        }
    }

    fn skip_separators(&mut self) {
        loop {
            self.skip_whitespace();
            if matches!(
                self.tokens.get(self.index).map(|token| &token.kind),
                Some(TokenKind::Newline | TokenKind::Operator(Operator::Semicolon))
            ) {
                self.index += 1;
            } else {
                break;
            }
        }
    }

    fn peek_operator(&self) -> Option<Operator> {
        match self.tokens.get(self.index).map(|token| &token.kind) {
            Some(TokenKind::Operator(operator)) => Some(*operator),
            _ => None,
        }
    }

    fn consume_operator(&mut self, operator: Operator) -> bool {
        self.skip_whitespace();
        if self.peek_operator() == Some(operator) {
            self.index += 1;
            true
        } else {
            self.diagnostic_here(&format!("expected {operator:?}"));
            false
        }
    }

    fn peek_kind(&self, kind: TokenKind) -> bool {
        self.tokens
            .get(self.index)
            .is_some_and(|token| token.kind == kind)
    }

    fn peek_word(&self, expected: &str) -> bool {
        let Some(token) = self.tokens.get(self.index) else {
            return false;
        };
        token.kind == TokenKind::Word && token.text(self.source) == expected
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        self.skip_separators();
        self.skip_whitespace();
        if self.peek_word(keyword) {
            self.index += 1;
            true
        } else {
            self.diagnostic_here(&format!("expected {keyword}"));
            false
        }
    }

    fn render_word(&self, word: &Word) -> String {
        word.fragments
            .iter()
            .map(|span| &self.source[span.start..span.end])
            .collect()
    }

    fn diagnostic_here(&mut self, message: &str) {
        let span = self
            .tokens
            .get(self.index)
            .map_or(Span { start: 0, end: 0 }, |token| token.span);
        self.diagnostics.push(Diagnostic {
            span,
            message: message.into(),
            fatal: false,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_shell_control_flow_and_functions() {
        let source = "greet() { echo hi; }\nif true; then for x in a b; do greet \"$x\"; done; else false; fi";
        let document = ParsedDocument::parse(source);
        assert!(
            document.diagnostics().is_empty(),
            "{:?}",
            document.diagnostics()
        );
        assert_eq!(document.program().items.len(), 2);
        assert!(matches!(
            document.program().items[0].pipeline.commands[0],
            Command::Function { .. }
        ));
        assert!(matches!(
            document.program().items[1].pipeline.commands[0],
            Command::If { .. }
        ));
    }

    #[test]
    fn unsupported_case_syntax_always_makes_parser_progress() {
        let source = r#"
case "$1" in
  --safe)
    echo safe
    ;;
  *)
    echo other
    ;;
esac
"#;
        let document = ParsedDocument::parse(source);

        assert!(
            document.diagnostics().is_empty(),
            "{:?}",
            document.diagnostics()
        );
        assert!(matches!(
            document.program().items[0].pipeline.commands[0],
            Command::Case { .. }
        ));
    }
}
