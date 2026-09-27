#[cfg(test)]
use std::cell::Cell;
use std::fmt;

#[cfg(test)]
thread_local! {
    static TOKENIZE_CALLS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub const fn len(self) -> usize {
        self.end - self.start
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentKind {
    Line,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringKind {
    Literal,
    Expandable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumberKind {
    Integer,
    Real,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delimiter {
    LeftParenthesis,
    RightParenthesis,
    LeftBrace,
    RightBrace,
    LeftBracket,
    RightBracket,
    Comma,
    Semicolon,
    Dot,
    Colon,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Whitespace,
    NewLine,
    LineContinuation,
    Comment(CommentKind),
    String(StringKind),
    HereString(StringKind),
    Variable,
    SplatVariable,
    Parameter,
    Number(NumberKind),
    VerbatimArgument,
    Keyword,
    Identifier,
    Operator,
    Delimiter(Delimiter),
    Unknown,
}

impl TokenKind {
    #[must_use]
    pub const fn is_trivia(self) -> bool {
        matches!(
            self,
            Self::Whitespace | Self::LineContinuation | Self::Comment(_)
        )
    }

    #[must_use]
    pub const fn is_comment(self) -> bool {
        matches!(self, Self::Comment(_))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

impl Token {
    #[must_use]
    pub fn text(self, source: &str) -> &str {
        &source[self.span.start..self.span.end]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub kind: DiagnosticKind,
    pub span: Span,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticKind {
    Lexical,
    Structural,
}

impl Diagnostic {
    #[must_use]
    pub const fn is_fatal(&self) -> bool {
        matches!(self.kind, DiagnosticKind::Lexical)
    }

    fn lexical(span: Span, message: impl Into<String>) -> Self {
        Self {
            kind: DiagnosticKind::Lexical,
            span,
            message: message.into(),
        }
    }

    fn structural(span: Span, message: impl Into<String>) -> Self {
        Self {
            kind: DiagnosticKind::Structural,
            span,
            message: message.into(),
        }
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} at byte range {}..{}",
            self.message, self.span.start, self.span.end
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tokenization {
    pub tokens: Vec<Token>,
    pub diagnostics: Vec<Diagnostic>,
    pub(crate) nested: Vec<NestedTokenization>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NestedTokenization {
    pub(crate) span: Span,
    pub(crate) tokens: Vec<Token>,
}

#[must_use]
pub fn tokenize(source: &str) -> Tokenization {
    #[cfg(test)]
    TOKENIZE_CALLS.with(|calls| calls.set(calls.get() + 1));
    Tokenizer::new(source).tokenize()
}

#[cfg(test)]
pub(crate) fn reset_tokenize_calls() {
    TOKENIZE_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn tokenize_calls() -> usize {
    TOKENIZE_CALLS.with(Cell::get)
}

#[derive(Debug)]
pub struct Tokenizer<'a> {
    source: &'a str,
    cursor: usize,
    tokens: Vec<Token>,
    diagnostics: Vec<Diagnostic>,
    nested: Vec<NestedTokenization>,
    verbatim_mode: bool,
}

impl<'a> Tokenizer<'a> {
    #[must_use]
    pub const fn new(source: &'a str) -> Self {
        Self {
            source,
            cursor: 0,
            tokens: Vec::new(),
            diagnostics: Vec::new(),
            nested: Vec::new(),
            verbatim_mode: false,
        }
    }

    #[must_use]
    pub fn tokenize(mut self) -> Tokenization {
        while self.cursor < self.source.len() {
            self.scan_token();
        }
        self.validate_delimiters();
        Tokenization {
            tokens: self.tokens,
            diagnostics: self.diagnostics,
            nested: self.nested,
        }
    }

    fn scan_token(&mut self) {
        let start = self.cursor;
        let Some(character) = self.peek_char() else {
            return;
        };

        if self.scan_verbatim_token(start, character) {
            return;
        }

        if is_horizontal_whitespace(character) {
            self.scan_horizontal_whitespace();
            self.push(TokenKind::Whitespace, start);
            return;
        }
        if matches!(character, '\r' | '\n') {
            self.scan_newline();
            self.push(TokenKind::NewLine, start);
            return;
        }
        if character == '`' && self.peek_line_break(1) {
            self.bump_char();
            self.scan_newline();
            self.push(TokenKind::LineContinuation, start);
            return;
        }
        if self.starts_with("<#") {
            self.scan_block_comment(start);
            return;
        }
        if character == '#' {
            self.scan_line_comment();
            self.push(TokenKind::Comment(CommentKind::Line), start);
            return;
        }
        if character == '@' {
            if let Some(kind) = self.here_string_kind() {
                self.scan_here_string(start, kind);
                return;
            }
            if self.peek_char_at(1).is_some_and(is_variable_start) {
                self.scan_splat_variable();
                self.push(TokenKind::SplatVariable, start);
                return;
            }
        }
        if is_quote(character) {
            let kind = if is_single_quote(character) {
                StringKind::Literal
            } else {
                StringKind::Expandable
            };
            self.scan_quoted_string(start, kind);
            return;
        }
        if character == '$' {
            self.scan_variable(start);
            return;
        }
        if self.is_redirection_start() {
            self.scan_redirection();
            self.push(TokenKind::Operator, start);
            return;
        }
        if character.is_ascii_digit()
            || (character == '.'
                && self
                    .peek_char_at(1)
                    .is_some_and(|next| next.is_ascii_digit()))
        {
            let kind = self.scan_number(start);
            self.push(TokenKind::Number(kind), start);
            return;
        }
        if is_dash(character) {
            self.scan_dash_token(start);
            return;
        }
        if let Some((kind, length)) = self.scan_symbol() {
            self.cursor += length;
            self.push(kind, start);
            return;
        }

        self.scan_bare_word();
        let text = &self.source[start..self.cursor];
        let kind = if is_keyword(text) {
            TokenKind::Keyword
        } else if text.is_empty() {
            self.bump_char();
            self.diagnostics.push(Diagnostic::lexical(
                Span::new(start, self.cursor),
                "unrecognized character",
            ));
            TokenKind::Unknown
        } else {
            TokenKind::Identifier
        };
        self.push(kind, start);
    }

    fn scan_horizontal_whitespace(&mut self) {
        while self.peek_char().is_some_and(is_horizontal_whitespace) {
            self.bump_char();
        }
    }

    fn scan_verbatim_token(&mut self, start: usize, character: char) -> bool {
        if !self.verbatim_mode {
            return false;
        }
        if matches!(character, '\r' | '\n' | '|') {
            self.verbatim_mode = false;
            return false;
        }
        if is_horizontal_whitespace(character) {
            self.scan_horizontal_whitespace();
            self.push(TokenKind::Whitespace, start);
            return true;
        }
        while self
            .peek_char()
            .is_some_and(|current| !matches!(current, '\r' | '\n' | '|'))
        {
            self.bump_char();
        }
        self.push(TokenKind::VerbatimArgument, start);
        true
    }

    fn scan_newline(&mut self) {
        if self.starts_with("\r\n") {
            self.cursor += 2;
        } else {
            self.bump_char();
        }
    }

    fn scan_line_comment(&mut self) {
        while self
            .peek_char()
            .is_some_and(|character| !matches!(character, '\r' | '\n'))
        {
            self.bump_char();
        }
    }

    fn scan_block_comment(&mut self, start: usize) {
        self.cursor += 2;
        if let Some(relative_end) = self.source[self.cursor..].find("#>") {
            self.cursor += relative_end + 2;
        } else {
            self.cursor = self.source.len();
            self.diagnostics.push(Diagnostic::lexical(
                Span::new(start, self.cursor),
                "unterminated block comment",
            ));
        }
        self.push(TokenKind::Comment(CommentKind::Block), start);
    }

    fn here_string_kind(&self) -> Option<StringKind> {
        let quote = self.peek_char_at(1)?;
        let kind = if is_single_quote(quote) {
            StringKind::Literal
        } else if is_double_quote(quote) {
            StringKind::Expandable
        } else {
            return None;
        };
        let mut offset = 1 + quote.len_utf8();
        while self
            .peek_char_at(offset)
            .is_some_and(is_horizontal_whitespace)
        {
            offset += self.peek_char_at(offset)?.len_utf8();
        }
        self.peek_line_break(offset).then_some(kind)
    }

    fn scan_here_string(&mut self, start: usize, kind: StringKind) {
        if self.consume_here_string(kind) {
            self.push(TokenKind::HereString(kind), start);
            return;
        }
        self.diagnostics.push(Diagnostic::lexical(
            Span::new(start, self.cursor),
            "unterminated here-string",
        ));
        self.push(TokenKind::HereString(kind), start);
    }

    fn consume_here_string(&mut self, kind: StringKind) -> bool {
        self.bump_char();
        self.bump_char();
        self.scan_horizontal_whitespace();
        if !self
            .peek_char()
            .is_some_and(|character| matches!(character, '\r' | '\n'))
        {
            return false;
        }
        self.scan_newline();
        let mut at_line_start = true;
        while self.cursor < self.source.len() {
            if at_line_start
                && self.peek_char().is_some_and(|character| {
                    matches!(kind, StringKind::Literal) && is_single_quote(character)
                        || matches!(kind, StringKind::Expandable) && is_double_quote(character)
                })
                && self
                    .peek_char()
                    .and_then(|character| self.peek_char_at(character.len_utf8()))
                    == Some('@')
            {
                self.bump_char();
                self.bump_char();
                return true;
            }
            if kind == StringKind::Expandable
                && self.peek_char() == Some('$')
                && self.peek_char_at(1) == Some('(')
            {
                self.bump_char();
                self.bump_char();
                let nested_start = self.cursor.saturating_sub(1);
                if !self.scan_subexpression(1) {
                    return false;
                }
                self.record_nested_tokens(nested_start, self.cursor);
                at_line_start = false;
                continue;
            }
            let Some(character) = self.bump_char() else {
                break;
            };
            at_line_start = match character {
                '\n' => true,
                '\r' => self.peek_char() != Some('\n'),
                _ => false,
            };
        }
        false
    }

    fn scan_quoted_string(&mut self, start: usize, kind: StringKind) {
        self.bump_char();
        if self.scan_quoted_body(kind, 0) {
            self.push(TokenKind::String(kind), start);
            return;
        }
        self.diagnostics.push(Diagnostic::lexical(
            Span::new(start, self.cursor),
            "unterminated string literal",
        ));
        self.push(TokenKind::String(kind), start);
    }

    fn scan_quoted_body(&mut self, kind: StringKind, depth: usize) -> bool {
        const MAX_NESTED_EXPANSION_DEPTH: usize = 128;
        if depth >= MAX_NESTED_EXPANSION_DEPTH {
            return false;
        }
        while let Some(character) = self.bump_char() {
            if kind == StringKind::Expandable && character == '`' {
                self.consume_escape_tail();
                continue;
            }
            if kind == StringKind::Expandable && character == '$' && self.peek_char() == Some('(') {
                self.bump_char();
                let nested_start = self.cursor.saturating_sub(1);
                if !self.scan_subexpression(depth + 1) {
                    return false;
                }
                let nested_end = self.cursor;
                self.record_nested_tokens(nested_start, nested_end);
                continue;
            }
            let closing = match kind {
                StringKind::Literal => is_single_quote(character),
                StringKind::Expandable => is_double_quote(character),
            };
            if closing {
                let doubled = self.peek_char().is_some_and(|next| match kind {
                    StringKind::Literal => is_single_quote(next),
                    StringKind::Expandable => is_double_quote(next),
                });
                if doubled {
                    self.bump_char();
                    continue;
                }
                return true;
            }
        }
        false
    }

    fn scan_subexpression(&mut self, depth: usize) -> bool {
        const MAX_NESTED_EXPANSION_DEPTH: usize = 128;
        if depth >= MAX_NESTED_EXPANSION_DEPTH {
            return false;
        }
        let mut parentheses = 1_usize;
        let mut token_start = true;
        while let Some(character) = self.peek_char() {
            if character == '`' {
                self.consume_backtick_escape();
                token_start = false;
                continue;
            }
            if character == '@' {
                if let Some(kind) = self.here_string_kind() {
                    if !self.consume_here_string(kind) {
                        return false;
                    }
                    token_start = false;
                    continue;
                }
            }
            if token_start && self.starts_with("<#") {
                self.cursor += 2;
                let Some(relative_end) = self.source[self.cursor..].find("#>") else {
                    self.cursor = self.source.len();
                    return false;
                };
                self.cursor += relative_end + 2;
                token_start = true;
                continue;
            }
            if is_single_quote(character) || is_double_quote(character) {
                let kind = if is_single_quote(character) {
                    StringKind::Literal
                } else {
                    StringKind::Expandable
                };
                self.bump_char();
                if !self.scan_quoted_body(kind, depth + 1) {
                    return false;
                }
                token_start = false;
                continue;
            }
            if character == '#' && token_start {
                self.scan_line_comment();
                token_start = true;
                continue;
            }
            self.bump_char();
            match character {
                '(' => {
                    parentheses += 1;
                    token_start = true;
                }
                ')' => {
                    parentheses = parentheses.saturating_sub(1);
                    if parentheses == 0 {
                        return true;
                    }
                    token_start = false;
                }
                '\r' | '\n' | ';' | ',' | '|' | '&' | '{' | '}' | '[' | ']' => {
                    token_start = true;
                }
                character if is_horizontal_whitespace(character) => token_start = true,
                _ => token_start = false,
            }
        }
        false
    }

    fn scan_variable(&mut self, start: usize) {
        self.bump_char();
        if self.peek_char() == Some('{') {
            self.bump_char();
            let name_start = self.cursor;
            while let Some(character) = self.bump_char() {
                if character == '`' {
                    self.consume_escape_tail();
                    continue;
                }
                if character == '}' {
                    if self.cursor - character.len_utf8() == name_start {
                        self.diagnostics.push(Diagnostic::lexical(
                            Span::new(start, self.cursor),
                            "empty braced variable",
                        ));
                    }
                    self.push(TokenKind::Variable, start);
                    return;
                }
            }
            self.diagnostics.push(Diagnostic::lexical(
                Span::new(start, self.cursor),
                "unterminated braced variable",
            ));
            self.push(TokenKind::Variable, start);
            return;
        }

        if self.scan_unbraced_variable_name() {
            self.push(TokenKind::Variable, start);
        } else {
            self.push(TokenKind::Operator, start);
        }
    }

    fn scan_splat_variable(&mut self) {
        self.bump_char();
        self.scan_unbraced_variable_name();
    }

    fn scan_unbraced_variable_name(&mut self) -> bool {
        let Some(first) = self.peek_char() else {
            return false;
        };
        if !is_variable_start(first) {
            return false;
        }
        self.bump_char();
        if matches!(first, '$' | '?' | '^') {
            return true;
        }
        while let Some(character) = self.peek_char() {
            if is_variable_continue(character)
                || character == ':' && self.peek_char_at(1) != Some(':')
            {
                self.bump_char();
            } else {
                break;
            }
        }
        true
    }

    fn scan_number(&mut self, start: usize) -> NumberKind {
        if self.starts_with_case_insensitive("0x") {
            self.cursor += 2;
            if self.scan_digits(|character| character.is_ascii_hexdigit()) == 0 {
                self.diagnostics.push(Diagnostic::lexical(
                    Span::new(start, self.cursor),
                    "hexadecimal literal requires at least one digit",
                ));
            }
            self.scan_number_suffix();
            return NumberKind::Integer;
        }
        if self.starts_with_case_insensitive("0b") {
            self.cursor += 2;
            if self.scan_digits(|character| matches!(character, '0' | '1')) == 0 {
                self.diagnostics.push(Diagnostic::lexical(
                    Span::new(start, self.cursor),
                    "binary literal requires at least one digit",
                ));
            }
            self.scan_number_suffix();
            return NumberKind::Integer;
        }

        let mut kind = NumberKind::Integer;
        self.scan_digits(|character| character.is_ascii_digit());
        if self.peek_char() == Some('.') && self.peek_char_at(1) != Some('.') {
            kind = NumberKind::Real;
            self.bump_char();
            self.scan_digits(|character| character.is_ascii_digit());
        }
        if self
            .peek_char()
            .is_some_and(|character| matches!(character, 'e' | 'E'))
        {
            kind = NumberKind::Real;
            self.bump_char();
            if self
                .peek_char()
                .is_some_and(|character| matches!(character, '+' | '-'))
            {
                self.bump_char();
            }
            if self.scan_digits(|character| character.is_ascii_digit()) == 0 {
                self.diagnostics.push(Diagnostic::lexical(
                    Span::new(start, self.cursor),
                    "numeric exponent requires at least one digit",
                ));
            }
        }
        self.scan_number_suffix();
        kind
    }

    fn scan_digits(&mut self, predicate: impl Fn(char) -> bool) -> usize {
        let mut digits = 0;
        while self
            .peek_char()
            .is_some_and(|character| predicate(character) || character == '_')
        {
            if self.peek_char().is_some_and(&predicate) {
                digits += 1;
            }
            self.bump_char();
        }
        digits
    }

    fn scan_number_suffix(&mut self) {
        while self.peek_char().is_some_and(|character| {
            matches!(
                character.to_ascii_lowercase(),
                'u' | 'l' | 'd' | 'y' | 's' | 'b' | 'k' | 'm' | 'g' | 't' | 'p'
            )
        }) {
            self.bump_char();
        }
    }

    fn scan_dash_token(&mut self, start: usize) {
        if self.starts_with("--%") {
            self.cursor += "--%".len();
            self.push(TokenKind::Operator, start);
            self.verbatim_mode = true;
            return;
        }
        let Some(dash) = self.bump_char() else {
            return;
        };
        if self.peek_char().is_some_and(char::is_alphabetic) {
            while self.peek_char().is_some_and(|character| {
                character.is_alphanumeric() || is_dash(character) || character == '_'
            }) {
                self.bump_char();
            }
            let text = &self.source[start..self.cursor];
            let normalized = format!("-{}", &text[dash.len_utf8()..]);
            let kind = if is_word_operator(&normalized) {
                TokenKind::Operator
            } else {
                TokenKind::Parameter
            };
            self.push(kind, start);
            return;
        }
        if self.peek_char() == Some('=') || self.peek_char().is_some_and(is_dash) {
            self.bump_char();
        }
        self.push(TokenKind::Operator, start);
    }

    fn scan_symbol(&self) -> Option<(TokenKind, usize)> {
        for operator in [
            "??=", "2>&1", "1>&2", "&&", "||", "::", "?.", "?[", "..", "++", "+=", "*=", "/=",
            "%=", "??", "==", "!=", "<=", ">=", ">>", ">&", "=>",
        ] {
            if self.starts_with(operator) {
                return Some((TokenKind::Operator, operator.len()));
            }
        }

        let character = self.peek_char()?;
        let kind = match character {
            '(' => TokenKind::Delimiter(Delimiter::LeftParenthesis),
            ')' => TokenKind::Delimiter(Delimiter::RightParenthesis),
            '{' => TokenKind::Delimiter(Delimiter::LeftBrace),
            '}' => TokenKind::Delimiter(Delimiter::RightBrace),
            '[' => TokenKind::Delimiter(Delimiter::LeftBracket),
            ']' => TokenKind::Delimiter(Delimiter::RightBracket),
            ',' => TokenKind::Delimiter(Delimiter::Comma),
            ';' => TokenKind::Delimiter(Delimiter::Semicolon),
            '.' => TokenKind::Delimiter(Delimiter::Dot),
            ':' => TokenKind::Delimiter(Delimiter::Colon),
            '|' | '&' | '=' | '+' | '*' | '/' | '%' | '!' | '?' | '<' | '>' | '@' => {
                TokenKind::Operator
            }
            _ => return None,
        };
        Some((kind, character.len_utf8()))
    }

    fn is_redirection_start(&self) -> bool {
        let Some(character) = self.peek_char() else {
            return false;
        };
        if character == '*' {
            return self.peek_char_at(1) == Some('>');
        }
        if !character.is_ascii_digit() {
            return false;
        }
        let mut offset = character.len_utf8();
        while self
            .peek_char_at(offset)
            .is_some_and(|next| next.is_ascii_digit())
        {
            offset += 1;
        }
        self.peek_char_at(offset) == Some('>')
    }

    fn scan_redirection(&mut self) {
        while self
            .peek_char()
            .is_some_and(|character| character.is_ascii_digit() || character == '*')
        {
            self.bump_char();
        }
        if self.peek_char() == Some('>') {
            self.bump_char();
        }
        if self.peek_char() == Some('>') {
            self.bump_char();
        }
        if self.peek_char() == Some('&') {
            self.bump_char();
            while self
                .peek_char()
                .is_some_and(|character| character.is_ascii_digit())
            {
                self.bump_char();
            }
        }
    }

    fn scan_bare_word(&mut self) {
        while let Some(character) = self.peek_char() {
            if is_bare_word_boundary(character) {
                break;
            }
            if character == '`' {
                self.consume_backtick_escape();
            } else {
                self.bump_char();
            }
        }
    }

    fn push(&mut self, kind: TokenKind, start: usize) {
        self.tokens.push(Token {
            kind,
            span: Span::new(start, self.cursor),
        });
    }

    fn validate_delimiters(&mut self) {
        let mut stack = Vec::<(Delimiter, Token)>::new();
        for token in self.tokens.iter().copied() {
            if let Some(open) = opening_delimiter(token, self.source) {
                stack.push((open, token));
                continue;
            }
            if let TokenKind::Delimiter(
                close @ (Delimiter::RightParenthesis
                | Delimiter::RightBrace
                | Delimiter::RightBracket),
            ) = token.kind
            {
                let Some((open_kind, open_token)) = stack.pop() else {
                    self.diagnostics.push(Diagnostic::structural(
                        token.span,
                        format!("unmatched closing delimiter {}", token.text(self.source)),
                    ));
                    continue;
                };
                if !delimiters_match(open_kind, close) {
                    self.diagnostics.push(Diagnostic::structural(
                        token.span,
                        format!(
                            "mismatched delimiter {} after {}",
                            token.text(self.source),
                            open_token.text(self.source)
                        ),
                    ));
                }
            }
        }
        for (_, token) in stack {
            self.diagnostics.push(Diagnostic::structural(
                token.span,
                format!("unclosed delimiter {}", token.text(self.source)),
            ));
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.source[self.cursor..].chars().next()
    }

    fn peek_char_at(&self, byte_offset: usize) -> Option<char> {
        self.source.get(self.cursor + byte_offset..)?.chars().next()
    }

    fn bump_char(&mut self) -> Option<char> {
        let character = self.peek_char()?;
        self.cursor += character.len_utf8();
        Some(character)
    }

    fn consume_backtick_escape(&mut self) {
        if self.bump_char() == Some('`') {
            self.consume_escape_tail();
        }
    }

    fn consume_escape_tail(&mut self) {
        let Some(escaped) = self.bump_char() else {
            return;
        };
        if escaped != 'u' || self.peek_char() != Some('{') {
            return;
        }
        self.bump_char();
        let mut digits = 0_usize;
        while digits < 6
            && self
                .peek_char()
                .is_some_and(|character| character.is_ascii_hexdigit())
        {
            self.bump_char();
            digits += 1;
        }
        if digits > 0 && self.peek_char() == Some('}') {
            self.bump_char();
        }
    }

    fn record_nested_tokens(&mut self, start: usize, end: usize) {
        if start >= end {
            return;
        }
        let nested = Tokenizer::new(&self.source[start..end]).tokenize();
        let tokens = nested
            .tokens
            .into_iter()
            .map(|token| Token {
                kind: token.kind,
                span: Span::new(token.span.start + start, token.span.end + start),
            })
            .collect();
        self.diagnostics
            .extend(nested.diagnostics.into_iter().map(|diagnostic| Diagnostic {
                kind: diagnostic.kind,
                span: Span::new(diagnostic.span.start + start, diagnostic.span.end + start),
                message: diagnostic.message,
            }));
        self.nested.push(NestedTokenization {
            span: Span::new(start, end),
            tokens,
        });
        self.nested.extend(nested.nested.into_iter().map(|nested| {
            NestedTokenization {
                span: Span::new(nested.span.start + start, nested.span.end + start),
                tokens: nested
                    .tokens
                    .into_iter()
                    .map(|token| Token {
                        kind: token.kind,
                        span: Span::new(token.span.start + start, token.span.end + start),
                    })
                    .collect(),
            }
        }));
    }

    fn starts_with(&self, value: &str) -> bool {
        self.source[self.cursor..].starts_with(value)
    }

    fn starts_with_case_insensitive(&self, value: &str) -> bool {
        self.source[self.cursor..]
            .get(..value.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(value))
    }

    fn peek_line_break(&self, byte_offset: usize) -> bool {
        self.source
            .get(self.cursor + byte_offset..)
            .is_some_and(|remainder| remainder.starts_with('\n') || remainder.starts_with("\r\n"))
    }
}

fn is_variable_start(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '?' | '^' | '$')
}

fn is_variable_continue(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '?')
}

fn is_horizontal_whitespace(character: char) -> bool {
    character.is_whitespace() && !matches!(character, '\r' | '\n')
}

pub(crate) const fn is_single_quote(character: char) -> bool {
    matches!(
        character,
        '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}'
    )
}

pub(crate) const fn is_double_quote(character: char) -> bool {
    matches!(character, '"' | '\u{201c}' | '\u{201d}' | '\u{201e}')
}

const fn is_quote(character: char) -> bool {
    is_single_quote(character) || is_double_quote(character)
}

const fn is_dash(character: char) -> bool {
    matches!(character, '-' | '\u{2013}' | '\u{2014}' | '\u{2015}')
}

const fn is_special_dash(character: char) -> bool {
    matches!(character, '\u{2013}' | '\u{2014}' | '\u{2015}')
}

fn opening_delimiter(token: Token, source: &str) -> Option<Delimiter> {
    match token.kind {
        TokenKind::Delimiter(
            open @ (Delimiter::LeftParenthesis | Delimiter::LeftBrace | Delimiter::LeftBracket),
        ) => Some(open),
        TokenKind::Operator if token.text(source) == "?[" => Some(Delimiter::LeftBracket),
        _ => None,
    }
}

const fn delimiters_match(open: Delimiter, close: Delimiter) -> bool {
    matches!(
        (open, close),
        (Delimiter::LeftParenthesis, Delimiter::RightParenthesis)
            | (Delimiter::LeftBrace, Delimiter::RightBrace)
            | (Delimiter::LeftBracket, Delimiter::RightBracket)
    )
}

fn is_bare_word_boundary(character: char) -> bool {
    character.is_whitespace()
        || is_quote(character)
        || is_special_dash(character)
        || matches!(
            character,
            '$' | '('
                | ')'
                | '{'
                | '}'
                | '['
                | ']'
                | ','
                | ';'
                | '.'
                | ':'
                | '|'
                | '&'
                | '='
                | '+'
                | '*'
                | '/'
                | '%'
                | '!'
                | '?'
                | '<'
                | '>'
        )
}

fn is_keyword(value: &str) -> bool {
    [
        "begin",
        "break",
        "catch",
        "class",
        "continue",
        "data",
        "define",
        "do",
        "dynamicparam",
        "else",
        "elseif",
        "end",
        "enum",
        "exit",
        "filter",
        "finally",
        "for",
        "foreach",
        "from",
        "function",
        "if",
        "in",
        "inlinescript",
        "param",
        "parallel",
        "private",
        "process",
        "public",
        "return",
        "sequence",
        "static",
        "switch",
        "throw",
        "trap",
        "try",
        "until",
        "using",
        "var",
        "while",
        "workflow",
        "configuration",
        "interface",
    ]
    .iter()
    .any(|keyword| value.eq_ignore_ascii_case(keyword))
}

fn is_word_operator(value: &str) -> bool {
    [
        "-and",
        "-as",
        "-band",
        "-bnot",
        "-bor",
        "-bxor",
        "-ceq",
        "-cge",
        "-cgt",
        "-cle",
        "-clike",
        "-clt",
        "-cmatch",
        "-cne",
        "-ccontains",
        "-cnotcontains",
        "-cnotlike",
        "-cnotmatch",
        "-contains",
        "-creplace",
        "-csplit",
        "-eq",
        "-f",
        "-ge",
        "-gt",
        "-icontains",
        "-ieq",
        "-ige",
        "-igt",
        "-ile",
        "-ilike",
        "-ilt",
        "-imatch",
        "-in",
        "-ine",
        "-inotcontains",
        "-inotlike",
        "-inotmatch",
        "-ireplace",
        "-is",
        "-isnot",
        "-isplit",
        "-join",
        "-le",
        "-like",
        "-lt",
        "-match",
        "-ne",
        "-not",
        "-notcontains",
        "-notin",
        "-notlike",
        "-notmatch",
        "-or",
        "-replace",
        "-shl",
        "-shr",
        "-split",
        "-xor",
    ]
    .iter()
    .any(|operator| value.eq_ignore_ascii_case(operator))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(source: &str) -> Vec<TokenKind> {
        tokenize(source)
            .tokens
            .into_iter()
            .filter(|token| !token.kind.is_trivia())
            .map(|token| token.kind)
            .collect()
    }

    #[test]
    fn tokenizes_variables_parameters_operators_and_delimiters() {
        let source = "$env:TEMP = [Text.Encoding]::UTF8.GetString($bytes) -replace 'x','y'";
        let tokenization = tokenize(source);

        assert!(tokenization.diagnostics.is_empty());
        assert_eq!(
            kinds(source),
            vec![
                TokenKind::Variable,
                TokenKind::Operator,
                TokenKind::Delimiter(Delimiter::LeftBracket),
                TokenKind::Identifier,
                TokenKind::Delimiter(Delimiter::Dot),
                TokenKind::Identifier,
                TokenKind::Delimiter(Delimiter::RightBracket),
                TokenKind::Operator,
                TokenKind::Identifier,
                TokenKind::Delimiter(Delimiter::Dot),
                TokenKind::Identifier,
                TokenKind::Delimiter(Delimiter::LeftParenthesis),
                TokenKind::Variable,
                TokenKind::Delimiter(Delimiter::RightParenthesis),
                TokenKind::Operator,
                TokenKind::String(StringKind::Literal),
                TokenKind::Delimiter(Delimiter::Comma),
                TokenKind::String(StringKind::Literal),
            ]
        );
    }

    #[test]
    fn keeps_strings_comments_and_line_continuations_atomic() {
        let source = "Write-Output \"a`n#b\" `\r\n  # comment\r\n'x''y'";
        let tokenization = tokenize(source);

        assert!(tokenization.diagnostics.is_empty());
        assert!(tokenization
            .tokens
            .iter()
            .any(|token| token.kind == TokenKind::LineContinuation));
        assert!(tokenization.tokens.iter().any(|token| {
            token.kind == TokenKind::Comment(CommentKind::Line) && token.text(source) == "# comment"
        }));
        assert!(tokenization.tokens.iter().any(|token| {
            token.kind == TokenKind::String(StringKind::Expandable)
                && token.text(source) == "\"a`n#b\""
        }));
    }

    #[test]
    fn tokenizes_here_strings_as_single_tokens() {
        let source = "$x = @\"\nline one\n$expanded\n\"@\n$y = @'\nliteral\n'@";
        let tokenization = tokenize(source);
        let here_strings = tokenization
            .tokens
            .iter()
            .filter(|token| matches!(token.kind, TokenKind::HereString(_)))
            .collect::<Vec<_>>();

        assert!(tokenization.diagnostics.is_empty());
        assert_eq!(here_strings.len(), 2);
        assert_eq!(
            here_strings[0].kind,
            TokenKind::HereString(StringKind::Expandable)
        );
        assert_eq!(
            here_strings[1].kind,
            TokenKind::HereString(StringKind::Literal)
        );
    }

    #[test]
    fn accepts_here_string_header_space_and_trailing_footer_syntax() {
        let source = "$x = @' \nvalue\n'@ | Write-Output";
        let tokenization = tokenize(source);
        let significant = tokenization
            .tokens
            .iter()
            .copied()
            .filter(|token| !token.kind.is_trivia())
            .collect::<Vec<_>>();

        assert!(tokenization.diagnostics.is_empty());
        assert_eq!(
            significant
                .iter()
                .map(|token| token.kind)
                .collect::<Vec<_>>(),
            [
                TokenKind::Variable,
                TokenKind::Operator,
                TokenKind::HereString(StringKind::Literal),
                TokenKind::Operator,
                TokenKind::Identifier,
            ]
        );
        assert_eq!(significant[2].text(source), "@' \nvalue\n'@");
    }

    #[test]
    fn keeps_nested_subexpressions_inside_expandable_strings() {
        let source = r#""$(if ($true) { "yes" } else { "no" })""#;
        let tokenization = tokenize(source);

        assert!(tokenization.diagnostics.is_empty());
        assert_eq!(tokenization.tokens.len(), 1);
        assert_eq!(
            tokenization.tokens[0].kind,
            TokenKind::String(StringKind::Expandable)
        );
        assert_eq!(tokenization.tokens[0].text(source), source);
    }

    #[test]
    fn respects_variable_boundaries_and_unicode_names() {
        let source = "$i-- $_-BXor $type::Member $fg$bg $végösszeg $env:PATH";
        let significant = tokenize(source)
            .tokens
            .into_iter()
            .filter(|token| !token.kind.is_trivia())
            .map(|token| (token.kind, token.text(source)))
            .collect::<Vec<_>>();

        assert_eq!(
            significant,
            [
                (TokenKind::Variable, "$i"),
                (TokenKind::Operator, "--"),
                (TokenKind::Variable, "$_"),
                (TokenKind::Operator, "-BXor"),
                (TokenKind::Variable, "$type"),
                (TokenKind::Operator, "::"),
                (TokenKind::Identifier, "Member"),
                (TokenKind::Variable, "$fg"),
                (TokenKind::Variable, "$bg"),
                (TokenKind::Variable, "$végösszeg"),
                (TokenKind::Variable, "$env:PATH"),
            ]
        );
    }

    #[test]
    fn supports_unicode_whitespace_quotes_and_dashes() {
        let source = "$x\u{00a0}=\u{00a0}“value”\nWrite-Output –NoEnumerate 3 – 2";
        let tokenization = tokenize(source);
        let significant = tokenization
            .tokens
            .iter()
            .copied()
            .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
            .collect::<Vec<_>>();

        assert!(tokenization.diagnostics.is_empty());
        assert_eq!(
            significant[2].kind,
            TokenKind::String(StringKind::Expandable)
        );
        assert_eq!(significant[4].kind, TokenKind::Parameter);
        assert_eq!(significant[6].kind, TokenKind::Operator);
    }

    #[test]
    fn starts_line_comments_only_at_token_boundaries() {
        let source = "Write-Output value#suffix https://example/payload#fragment # comment";
        let tokenization = tokenize(source);
        let comments = tokenization
            .tokens
            .iter()
            .filter(|token| token.kind == TokenKind::Comment(CommentKind::Line))
            .collect::<Vec<_>>();

        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].text(source), "# comment");
        assert!(tokenization
            .tokens
            .iter()
            .any(|token| token.text(source) == "value#suffix"));
        assert!(tokenization
            .tokens
            .iter()
            .any(|token| token.text(source) == "payload#fragment"));
    }

    #[test]
    fn recognizes_modern_compound_and_stop_parsing_tokens() {
        let source = "${value}?.Name ${items}?[0]\ncmd.exe --% /c echo %PATH% & literal | next";
        let tokenization = tokenize(source);
        let significant = tokenization
            .tokens
            .iter()
            .copied()
            .filter(|token| !token.kind.is_trivia() && token.kind != TokenKind::NewLine)
            .map(|token| (token.kind, token.text(source)))
            .collect::<Vec<_>>();

        assert!(tokenization.diagnostics.is_empty());
        assert!(significant.contains(&(TokenKind::Operator, "?.")));
        assert!(significant.contains(&(TokenKind::Operator, "?[")));
        assert!(significant.contains(&(TokenKind::Operator, "--%")));
        assert!(significant.contains(&(TokenKind::VerbatimArgument, "/c echo %PATH% & literal ")));
    }

    #[test]
    fn recognizes_current_language_keywords() {
        for keyword in [
            "parallel",
            "sequence",
            "inlinescript",
            "configuration",
            "public",
            "private",
            "static",
            "interface",
        ] {
            assert_eq!(kinds(keyword), [TokenKind::Keyword], "{keyword}");
        }
    }

    #[test]
    fn permits_escaped_closing_braces_in_braced_variables() {
        for source in ["${name`}suffix}", "${name`u{2195}}"] {
            let tokenization = tokenize(source);

            assert!(tokenization.diagnostics.is_empty(), "{source}");
            assert_eq!(tokenization.tokens.len(), 1, "{source}");
            assert_eq!(tokenization.tokens[0].kind, TokenKind::Variable, "{source}");
        }
    }

    #[test]
    fn reports_unterminated_constructs_without_dropping_tokens() {
        let tokenization = tokenize("$x = \"unterminated");

        assert_eq!(tokenization.diagnostics.len(), 1);
        assert!(tokenization
            .tokens
            .iter()
            .any(|token| matches!(token.kind, TokenKind::String(_))));
    }

    #[test]
    fn recognizes_numeric_forms_and_redirections() {
        let source = "0x41 0b1010 1.5e2 10kb 2>&1 *>>";
        assert_eq!(
            kinds(source),
            vec![
                TokenKind::Number(NumberKind::Integer),
                TokenKind::Number(NumberKind::Integer),
                TokenKind::Number(NumberKind::Real),
                TokenKind::Number(NumberKind::Integer),
                TokenKind::Operator,
                TokenKind::Operator,
            ]
        );
    }

    #[test]
    fn reports_incomplete_numeric_literals() {
        let tokenization = tokenize("0x 0b 1e+");

        assert_eq!(tokenization.diagnostics.len(), 3);
        assert!(tokenization
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("hexadecimal")));
        assert!(tokenization
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("binary")));
        assert!(tokenization
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.message.contains("exponent")));
    }

    #[test]
    fn reports_mismatched_delimiters_as_structural() {
        let tokenization = tokenize("($value]");

        assert_eq!(tokenization.diagnostics.len(), 1);
        assert_eq!(tokenization.diagnostics[0].kind, DiagnosticKind::Structural);
        assert!(tokenization.diagnostics[0]
            .message
            .contains("mismatched delimiter"));
    }

    #[test]
    fn keeps_hyphenated_command_names_distinct_from_parameters() {
        let source = "Invoke-WebRequest -Uri https://example.invalid";
        let significant = tokenize(source)
            .tokens
            .into_iter()
            .filter(|token| !token.kind.is_trivia())
            .collect::<Vec<_>>();

        assert_eq!(significant[0].kind, TokenKind::Identifier);
        assert_eq!(significant[0].text(source), "Invoke-WebRequest");
        assert_eq!(significant[1].kind, TokenKind::Parameter);
        assert_eq!(significant[1].text(source), "-Uri");
    }
}
