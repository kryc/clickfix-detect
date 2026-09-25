use std::fmt;

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
    pub span: Span,
    pub message: String,
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
}

#[must_use]
pub fn tokenize(source: &str) -> Tokenization {
    Tokenizer::new(source).tokenize()
}

#[derive(Debug)]
pub struct Tokenizer<'a> {
    source: &'a str,
    cursor: usize,
    tokens: Vec<Token>,
    diagnostics: Vec<Diagnostic>,
}

impl<'a> Tokenizer<'a> {
    #[must_use]
    pub const fn new(source: &'a str) -> Self {
        Self {
            source,
            cursor: 0,
            tokens: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    #[must_use]
    pub fn tokenize(mut self) -> Tokenization {
        while self.cursor < self.source.len() {
            self.scan_token();
        }
        Tokenization {
            tokens: self.tokens,
            diagnostics: self.diagnostics,
        }
    }

    fn scan_token(&mut self) {
        let start = self.cursor;
        let Some(character) = self.peek_char() else {
            return;
        };

        if matches!(character, ' ' | '\t' | '\u{000b}' | '\u{000c}') {
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
        if matches!(character, '\'' | '"') {
            let kind = if character == '\'' {
                StringKind::Literal
            } else {
                StringKind::Expandable
            };
            self.scan_quoted_string(start, character, kind);
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
            let kind = self.scan_number();
            self.push(TokenKind::Number(kind), start);
            return;
        }
        if character == '-' {
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
            TokenKind::Unknown
        } else {
            TokenKind::Identifier
        };
        self.push(kind, start);
    }

    fn scan_horizontal_whitespace(&mut self) {
        while self
            .peek_char()
            .is_some_and(|character| matches!(character, ' ' | '\t' | '\u{000b}' | '\u{000c}'))
        {
            self.bump_char();
        }
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
            self.diagnostics.push(Diagnostic {
                span: Span::new(start, self.cursor),
                message: "unterminated block comment".into(),
            });
        }
        self.push(TokenKind::Comment(CommentKind::Block), start);
    }

    fn here_string_kind(&self) -> Option<StringKind> {
        let quote = self.peek_char_at(1)?;
        let kind = match quote {
            '\'' => StringKind::Literal,
            '"' => StringKind::Expandable,
            _ => return None,
        };
        self.peek_line_break(2).then_some(kind)
    }

    fn scan_here_string(&mut self, start: usize, kind: StringKind) {
        let quote = match kind {
            StringKind::Literal => '\'',
            StringKind::Expandable => '"',
        };
        self.cursor += 2;
        self.scan_newline();
        let mut at_line_start = true;
        while self.cursor < self.source.len() {
            if at_line_start
                && self.peek_char() == Some(quote)
                && self.peek_char_at(1) == Some('@')
                && self
                    .peek_char_at(2)
                    .is_none_or(|next| matches!(next, '\r' | '\n'))
            {
                self.cursor += quote.len_utf8() + '@'.len_utf8();
                self.push(TokenKind::HereString(kind), start);
                return;
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
        self.diagnostics.push(Diagnostic {
            span: Span::new(start, self.cursor),
            message: "unterminated here-string".into(),
        });
        self.push(TokenKind::HereString(kind), start);
    }

    fn scan_quoted_string(&mut self, start: usize, quote: char, kind: StringKind) {
        self.bump_char();
        while let Some(character) = self.bump_char() {
            if quote == '"' && character == '`' {
                self.bump_char();
                continue;
            }
            if character == quote {
                if self.peek_char() == Some(quote) {
                    self.bump_char();
                    continue;
                }
                self.push(TokenKind::String(kind), start);
                return;
            }
        }
        self.diagnostics.push(Diagnostic {
            span: Span::new(start, self.cursor),
            message: "unterminated string literal".into(),
        });
        self.push(TokenKind::String(kind), start);
    }

    fn scan_variable(&mut self, start: usize) {
        self.bump_char();
        if self.peek_char() == Some('{') {
            self.bump_char();
            while let Some(character) = self.bump_char() {
                if character == '}' {
                    self.push(TokenKind::Variable, start);
                    return;
                }
            }
            self.diagnostics.push(Diagnostic {
                span: Span::new(start, self.cursor),
                message: "unterminated braced variable".into(),
            });
            self.push(TokenKind::Variable, start);
            return;
        }

        let variable_start = self.cursor;
        while self.peek_char().is_some_and(is_variable_continue) {
            self.bump_char();
        }
        if self.cursor == variable_start {
            self.push(TokenKind::Operator, start);
        } else {
            self.push(TokenKind::Variable, start);
        }
    }

    fn scan_splat_variable(&mut self) {
        self.bump_char();
        while self.peek_char().is_some_and(is_variable_continue) {
            self.bump_char();
        }
    }

    fn scan_number(&mut self) -> NumberKind {
        if self.starts_with_case_insensitive("0x") {
            self.cursor += 2;
            self.scan_digits(|character| character.is_ascii_hexdigit());
            self.scan_number_suffix();
            return NumberKind::Integer;
        }
        if self.starts_with_case_insensitive("0b") {
            self.cursor += 2;
            self.scan_digits(|character| matches!(character, '0' | '1'));
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
            self.scan_digits(|character| character.is_ascii_digit());
        }
        self.scan_number_suffix();
        kind
    }

    fn scan_digits(&mut self, predicate: impl Fn(char) -> bool) {
        while self
            .peek_char()
            .is_some_and(|character| predicate(character) || character == '_')
        {
            self.bump_char();
        }
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
        if self
            .peek_char_at(1)
            .is_some_and(|character| character.is_ascii_alphabetic())
        {
            self.bump_char();
            while self.peek_char().is_some_and(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            }) {
                self.bump_char();
            }
            let text = &self.source[start..self.cursor];
            let kind = if is_word_operator(text) {
                TokenKind::Operator
            } else {
                TokenKind::Parameter
            };
            self.push(kind, start);
            return;
        }
        if self.starts_with("-=") || self.starts_with("--") {
            self.cursor += 2;
        } else {
            self.bump_char();
        }
        self.push(TokenKind::Operator, start);
    }

    fn scan_symbol(&self) -> Option<(TokenKind, usize)> {
        for operator in [
            "??=", "2>&1", "1>&2", "&&", "||", "::", "..", "++", "--", "+=", "-=", "*=", "/=",
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
                self.bump_char();
                self.bump_char();
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
    character.is_ascii_alphabetic() || matches!(character, '_' | '?' | '^' | '$')
}

fn is_variable_continue(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | ':' | '-' | '?' | '^' | '$')
}

fn is_bare_word_boundary(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '\'' | '"'
                | '$'
                | '@'
                | '#'
                | '('
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
        "param",
        "process",
        "return",
        "switch",
        "throw",
        "trap",
        "try",
        "until",
        "using",
        "var",
        "while",
        "workflow",
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
