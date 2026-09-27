use crate::tokenizer::{Span, StringKind};

#[derive(Debug, Clone)]
pub(crate) struct Program {
    pub(crate) range: Span,
    pub(crate) statements: Vec<Statement>,
}

#[derive(Debug, Clone)]
pub(crate) struct Statement {
    pub(crate) range: Span,
    pub(crate) kind: StatementKind,
}

#[derive(Debug, Clone)]
pub(crate) enum StatementKind {
    Empty,
    Function {
        name: Span,
        parameters: Vec<ParameterDeclaration>,
        body: Span,
        filter: bool,
    },
    OpaqueDeclaration,
    Param(Vec<ParameterDeclaration>),
    If(IfStatement),
    Foreach(ForeachStatement),
    While(WhileStatement),
    For(ForStatement),
    Switch(SwitchStatement),
    Do(DoStatement),
    Try(TryStatement),
    Break,
    Continue,
    Return(Option<Expression>),
    Exit(Option<Expression>),
    Throw(Expression),
    Increment {
        variable: Span,
        delta: i64,
    },
    CompoundAssignment {
        target: Span,
        operator: String,
        value: Expression,
    },
    Assignment {
        target: Span,
        value: Expression,
    },
    Redirected {
        command: Box<Statement>,
        redirections: Vec<crate::syntax::Redirection>,
    },
    Pipeline(Vec<Statement>),
    Invocation {
        target: Expression,
        arguments: Vec<Expression>,
        dot_source: bool,
    },
    Expression(Expression),
    Command {
        command: Span,
        arguments: Vec<Span>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct ParameterDeclaration {
    pub(crate) name: Span,
    pub(crate) default: Option<Expression>,
}

#[derive(Debug, Clone)]
pub(crate) struct SwitchStatement {
    pub(crate) condition: Expression,
    pub(crate) cases: Vec<SwitchCase>,
    pub(crate) input: SwitchInput,
    pub(crate) case_sensitive: bool,
    pub(crate) matching: SwitchMatching,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SwitchInput {
    Values,
    File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SwitchMatching {
    Exact,
    Regex,
    Wildcard,
}

#[derive(Debug, Clone)]
pub(crate) struct SwitchCase {
    pub(crate) label: Option<Expression>,
    pub(crate) body: Span,
}

#[derive(Debug, Clone)]
pub(crate) struct TryStatement {
    pub(crate) body: Span,
    pub(crate) catch_body: Option<Span>,
    pub(crate) finally_body: Option<Span>,
}

#[derive(Debug, Clone)]
pub(crate) struct ForeachStatement {
    pub(crate) variable: Span,
    pub(crate) values: Expression,
    pub(crate) body: Span,
}

#[derive(Debug, Clone)]
pub(crate) struct WhileStatement {
    pub(crate) condition: Expression,
    pub(crate) body: Span,
}

#[derive(Debug, Clone)]
pub(crate) struct ForStatement {
    pub(crate) initialization: Box<Statement>,
    pub(crate) condition: Expression,
    pub(crate) iteration: Box<Statement>,
    pub(crate) body: Span,
}

#[derive(Debug, Clone)]
pub(crate) struct DoStatement {
    pub(crate) body: Span,
    pub(crate) condition: Expression,
    pub(crate) until: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct IfStatement {
    pub(crate) condition: Expression,
    pub(crate) then_body: Span,
    pub(crate) else_branch: Option<IfBranch>,
}

#[derive(Debug, Clone)]
pub(crate) enum IfBranch {
    ElseIf(Box<IfStatement>),
    Else(Span),
}

#[derive(Debug, Clone)]
pub(crate) struct Expression {
    pub(crate) range: Span,
    pub(crate) kind: ExpressionKind,
}

#[derive(Debug, Clone)]
pub(crate) enum ExpressionKind {
    Empty,
    Null,
    Boolean(bool),
    Number,
    Variable,
    String(StringKind),
    HereString(StringKind),
    Parenthesized(Box<Expression>),
    Subexpression(Span),
    Array(Vec<Expression>),
    Hashtable(Vec<HashtableEntry>),
    ScriptBlock(Span),
    Cast {
        type_name: String,
        value: Box<Expression>,
    },
    TypeLiteral(String),
    Unary {
        operator: String,
        value: Box<Expression>,
    },
    Binary {
        left: Box<Expression>,
        operator: String,
        right: Box<Expression>,
    },
    Index {
        value: Box<Expression>,
        index: Box<Expression>,
        null_conditional: bool,
    },
    StaticCall {
        type_name: Span,
        method: Span,
        arguments: Vec<Expression>,
    },
    StaticMember {
        type_name: Span,
        member: Span,
    },
    InstanceCall {
        receiver: Box<Expression>,
        method: Span,
        arguments: Vec<Expression>,
        null_conditional: bool,
    },
    Member {
        receiver: Box<Expression>,
        member: Span,
        null_conditional: bool,
    },
    NewObject {
        arguments: Vec<Span>,
    },
    Bare,
}

#[derive(Debug, Clone)]
pub(crate) struct HashtableEntry {
    pub(crate) key: String,
    pub(crate) value: Expression,
}
