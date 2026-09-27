use crate::syntax::{ChainOperator, Stream};
use crate::tokenizer::Span;

#[derive(Debug, Clone)]
pub(crate) struct Program {
    pub(crate) parts: Vec<ChainPart>,
}

#[derive(Debug, Clone)]
pub(crate) struct ChainPart {
    pub(crate) operator: ChainOperator,
    pub(crate) command: Command,
}

#[derive(Debug, Clone)]
pub(crate) struct Command {
    pub(crate) core_ranges: Vec<Span>,
    pub(crate) redirections: Vec<Redirection>,
    pub(crate) group: Option<Box<Program>>,
    pub(crate) kind: CommandKind,
}

#[derive(Debug, Clone)]
pub(crate) enum CommandKind {
    Simple { command: Span, arguments: Vec<Span> },
    If(IfCommand),
    For(ForCommand),
}

#[derive(Debug, Clone)]
pub(crate) struct ForCommand {
    pub(crate) mode: ForMode,
    pub(crate) variable: char,
    pub(crate) set: Span,
    pub(crate) body: Box<Program>,
}

#[derive(Debug, Clone)]
pub(crate) enum ForMode {
    Simple,
    Linear,
    Recursive { root: Option<Span> },
    Text { options: ForTextOptions },
}

#[derive(Debug, Clone)]
pub(crate) struct ForTextOptions {
    pub(crate) tokens: Vec<usize>,
    pub(crate) remainder: bool,
    pub(crate) delimiters: String,
    pub(crate) skip: usize,
    pub(crate) eol: Option<char>,
}

#[derive(Debug, Clone)]
pub(crate) struct IfCommand {
    pub(crate) ignore_case: bool,
    pub(crate) negate: bool,
    pub(crate) condition: IfCondition,
    pub(crate) then_program: Box<Program>,
    pub(crate) else_program: Option<Box<Program>>,
}

#[derive(Debug, Clone)]
pub(crate) enum IfCondition {
    ErrorLevel(Span),
    Exist(Span),
    Defined(Span),
    Equal {
        left: Span,
        right: Span,
    },
    Compare {
        left: Span,
        operator: Span,
        right: Span,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct Redirection {
    pub(crate) stream: Stream,
    pub(crate) target: Option<Span>,
    pub(crate) append: bool,
    pub(crate) merge_to: Option<Stream>,
}
