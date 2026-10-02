use crate::tokenizer::Span;

#[derive(Debug, Clone, Default)]
pub(crate) struct Program {
    pub items: Vec<ListItem>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListOperator {
    Always,
    OnSuccess,
    OnFailure,
    Background,
}

#[derive(Debug, Clone)]
pub(crate) struct ListItem {
    pub operator: ListOperator,
    pub pipeline: Pipeline,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Pipeline {
    pub commands: Vec<Command>,
    pub negated: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum Command {
    Simple(SimpleCommand),
    If {
        branches: Vec<(Program, Program)>,
        else_body: Option<Program>,
    },
    Case {
        word: Word,
        arms: Vec<CaseArm>,
    },
    For {
        name: String,
        words: Vec<Word>,
        body: Program,
    },
    ForArithmetic {
        initializer: String,
        condition: String,
        update: String,
        body: Program,
    },
    While {
        condition: Program,
        body: Program,
        until: bool,
    },
    Function {
        name: String,
        body: Box<Command>,
    },
    Arithmetic {
        expression: String,
    },
    Conditional {
        expression: String,
    },
    Group {
        body: Program,
        subshell: bool,
    },
    Redirected {
        command: Box<Command>,
        redirections: Vec<Redirection>,
    },
}

#[derive(Debug, Clone)]
pub(crate) struct CaseArm {
    pub patterns: Vec<Word>,
    pub body: Program,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SimpleCommand {
    pub words: Vec<Word>,
    pub redirections: Vec<Redirection>,
}

#[derive(Debug, Clone)]
pub(crate) struct Word {
    pub fragments: Vec<Span>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RedirectKind {
    Input,
    Output,
    Append,
    HereDoc,
    HereString,
    Merge,
}

#[derive(Debug, Clone)]
pub(crate) struct Redirection {
    pub fd: u8,
    pub kind: RedirectKind,
    pub target: Option<Word>,
    pub merge_fd: Option<u8>,
    pub here_doc: Option<HereDoc>,
}

#[derive(Debug, Clone)]
pub(crate) struct HereDoc {
    pub body: Span,
    pub delimiter: String,
    pub strip_tabs: bool,
    pub expand: bool,
}
