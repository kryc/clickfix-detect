#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChainOperator {
    Always,
    OnSuccess,
    OnFailure,
    Pipe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stream {
    Stdout,
    Stderr,
    Stdin,
}

#[derive(Debug, Clone)]
pub(crate) struct Redirection {
    pub stream: Stream,
    pub target: String,
    pub append: bool,
    pub merge_to: Option<Stream>,
}

pub(crate) fn split_words(source: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => quoted = !quoted,
            '^' => {
                if matches!(chars.peek(), Some('\r')) {
                    chars.next();
                    if matches!(chars.peek(), Some('\n')) {
                        chars.next();
                    }
                } else if matches!(chars.peek(), Some('\n')) {
                    chars.next();
                } else if let Some(escaped) = chars.next() {
                    current.push(escaped);
                }
            }
            ' ' | '\t' if !quoted => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

pub(crate) fn unquote_and_unescape(value: &str) -> String {
    split_words(value).into_iter().next().unwrap_or_default()
}
