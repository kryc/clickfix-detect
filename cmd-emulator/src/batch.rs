use crate::parser::ParsedDocument;
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub(crate) enum BatchAction {
    Goto(String),
    Call { label: String, args: Vec<String> },
    Return(i32),
}

#[derive(Debug, Clone)]
struct CallFrame {
    return_pc: usize,
    args: Vec<String>,
    shift: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct BatchContext {
    pub lines: Vec<ParsedDocument>,
    pub labels: BTreeMap<String, usize>,
    pub file_name: String,
    pub args: Vec<String>,
    pub shift: usize,
    pub pc: usize,
    pub action: Option<BatchAction>,
    call_stack: Vec<CallFrame>,
}

impl BatchContext {
    pub fn new(source: &str, file_name: &str, args: Vec<String>) -> Self {
        let lines = logical_lines(source)
            .into_iter()
            .map(|line| ParsedDocument::parse(&line))
            .collect::<Vec<_>>();
        let labels = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| line.label().map(|label| (label, index)))
            .collect();
        Self {
            lines,
            labels,
            file_name: file_name.into(),
            args,
            shift: 0,
            pc: 0,
            action: None,
            call_stack: Vec::new(),
        }
    }

    pub fn argument(&self, index: usize) -> String {
        if index == 0 {
            return self.file_name.clone();
        }
        self.args
            .get(self.shift.saturating_add(index - 1))
            .cloned()
            .unwrap_or_default()
    }

    pub fn all_arguments(&self) -> String {
        self.args
            .iter()
            .skip(self.shift)
            .map(|value| quote_if_needed(value))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn shift(&mut self) {
        self.shift = self.shift.saturating_add(1).min(self.args.len());
    }

    pub fn jump(&mut self, label: &str) -> bool {
        let normalized = normalize_label(label);
        if normalized == "eof" {
            self.return_from_call();
            return true;
        }
        if let Some(index) = self.labels.get(&normalized) {
            self.pc = index.saturating_add(1);
            true
        } else {
            false
        }
    }

    pub fn call(&mut self, label: &str, args: Vec<String>) -> bool {
        let normalized = normalize_label(label);
        let Some(index) = self.labels.get(&normalized).copied() else {
            return false;
        };
        self.call_stack.push(CallFrame {
            return_pc: self.pc,
            args: std::mem::replace(&mut self.args, args),
            shift: std::mem::replace(&mut self.shift, 0),
        });
        self.pc = index.saturating_add(1);
        true
    }

    pub fn return_from_call(&mut self) -> bool {
        let Some(frame) = self.call_stack.pop() else {
            self.pc = self.lines.len();
            return false;
        };
        self.pc = frame.return_pc;
        self.args = frame.args;
        self.shift = frame.shift;
        true
    }

    #[must_use]
    pub fn call_depth(&self) -> usize {
        self.call_stack.len()
    }
}

fn logical_lines(source: &str) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut depth = 0_i32;
    for raw in source.lines() {
        let trimmed_end = raw.trim_end();
        let continued = trailing_caret(trimmed_end);
        let piece = if continued {
            trimmed_end.strip_suffix('^').unwrap_or(trimmed_end)
        } else {
            raw
        };
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(piece);
        depth += paren_delta(piece);
        if continued || depth > 0 {
            continue;
        }
        let line = current.trim().to_string();
        if line.to_ascii_lowercase().starts_with("else ") {
            if let Some(previous) = lines.last_mut() {
                previous.push(' ');
                previous.push_str(&line);
            } else {
                lines.push(line);
            }
        } else {
            lines.push(line);
        }
        current.clear();
        depth = 0;
    }
    if !current.trim().is_empty() {
        lines.push(current.trim().into());
    }
    lines
}

fn trailing_caret(value: &str) -> bool {
    value.chars().rev().take_while(|ch| *ch == '^').count() % 2 == 1
}

fn paren_delta(source: &str) -> i32 {
    let mut delta = 0;
    let mut quoted = false;
    let mut escaped = false;
    for ch in source.chars() {
        if escaped {
            escaped = false;
        } else if ch == '^' {
            escaped = true;
        } else if ch == '"' {
            quoted = !quoted;
        } else if !quoted && ch == '(' {
            delta += 1;
        } else if !quoted && ch == ')' {
            delta -= 1;
        }
    }
    delta
}

fn normalize_label(label: &str) -> String {
    label
        .trim()
        .trim_start_matches(':')
        .trim()
        .to_ascii_lowercase()
}

fn quote_if_needed(value: &str) -> String {
    if value.contains(char::is_whitespace) {
        format!("\"{value}\"")
    } else {
        value.into()
    }
}
