use crate::ast::Command;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FlowControl {
    None,
    Break,
    Continue,
    Return(i32),
    Exit(i32),
}

impl Default for FlowControl {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Runtime {
    pub variables: BTreeMap<String, String>,
    pub arrays: BTreeMap<String, Vec<String>>,
    pub exported: BTreeSet<String>,
    pub functions: BTreeMap<String, Command>,
    pub positional: Vec<String>,
    pub script_name: String,
    pub current_directory: String,
    pub directory_stack: Vec<String>,
    pub last_status: i32,
    pub flow: FlowControl,
    pub pid: u32,
    pub temporary_file_counter: usize,
    pub output_process_substitutions: BTreeMap<String, String>,
    pub initialized_from_host: bool,
}

impl Default for Runtime {
    fn default() -> Self {
        Self {
            variables: BTreeMap::new(),
            arrays: BTreeMap::new(),
            exported: BTreeSet::new(),
            functions: BTreeMap::new(),
            positional: Vec::new(),
            script_name: "bash".into(),
            current_directory: "/Users/analysis".into(),
            directory_stack: Vec::new(),
            last_status: 0,
            flow: FlowControl::None,
            pid: 4_242,
            temporary_file_counter: 0,
            output_process_substitutions: BTreeMap::new(),
            initialized_from_host: false,
        }
    }
}

impl Runtime {
    pub(crate) fn resolve_path(&self, path: &str) -> String {
        let path = path.trim();
        let path = if path == "~" {
            "/Users/analysis".into()
        } else if let Some(rest) = path.strip_prefix("~/") {
            format!("/Users/analysis/{rest}")
        } else if path.starts_with('/') {
            path.into()
        } else if path.is_empty() || path == "." {
            self.current_directory.clone()
        } else {
            format!("{}/{}", self.current_directory.trim_end_matches('/'), path)
        };
        emulator_core::normalize_posix_path(&path)
    }

    pub(crate) fn variable(&self, name: &str, environment: Option<&str>) -> String {
        if let Some((array, index)) = parse_array_reference(name) {
            let values = self.arrays.get(array).cloned().unwrap_or_default();
            return match index {
                "@" | "*" => values.join(" "),
                index => index
                    .parse::<usize>()
                    .ok()
                    .and_then(|index| values.get(index))
                    .cloned()
                    .unwrap_or_default(),
            };
        }
        match name {
            "?" => self.last_status.to_string(),
            "$" => self.pid.to_string(),
            "#" => self.positional.len().to_string(),
            "@" | "*" => self.positional.join(" "),
            "0" => self.script_name.clone(),
            _ if name.len() == 1 && name.as_bytes()[0].is_ascii_digit() => name
                .parse::<usize>()
                .ok()
                .and_then(|index| self.positional.get(index.saturating_sub(1)))
                .cloned()
                .unwrap_or_default(),
            "PWD" => self.current_directory.clone(),
            "OLDPWD" => self.directory_stack.last().cloned().unwrap_or_default(),
            _ => self
                .variables
                .get(name)
                .cloned()
                .or_else(|| {
                    self.arrays
                        .get(name)
                        .and_then(|values| values.first())
                        .cloned()
                })
                .or_else(|| environment.map(str::to_owned))
                .unwrap_or_default(),
        }
    }
}

fn parse_array_reference(name: &str) -> Option<(&str, &str)> {
    let open = name.find('[')?;
    let close = name.strip_suffix(']')?;
    Some((&name[..open], &close[open + 1..]))
}
