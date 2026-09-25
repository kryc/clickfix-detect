#![allow(clippy::pedantic)]

mod com;
mod expression;
mod host;
mod html;
mod jscript;
mod runtime;
mod value;
mod vbscript;

pub mod tokenizer;

use emulator_core::{Engine, EventKind, Host, HostError, TraceEvent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const MAX_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptLanguage {
    JScript,
    VBScript,
}

impl std::str::FromStr for ScriptLanguage {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "js" | "jscript" | "javascript" => Ok(Self::JScript),
            "vbs" | "vbscript" | "visualbasic" => Ok(Self::VBScript),
            _ => Err(format!("unsupported script language: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScriptHost {
    WScript,
    CScript,
    Mshta,
    Scriptlet,
}

impl std::str::FromStr for ScriptHost {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "wscript" | "wscript.exe" => Ok(Self::WScript),
            "cscript" | "cscript.exe" => Ok(Self::CScript),
            "mshta" | "mshta.exe" | "hta" => Ok(Self::Mshta),
            "scriptlet" | "sct" | "regsvr32" => Ok(Self::Scriptlet),
            _ => Err(format!("unsupported script host: {value}")),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScriptResult {
    pub stdout: Vec<String>,
    pub stderr: Vec<String>,
    pub exit_code: i32,
    pub exited: bool,
    pub diagnostics: Vec<String>,
    pub variables: BTreeMap<String, String>,
}

#[derive(Debug, Error)]
pub enum ScriptError {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("script input exceeds the {MAX_INPUT_BYTES} byte limit")]
    InputTooLarge,
    #[error("script syntax error: {0}")]
    Syntax(String),
    #[error("script loop iteration limit {limit} reached")]
    LoopLimit { limit: usize },
}

#[derive(Debug, Clone, Default)]
pub struct WindowsScriptEmulator {
    runtime: runtime::Runtime,
}

impl WindowsScriptEmulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Emulates Windows Script Host, HTA, or scriptlet source without native execution.
    ///
    /// Variables remain available across calls on the same emulator instance.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized input, malformed supported syntax, or exhausted limits.
    pub fn emulate<S: AsRef<str>>(
        &mut self,
        source: &str,
        language: ScriptLanguage,
        host_kind: ScriptHost,
        arguments: &[S],
        host: &mut dyn Host,
        depth: usize,
    ) -> Result<ScriptResult, ScriptError> {
        if source.len() > MAX_INPUT_BYTES {
            return Err(ScriptError::InputTooLarge);
        }
        host.consume_step(engine(host_kind), depth, "parsing Windows script input")?;
        let tokenization = tokenizer::tokenize(source, language);
        host.emit(
            TraceEvent::new(
                depth,
                engine(host_kind),
                EventKind::Parse,
                "tokenized Windows script input",
            )
            .with_data("bytes", source.len().to_string())
            .with_data("tokens", tokenization.tokens.len().to_string())
            .with_data("language", format!("{language:?}")),
        );
        for diagnostic in tokenization.diagnostics {
            self.runtime.diagnostic(diagnostic.message);
        }
        let arguments = arguments
            .iter()
            .map(|argument| argument.as_ref().to_owned())
            .collect::<Vec<_>>();
        self.runtime.prepare(language, host_kind, &arguments);
        if host_kind == ScriptHost::Mshta {
            html::execute_hta(source, language, &mut self.runtime, host, depth)?;
        } else if host_kind == ScriptHost::Scriptlet {
            html::execute_scriptlet(source, language, &mut self.runtime, host, depth)?;
        } else {
            runtime::execute_source(source, language, &mut self.runtime, host, depth)?;
        }
        Ok(self.runtime.take_result())
    }
}

fn engine(host: ScriptHost) -> Engine {
    match host {
        ScriptHost::Mshta => Engine::Mshta,
        ScriptHost::WScript | ScriptHost::CScript | ScriptHost::Scriptlet => Engine::Wscript,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulator_core::{AnalysisLimits, VirtualHost};

    #[test]
    fn variables_persist_across_calls() {
        let mut emulator = WindowsScriptEmulator::new();
        let mut host = VirtualHost::new(AnalysisLimits::default());
        emulator
            .emulate(
                "var x = 40;",
                ScriptLanguage::JScript,
                ScriptHost::WScript,
                &[] as &[String],
                &mut host,
                0,
            )
            .unwrap();
        let result = emulator
            .emulate(
                "WScript.Echo(x + 2);",
                ScriptLanguage::JScript,
                ScriptHost::CScript,
                &[] as &[String],
                &mut host,
                0,
            )
            .unwrap();
        assert_eq!(result.stdout, ["42"]);
    }
}
