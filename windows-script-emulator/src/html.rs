use crate::runtime::{execute_source, Runtime};
use crate::{ScriptError, ScriptLanguage};
use emulator_core::{Host, NetworkIntent};
use regex::Regex;

pub(crate) fn execute_hta(
    source: &str,
    default_language: ScriptLanguage,
    runtime: &mut Runtime,
    host: &mut dyn Host,
    depth: usize,
) -> Result<(), ScriptError> {
    if !source.to_ascii_lowercase().contains("<script") {
        execute_source(source, default_language, runtime, host, depth)?;
        return Ok(());
    }
    execute_markup_scripts(source, default_language, runtime, host, depth)
}

pub(crate) fn execute_scriptlet(
    source: &str,
    default_language: ScriptLanguage,
    runtime: &mut Runtime,
    host: &mut dyn Host,
    depth: usize,
) -> Result<(), ScriptError> {
    execute_markup_scripts(source, default_language, runtime, host, depth)
}

fn execute_markup_scripts(
    source: &str,
    default_language: ScriptLanguage,
    runtime: &mut Runtime,
    host: &mut dyn Host,
    depth: usize,
) -> Result<(), ScriptError> {
    let script_pattern = Regex::new(r"(?is)<script\b([^>]*)>(.*?)</script>")
        .expect("static script element regex is valid");
    let source_pattern = Regex::new(r#"(?i)\bsrc\s*=\s*["']([^"']+)["']"#)
        .expect("static script source regex is valid");
    let language_pattern = Regex::new(r#"(?i)\b(?:language|type)\s*=\s*["']([^"']+)["']"#)
        .expect("static script language regex is valid");
    for captures in script_pattern.captures_iter(source) {
        let attributes = captures.get(1).map_or("", |value| value.as_str());
        let language = language_pattern
            .captures(attributes)
            .and_then(|captures| captures.get(1))
            .map_or(default_language, |value| {
                language_from_attribute(value.as_str(), default_language)
            });
        if let Some(url) = source_pattern
            .captures(attributes)
            .and_then(|captures| captures.get(1))
            .map(|value| value.as_str())
        {
            if let Some(response) = host.network_request(NetworkIntent {
                method: "GET".into(),
                url: url.into(),
                origin: "Windows script markup src".into(),
                depth,
            }) {
                let body = String::from_utf8_lossy(&response.body);
                execute_source(&body, language, runtime, host, depth + 1)?;
            }
        }
        if let Some(body) = captures.get(2) {
            execute_source(body.as_str(), language, runtime, host, depth)?;
        }
        if runtime.exited() {
            break;
        }
    }
    Ok(())
}

fn language_from_attribute(value: &str, default: ScriptLanguage) -> ScriptLanguage {
    let lower = value.to_ascii_lowercase();
    if lower.contains("vbscript") || lower.contains("visualbasic") {
        ScriptLanguage::VBScript
    } else if lower.contains("javascript") || lower.contains("jscript") {
        ScriptLanguage::JScript
    } else {
        default
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emulator_core::{AnalysisLimits, VirtualHost};

    #[test]
    fn executes_mixed_script_blocks_in_order() {
        let mut runtime = Runtime::default();
        runtime.prepare(ScriptLanguage::JScript, crate::ScriptHost::Mshta, &[]);
        let mut host = VirtualHost::new(AnalysisLimits::default());
        execute_hta(
            r#"<script>var x = "a";</script><script language="VBScript">x = x & "b"</script>"#,
            ScriptLanguage::JScript,
            &mut runtime,
            &mut host,
            0,
        )
        .unwrap();
        assert_eq!(runtime.get_variable("x").string(), "ab");
    }
}
